/* ================================================================
   KRYPTIX — Crypto Worker (HyperTransfer Engine)
   Offloads AES-256-GCM encryption/decryption to a dedicated thread
   Uses Transferable ArrayBuffers for zero-copy data movement
   ================================================================ */

"use strict";

const KDF_SALT = "KRYPTIX::MESH::LOCK::V2";
const enc = new TextEncoder();

let _key = null;

/* ─── Key Derivation ─────────────────────────────────────────── */
async function deriveKey(secret) {
  const mat = await crypto.subtle.importKey(
    "raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode(KDF_SALT), iterations: 310000, hash: "SHA-256" },
    mat,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/* ─── Encrypt a file chunk into a binary packet ──────────────── */
// Returns: ArrayBuffer [KRYP(4)][idx(4)][fid(16)][iv(12)][ciphertext(N+16)]
async function encryptChunk(fid, chunkIdx, plainData) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, _key, plainData);
  const ctView = new Uint8Array(ct);
  // Single allocation: header(36) + ciphertext
  const pkt = new Uint8Array(36 + ctView.length);
  // Magic "KRYP"
  pkt[0] = 0x4B; pkt[1] = 0x52; pkt[2] = 0x59; pkt[3] = 0x50;
  // Chunk index (little-endian uint32)
  new DataView(pkt.buffer).setUint32(4, chunkIdx, true);
  // File ID (16 bytes, ASCII padded with zeros)
  for (let j = 0; j < 16; j++) pkt[8 + j] = j < fid.length ? fid.charCodeAt(j) : 0x00;
  // IV
  pkt.set(iv, 24);
  // Ciphertext
  pkt.set(ctView, 36);
  return pkt.buffer; // Return ArrayBuffer for Transferable
}

/* ─── Decrypt a file chunk ───────────────────────────────────── */
// Input: ArrayBuffer containing [iv(12)][ciphertext(N+16)]
async function decryptChunk(cipherData) {
  const packed = new Uint8Array(cipherData);
  const iv = packed.subarray(0, 12);
  const ct = packed.subarray(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, _key, ct);
  return plain; // ArrayBuffer
}

/* ─── Encrypt raw (for turbo=false, non-file data) ───────────── */
async function encryptRaw(plainData) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, _key, plainData));
  const packed = new Uint8Array(iv.length + ct.length);
  packed.set(iv);
  packed.set(ct, iv.length);
  return packed.buffer;
}

/* ─── Build turbo (unencrypted) packet ───────────────────────── */
// Returns: ArrayBuffer [KRYP(4)][idx(4)][fid(16)][plainData(N)]
function buildTurboPacket(fid, chunkIdx, plainData) {
  const plain = new Uint8Array(plainData);
  const pkt = new Uint8Array(24 + plain.length);
  // Magic "KRYP"
  pkt[0] = 0x4B; pkt[1] = 0x52; pkt[2] = 0x59; pkt[3] = 0x50;
  // Chunk index
  new DataView(pkt.buffer).setUint32(4, chunkIdx, true);
  // File ID
  for (let j = 0; j < 16; j++) pkt[8 + j] = j < fid.length ? fid.charCodeAt(j) : 0x00;
  // Raw data (no IV, no auth tag — DTLS handles encryption)
  pkt.set(plain, 24);
  return pkt.buffer;
}

/* ─── Message Handler ────────────────────────────────────────── */
self.onmessage = async function(e) {
  const { cmd, id } = e.data;

  try {
    switch (cmd) {
      case "init": {
        // Initialize the key from the shared secret
        _key = await deriveKey(e.data.secret);
        self.postMessage({ cmd: "init-done", id });
        break;
      }

      case "encrypt-chunk": {
        // Encrypt a file chunk into a binary KRYP packet
        const { fid, chunkIdx, data } = e.data;
        const result = await encryptChunk(fid, chunkIdx, data);
        self.postMessage({ cmd: "encrypted", id, result }, [result]);
        break;
      }

      case "encrypt-chunk-turbo": {
        // Build unencrypted turbo packet (DTLS-only security)
        const { fid: tFid, chunkIdx: tIdx, data: tData } = e.data;
        const result = buildTurboPacket(tFid, tIdx, tData);
        self.postMessage({ cmd: "encrypted", id, result }, [result]);
        break;
      }

      case "decrypt-chunk": {
        // Decrypt a file chunk (cipher = iv+ciphertext)
        const plain = await decryptChunk(e.data.data);
        self.postMessage({ cmd: "decrypted", id, result: plain }, [plain]);
        break;
      }

      case "encrypt-raw": {
        // Encrypt arbitrary bytes (for non-file data)
        const raw = await encryptRaw(e.data.data);
        self.postMessage({ cmd: "encrypted-raw", id, result: raw }, [raw]);
        break;
      }

      default:
        self.postMessage({ cmd: "error", id, error: "Unknown command: " + cmd });
    }
  } catch (err) {
    self.postMessage({ cmd: "error", id, error: err.message || String(err) });
  }
};
