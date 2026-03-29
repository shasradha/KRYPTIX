/* ================================================================
   KRYPTIX — Secure Mesh Messenger
   Simplified App Logic with AES-256-GCM Encryption
   ================================================================ */

"use strict";

/* ─── Constants ─────────────────────────────────────────────── */
const APP_NAME = "Kryptix";
const FILE_CHUNK_WAN = 256 * 1024;       // 256KB
const FILE_CHUNK_LAN = 256 * 1024;       // 256KB — optimal for worker pipeline parallelism
const THEME_KEY = "kryptix-theme";
const K_ACK_STEP = 8;                    // ACK every 8 chunks (progress display only)
const K_WINDOW_SIZE = 96;
const KDF_SALT = "KRYPTIX::MESH::LOCK::V2";
const MAX_MSG = 10000;
const MAX_FILE_LAN = 100 * 1024 * 1024 * 1024;  // 100 GB
const MAX_FILE_RELAY = 500 * 1024 * 1024;       // 500 MB
const MOBILE_BP = 900;
// Reduced buffer sizes guarantee chat messages can multiplex through massive file transfers (Concurrent)
const BUFFER_HIGH_LAN = 5 * 1024 * 1024;   // 5MB — prevents Head-of-Line blocking
const BUFFER_HIGH_WAN = 1 * 1024 * 1024;   // 1MB
const BUFFER_LOW_LAN  = 1 * 1024 * 1024;   // 1MB
const BUFFER_LOW_WAN  = 256 * 1024;        // 256KB
const ANTI_REPLAY_MS = 30000;              // Reject packets older than 30s
const BOND_CHANNELS = 4;                   // Number of parallel RTCPeerConnections for large files
const BOND_THRESHOLD = 10 * 1024 * 1024;   // Use bonding for files > 10MB
const WORKER_POOL_SIZE = 4;                // Number of crypto workers
const IS_CAPACITOR = typeof window.Capacitor !== 'undefined' || navigator.userAgent.includes('Capacitor');
const IS_DESKTOP = !!(window.electronAPI && window.electronAPI.isDesktop);

/* ─── Desktop Speed Overrides (Feature 5) ───────────────────── */
// Desktop apps have no browser throttling — blast through at max speed
const DESKTOP_CHUNK = 1 * 1024 * 1024;          // 1MB chunks (4x browser size)
const DESKTOP_BUFFER_HIGH = 8 * 1024 * 1024;    // Reduced from 32MB to 8MB to allow instant messaging
const DESKTOP_BUFFER_LOW  = 2 * 1024 * 1024;    // 2MB
const DESKTOP_SEND_THREADS = 16;                 // 16 parallel send workers
const DESKTOP_BOND_CHANNELS = 6;                 // More bond channels on desktop

/* ─── HyperDrive Native Bridge ──────────────────────────────── */
// If running in Capacitor, access the native HyperDrive plugin for 100+ MB/s transfers
const HyperDrive = IS_CAPACITOR && window.Capacitor && window.Capacitor.Plugins
  ? window.Capacitor.Plugins.HyperDrive : null;

async function hyperDriveAvailable() {
  if (!HyperDrive) return false;
  try {
    const r = await HyperDrive.getLocalIp();
    return r && r.ip;
  } catch (e) { return false; }
}

const cfg = window.KRYPTIX_CONFIG || {};
const ICE = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
  { urls: "stun:stun2.l.google.com:19302" },
  { urls: "stun:stun3.l.google.com:19302" },
  { urls: "stun:stun4.l.google.com:19302" }
];

/* ─── Rate Limiter ──────────────────────────────────────────── */
class RateLimiter {
  constructor(max, ms) {
    this.max = max;
    this.ms = ms;
    this.log = new Map();
  }
  ok(k = "_") {
    const now = Date.now();
    const arr = (this.log.get(k) || []).filter(t => t > now - this.ms);
    this.log.set(k, arr);
    if (arr.length >= this.max) return false;
    arr.push(now);
    return true;
  }
  clear() { this.log.clear(); }
}

const rlConnect = new RateLimiter(5, 30000);
const rlMessage = new RateLimiter(20, 10000);
const rlIncoming = new RateLimiter(10, 30000);
const fails = { n: 0, until: 0 };

/* ─── State ─────────────────────────────────────────────────── */
const state = {
  peer: null,
  id: "",
  booting: false,
  key: null,
  secret: "",
  conns: new Map(),
  history: [],
  localStream: null,
  streamMode: "none",
  urls: new Set(),
  transfers: new Map(),  // Active file transfers (progress tracking)
  wakeLock: null,         // Screen wake lock for background transfers
  turbo: false,           // Strategy 5: Turbo LAN Mode (skip app-layer encryption for files)
  bonds: new Map()        // Strategy 2: Bond channel connections (multi-PeerConnection)
};

// Per-peer serial processing queue - prevents message blocking during file transfers
function makePeerQueue() {
  let tail = Promise.resolve();
  return function enqueue(fn) {
    tail = tail.then(fn).catch(e => console.error("Queue error:", e));
  };
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ─── Worker Pool (Strategy 1: Offload Crypto) ──────────────── */
class WorkerPool {
  constructor(size = WORKER_POOL_SIZE) {
    this.size = size;
    this.workers = [];
    this.pending = new Map();
    this.nextId = 0;
    this.robin = 0;
    this.ready = false;
  }

  async init(secret) {
    this.destroy();
    this.workers = [];
    this.pending = new Map();
    this.nextId = 0;
    this.robin = 0;
    this.ready = false;

    const workerUrl = './js/crypto-worker.js';
    const initPromises = [];

    for (let i = 0; i < this.size; i++) {
      const w = new Worker(workerUrl);
      w.onmessage = (e) => this._onMessage(i, e.data);
      w.onerror = (e) => console.error(`Worker ${i} error:`, e);
      this.workers.push(w);

      // Initialize each worker with the key
      initPromises.push(this._dispatch(i, { cmd: 'init', secret }));
    }

    await Promise.all(initPromises);
    this.ready = true;
  }

  _onMessage(workerIdx, msg) {
    const cb = this.pending.get(msg.id);
    if (!cb) return;
    this.pending.delete(msg.id);
    if (msg.cmd === 'error') {
      cb.reject(new Error(msg.error));
    } else {
      cb.resolve(msg.result);
    }
  }

  _dispatch(workerIdx, msg) {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      msg.id = id;
      this.pending.set(id, { resolve, reject });

      // Build transferable list
      const transferable = [];
      if (msg.data instanceof ArrayBuffer) transferable.push(msg.data);
      else if (msg.data && msg.data.buffer instanceof ArrayBuffer && ArrayBuffer.isView(msg.data)) {
        // Convert typed array to pure ArrayBuffer for transfer
        const ab = msg.data.buffer.slice(msg.data.byteOffset, msg.data.byteOffset + msg.data.byteLength);
        msg.data = ab;
        transferable.push(ab);
      }

      this.workers[workerIdx].postMessage(msg, transferable);
    });
  }

  _nextWorker() {
    const idx = this.robin;
    this.robin = (this.robin + 1) % this.size;
    return idx;
  }

  async encryptChunk(fid, chunkIdx, data) {
    if (!this.ready) throw new Error('WorkerPool not initialized');
    return this._dispatch(this._nextWorker(), {
      cmd: 'encrypt-chunk', fid, chunkIdx, data
    });
  }

  async encryptChunkTurbo(fid, chunkIdx, data) {
    if (!this.ready) throw new Error('WorkerPool not initialized');
    return this._dispatch(this._nextWorker(), {
      cmd: 'encrypt-chunk-turbo', fid, chunkIdx, data
    });
  }

  async decryptChunk(data) {
    if (!this.ready) throw new Error('WorkerPool not initialized');
    return this._dispatch(this._nextWorker(), {
      cmd: 'decrypt-chunk', data
    });
  }

  destroy() {
    for (const w of this.workers) {
      try { w.terminate(); } catch (e) {}
    }
    this.workers = [];
    this.pending.clear();
    this.ready = false;
  }
}

const workerPool = new WorkerPool();

/* ─── DOM ───────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);

const el = {
  body: document.body,
  statusPill: $("statusPill"),
  statusText: $("statusText"),
  themeToggle: $("themeToggle"),
  peerIdInput: $("peerIdInput"),
  secretInput: $("sharedSecretInput"),
  toggleSecret: $("toggleSecretBtn"),
  goOnline: $("goOnlineBtn"),
  goOffline: $("goOfflineBtn"),
  idDisplay: $("idDisplay"),
  myPeerId: $("myPeerId"),
  copyId: $("copyIdBtn"),
  connectInput: $("connectInput"),
  connectBtn: $("connectBtn"),
  peerCount: $("peerCount"),
  peerList: $("peerList"),
  chatPanel: $("chatPanel"),
  chatStatus: $("chatStatus"),
  timeline: $("timeline"),
  composer: $("composer"),
  msgInput: $("messageInput"),
  sendBtn: $("sendBtn"),
  voiceBtn: $("voiceBtn"),
  videoBtn: $("videoBtn"),
  cameraBtn: $("cameraBtn"),
  filesBtn: $("filesBtn"),
  stopMedia: $("stopMediaBtn"),
  clearBtn: $("clearBtn"),
  panicBtn: $("panicBtn"),
  fileInput: $("fileInput"),
  cameraPhotoInput: $("cameraPhotoInput"),
  cameraVideoInput: $("cameraVideoInput"),
  cameraModal: $("cameraModal"),
  cameraPhotoBtn: $("cameraPhotoBtn"),
  cameraVideoBtn: $("cameraVideoBtn"),
  cameraCancelBtn: $("cameraCancelBtn"),
  mediaGrid: $("mediaGrid"),
  toasts: $("toastWrap"),
  turboToggle: $("turboToggle"),
  turboIndicator: $("turboIndicator"),
  // Desktop features
  nearbyCard: $("nearbyCard"),
  nearbyList: $("nearbyList"),
  dropZone: $("dropZone")
};

/* ─── Utilities ─────────────────────────────────────────────── */
function rndId() {
  return crypto.randomUUID ? crypto.randomUUID() : "kx-" + Date.now() + "-" + Math.random().toString(36).slice(2);
}

// Short 12-char file ID that fits in the 16-byte binary header field
function fileId() {
  const c = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const a = crypto.getRandomValues(new Uint8Array(12));
  let s = '';
  for (let i = 0; i < 12; i++) s += c[a[i] % c.length];
  return s;
}

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function fmtBytes(b) {
  if (!b || b <= 0) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  const e = Math.min(Math.floor(Math.log(b) / Math.log(1024)), u.length - 1);
  const v = b / 1024 ** e;
  return (v >= 10 || e === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + u[e];
}

function sanitizeId(raw) {
  return raw.trim().toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9_-]/g, "").slice(0, 64);
}

function parseTargets(raw) {
  const seen = new Set();
  return raw.split(/[\n,]+/).map(sanitizeId).filter(v => {
    if (!v || seen.has(v)) return false;
    seen.add(v);
    return true;
  });
}

function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new Error("Bad binary payload");
}

async function toBytesAsync(v) {
  return v instanceof Blob ? new Uint8Array(await v.arrayBuffer()) : toBytes(v);
}

function fileExt(type, name = "") {
  const map = {
    "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif",
    "application/pdf": "pdf", "application/zip": "zip", "text/plain": "txt",
    "application/json": "json", "audio/mpeg": "mp3", "video/mp4": "mp4", "video/webm": "webm"
  };
  if (map[type]) return map[type];
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot + 1).replace(/[^a-z0-9]/gi, "").toLowerCase() || "bin" : "bin";
}

function fileKind(type) {
  if (!type) return "File";
  if (type.startsWith("image/")) return "Image";
  if (type.startsWith("video/")) return "Video";
  if (type.startsWith("audio/")) return "Audio";
  if (type.startsWith("text/")) return "Text";
  return "File";
}

function safeName(type, name = "") {
  return `kryptix-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${fileExt(type, name)}`;
}

/* Universal download that works in browser AND Android WebView */
function downloadBlob(blobUrl, filename) {
  // First try the standard <a download> approach
  const a = document.createElement("a");
  a.href = blobUrl;
  a.download = filename;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  // If running in Capacitor/WebView, the above may fail silently.
  // Fallback: fetch the blob and convert to data URL for download
  if (IS_CAPACITOR) {
    fetch(blobUrl)
      .then(r => r.blob())
      .then(async blob => {
        const reader = new FileReader();
        reader.onloadend = async () => {
          const base64Data = reader.result.split(',')[1];
          // Use Capacitor Filesystem if available to write straight to Documents
          if (window.Capacitor && window.Capacitor.Plugins.Filesystem) {
            try {
              const res = await window.Capacitor.Plugins.Filesystem.writeFile({
                path: filename,
                data: base64Data,
                directory: 'DOCUMENTS'
              });
              toast(`Saved ${filename} to Documents.`, "success");
            } catch (e) {
              console.error("Capacitor write failed:", e);
              window.open(reader.result, "_blank"); // Fallback
            }
          } else {
            // Last resort for WebViews missing the filesystem plugin
            const dataA = document.createElement("a");
            dataA.href = reader.result;
            dataA.download = filename;
            dataA.style.display = "none";
            document.body.appendChild(dataA);
            dataA.click();
            setTimeout(() => dataA.remove(), 200);
          }
        };
        reader.readAsDataURL(blob);
      })
      .catch(() => {
        window.open(blobUrl, "_blank");
      });
  }
  setTimeout(() => a.remove(), 200);
}

async function stripMeta(file) {
  if (!file.type.startsWith("image/") || file.type === "image/gif" || typeof createImageBitmap !== "function") return file;
  const bmp = await createImageBitmap(file);
  const c = document.createElement("canvas");
  c.width = bmp.width; c.height = bmp.height;
  const ctx = c.getContext("2d");
  if (!ctx) { bmp.close(); return file; }
  ctx.drawImage(bmp, 0, 0);
  bmp.close();
  const out = ["image/jpeg", "image/png", "image/webp"].includes(file.type) ? file.type : "image/png";
  return new Promise((ok, fail) => c.toBlob(r => r ? ok(r) : fail(new Error("Strip failed")), out, 0.92));
}

async function prepFile(file) {
  const clean = file.type.startsWith("image/") ? await stripMeta(file).catch(() => file) : file;
  const type = clean.type || file.type || "application/octet-stream";
  return { blob: clean, type, label: fileKind(type), dl: safeName(type, file.name), size: clean.size };
}

/* ─── Notifications ─────────────────────────────────────────── */
async function showNotification(title, body, tag = 'kryptix-msg') {
  if (IS_DESKTOP && window.electronAPI && window.electronAPI.showNativeNotification) {
    window.electronAPI.showNativeNotification(title, body);
    return;
  }
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  if ('serviceWorker' in navigator) {
    const reg = await navigator.serviceWorker.ready;
    reg.showNotification(title, {
      body,
      icon: 'data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🔒</text></svg>',
      tag,
      renotify: true,
      requireInteraction: tag === 'kryptix-ongoing'
    });
  } else {
    new Notification(title, { body, tag });
  }
}

function clearNotification(tag) {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.ready.then(reg => {
      reg.getNotifications({ tag }).then(ns => ns.forEach(n => n.close()));
    });
  }
}

function requestNotificationPermission() {
  if ('Notification' in window && Notification.permission !== 'granted' && Notification.permission !== 'denied') {
    Notification.requestPermission();
  }
}

document.addEventListener("visibilitychange", () => {
  if (state.id && state.peer && document.visibilityState === 'hidden') {
    showNotification('Kryptix is running', 'Tap to return to your secure session.', 'kryptix-ongoing');
  } else if (document.visibilityState === 'visible') {
    clearNotification('kryptix-ongoing');
  }
});

/* ─── Wake Lock (keeps app alive during transfers) ──────────── */
async function acquireWakeLock() {
  if (state.wakeLock) return;
  try {
    if ('wakeLock' in navigator) {
      state.wakeLock = await navigator.wakeLock.request('screen');
      state.wakeLock.addEventListener('release', () => { state.wakeLock = null; });
    }
  } catch (e) { /* Wake Lock not supported or denied */ }
}
function releaseWakeLock() {
  if (state.wakeLock) { state.wakeLock.release().catch(() => {}); state.wakeLock = null; }
}
// Re-acquire wake lock when page becomes visible again (Chrome releases it on hide)
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && state.transfers.size > 0) acquireWakeLock();
});

/* ─── UI Helpers ────────────────────────────────────────────── */
function setStatus(text, tone) {
  el.statusText.textContent = text;
  el.statusPill.dataset.tone = tone;
}

function toast(msg, tone = "") {
  const t = document.createElement("div");
  t.className = "toast";
  if (tone) t.dataset.tone = tone;
  t.textContent = msg;
  el.toasts.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

function applyTheme(theme, save = true) {
  el.body.dataset.theme = theme;
  el.themeToggle.textContent = theme === "dark" ? "🌙" : "☀️";
  if (save) localStorage.setItem(THEME_KEY, theme);
}

function initTheme() {
  const s = localStorage.getItem(THEME_KEY);
  return s === "light" || s === "dark" ? s : matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function getOpen() {
  return [...state.conns.values()].filter(p => p.conn && p.conn.open);
}

function getVerified() {
  return getOpen().filter(p => p.verified);
}

/* ─── Controls ──────────────────────────────────────────────── */
function refresh() {
  const online = Boolean(state.id && state.peer);
  const open = getOpen();
  const hasMesh = open.length > 0;
  const hasSecret = Boolean(el.secretInput.value.trim());

  el.goOnline.disabled = online;
  el.goOffline.disabled = !online;
  el.connectBtn.disabled = !online || !hasSecret;
  el.msgInput.disabled = !hasMesh;
  el.sendBtn.disabled = !hasMesh;
  el.voiceBtn.disabled = !hasMesh;
  el.videoBtn.disabled = !hasMesh;
  el.cameraBtn.disabled = !hasMesh;
  el.filesBtn.disabled = !hasMesh;
  el.stopMedia.disabled = !state.localStream;
  el.peerCount.textContent = `${open.length} peer${open.length === 1 ? "" : "s"}`;

  if (online) {
    el.chatStatus.textContent = hasMesh
      ? `Encrypted mesh with ${open.length} peer${open.length === 1 ? "" : "s"} (${getVerified().length} verified).`
      : "You're online! Share your ID and connect to a peer to start chatting.";
  } else {
    el.chatStatus.textContent = "Go online and connect a peer to start chatting.";
  }
}

/* ─── Transfer Progress UI ──────────────────────────────────── */

window.acceptFile = async function(id) {
  const tf = state.transfers.get(id);
  if (!tf || tf.status !== "offer") return;
  const p = ensurePeer(tf.peer);
  const rec = p.files.get(tf.fid);

  // 🚀 TURBO-SAVE: Direct Disk Streaming
  // If the browser supports it, we save directly to disk chunk-by-chunk.
  if (!IS_CAPACITOR && window.showSaveFilePicker && rec && rec.size > 2 * 1024 * 1024) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: rec.dl });
      rec.writable = await handle.createWritable();
    } catch (e) {
      if (e.name === "AbortError") return; // User cancelled the picker
      console.warn("Disk stream failed, falling back to Blob:", e);
    }
  }

  tf.status = "run";
  tf.startTime = performance.now();
  tf.lastActivity = performance.now();
  renderTransfers();
  if (p.conn && p.conn.open) sendPkt(p.conn, "ctl", { action: "file-accept", fid: tf.fid });
};

window.declineFile = function(id) {
  const tf = state.transfers.get(id);
  if (!tf) return;
  const p = ensurePeer(tf.peer);
  if (p.conn && p.conn.open) sendPkt(p.conn, "ctl", { action: "file-decline", fid: tf.fid });
  state.transfers.delete(id);
  renderTransfers();
};

window.cancelFile = function(id) {
  const tf = state.transfers.get(id);
  if (!tf) return;
  tf.cancelled = true;
  
  if (id.startsWith("tx-")) {
    // SENDER cancelling -> notify all accepted receivers
    for (const pid of tf.acceptedPeers) {
      const p = state.conns.get(pid);
      if (p && p.conn && p.conn.open) sendPkt(p.conn, "ctl", { action: "file-cancel", fid: tf.fid });
    }
  } else if (id.startsWith("rx-")) {
    // RECEIVER cancelling -> notify ONLY the sender
    const p = state.conns.get(tf.peer);
    if (p && p.conn && p.conn.open) sendPkt(p.conn, "ctl", { action: "file-cancel", fid: tf.fid });
    if (p && p.files.has(tf.fid)) p.files.delete(tf.fid);
  }
  
  state.transfers.delete(id);
  renderTransfers();
};

function renderTransfers() {
  const bar = document.getElementById("transferBar");
  if (!bar) return;
  if (!state.transfers.size) { bar.style.display = "none"; bar.innerHTML = ""; return; }
  bar.style.display = "";

  for (const [id, t] of state.transfers) {
    let row = document.getElementById(id);
    if (!row) {
      row = document.createElement("div");
      row.className = "transfer-row";
      row.id = id;
      bar.appendChild(row);
    }

    if (t.status === "offer") {
      row.innerHTML = `
        <div class="transfer-info">
          <span class="transfer-icon">❓</span>
          <span class="transfer-name">Incoming: ${t.label}</span>
          <span class="transfer-size">${fmtBytes(t.fileSize)}</span>
        </div>
        <div class="transfer-actions">
          <button class="transfer-btn accept" onclick="acceptFile('${id}')">Accept</button>
          <button class="transfer-btn decline" onclick="declineFile('${id}')">Decline</button>
        </div>
      `;
      continue;
    }

    if (t.status === "wait") {
      row.innerHTML = `
        <div class="transfer-info">
          <span class="transfer-icon">⏳</span>
          <span class="transfer-name">Waiting: ${t.label}</span>
          <span class="transfer-size">${fmtBytes(t.fileSize)}</span>
        </div>
        <div class="transfer-actions">
           <button class="transfer-btn decline" onclick="cancelFile('${id}')">Cancel</button>
        </div>
      `;
      continue;
    }

    if (t.status === "run") {
      if (!document.getElementById("tf-fill-" + id)) {
        row.innerHTML = `
          <div class="transfer-info">
            <span class="transfer-icon">${t.dir === "up" ? "⬆" : "⬇"}</span>
            <span class="transfer-name">${t.label}</span>
            <span class="transfer-size">${fmtBytes(t.fileSize)}</span>
          </div>
          <div class="transfer-progress-track">
            <div class="transfer-progress-fill" id="tf-fill-${id}" style="width:0%"></div>
          </div>
          <div class="transfer-stats">
            <span id="tf-pct-${id}">0%</span>
            <span id="tf-spd-${id}">0 KB/s</span>
            <span id="tf-eta-${id}">calculating…</span>
            <span id="tf-ela-${id}">0s</span>
          </div>
          <div class="transfer-actions" style="margin-top:2px">
             <button class="transfer-btn decline" style="padding:4px 10px;font-size:0.7rem" onclick="cancelFile('${id}')">Cancel</button>
          </div>
        `;
      }

      const elapsed = (performance.now() - t.startTime) / 1000;
      let pct, bytesDone, speed, remaining, etaText;

      if (t.dir === "up") {
        // SENDER: Use sent count for responsive progress, acked for speed accuracy
        pct = t.total > 0 ? Math.min(100, Math.round((t.sent / t.total) * 100)) : 0;
        const acked = t.acked || 0;
        const ackedBytes = Math.min(acked * t.chunkSize, t.fileSize);
        speed = elapsed > 0.5 ? ackedBytes / elapsed : 0;
        // If no ACKs yet, estimate speed from sent chunks
        if (speed === 0 && t.sent > 0 && elapsed > 1) speed = Math.min(t.sent * t.chunkSize, t.fileSize) / elapsed;
        bytesDone = Math.min(t.sent * t.chunkSize, t.fileSize);
        remaining = speed > 0 ? (t.fileSize - ackedBytes) / speed : 0;
        if (t.sent === 0 && elapsed < 3) etaText = "starting…";
        else if (t.sent >= t.total) etaText = "finishing…";
        else etaText = remaining > 0 ? remaining.toFixed(1) + "s left" : "finishing…";
      } else {
        // RECEIVER: Use actual received chunk count
        pct = t.total > 0 ? Math.min(100, Math.round((t.sent / t.total) * 100)) : 0;
        bytesDone = Math.min(t.sent * t.chunkSize, t.fileSize);
        speed = elapsed > 0.5 ? bytesDone / elapsed : 0;
        remaining = speed > 0 ? (t.fileSize - bytesDone) / speed : 0;
        if (t.lastActivity && (performance.now() - t.lastActivity) > 15000 && t.sent < t.total) etaText = "stalled!";
        else etaText = remaining > 0 ? remaining.toFixed(1) + "s left" : "finishing…";
      }

      document.getElementById("tf-fill-" + id).style.width = pct + "%";
      document.getElementById("tf-pct-" + id).textContent = pct + "%";
      document.getElementById("tf-spd-" + id).textContent = fmtBytes(speed) + "/s";
      document.getElementById("tf-eta-" + id).textContent = etaText;
      document.getElementById("tf-ela-" + id).textContent = elapsed.toFixed(1) + "s";
    }
  }

  for (const el of Array.from(bar.children)) {
    if (!state.transfers.has(el.id)) el.remove();
  }

  if (document.hidden && state.transfers.size) {
    const t = [...state.transfers.values()][0];
    if (t.status !== "run") return;
    const elapsed = (performance.now() - t.startTime) / 1000;
    const progress = t.dir === "up" ? t.sent : t.sent;
    const npct = t.total > 0 ? Math.min(100, Math.round((progress / t.total) * 100)) : 0;
    const nspeed = elapsed > 0.5 ? Math.min(progress * t.chunkSize, t.fileSize) / elapsed : 0;
    if (Math.round(elapsed * 10) % 20 === 0) {
      showNotification(`${t.dir === "up" ? "Uploading" : "Downloading"} ${t.label}`, `${npct}% • ${fmtBytes(nspeed)}/s • ${fmtBytes(t.fileSize)}`, "kryptix-transfer");
    }
  }
}

/* ─── Object URLs ───────────────────────────────────────────── */
function regUrl(url) { state.urls.add(url); return url; }
function revokeUrls() { state.urls.forEach(u => URL.revokeObjectURL(u)); state.urls.clear(); }

/* ─── History ───────────────────────────────────────────────── */
function clearHistory() { state.history = []; revokeUrls(); renderTimeline(); }

function pushEntry(e) { state.history.push(e); renderTimeline(); }
function sysMsg(text, tone = "") { pushEntry({ k: "sys", tone, text, ts: Date.now() }); }
function chatMsg({ dir, text, meta }) { pushEntry({ k: "msg", dir, text, meta, ts: Date.now() }); }
function fileMsg({ dir, name, size, mime, url, meta, label, dl }) {
  pushEntry({ k: "file", dir, name, size, mime, url, meta, label: label || fileKind(mime), dl: dl || safeName(mime, name), ts: Date.now() });
}

/* ─── Render Timeline ───────────────────────────────────────── */
function renderTimeline() {
  el.timeline.textContent = "";

  if (!state.history.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const h = document.createElement("h3");
    h.textContent = state.id ? "You're online!" : "No session yet";
    const p = document.createElement("p");
    p.textContent = state.id
      ? "Share your ID with friends and connect to start messaging."
      : "Enter your name and password, then click Go Online.";
    empty.appendChild(h);
    empty.appendChild(p);
    el.timeline.appendChild(empty);
    return;
  }

  for (const item of state.history) {
    const row = document.createElement("article");
    row.className = item.k === "sys" ? "entry sys" : `entry ${item.dir === "outgoing" ? "out" : "in"}`;
    if (item.k === "sys" && item.tone) row.dataset.tone = item.tone;

    const bubble = document.createElement("div");
    bubble.className = "entry-bubble";

    if (item.k === "msg") {
      const sender = document.createElement("div");
      sender.className = "entry-sender";
      sender.textContent = item.dir === "outgoing" ? "You" : (item.meta || "Peer");
      bubble.appendChild(sender);
      const p = document.createElement("p");
      p.textContent = item.text;
      bubble.appendChild(p);
    } else if (item.k === "file") {
      const fc = document.createElement("div");
      fc.className = "file-card";
      const sender = document.createElement("div");
      sender.className = "entry-sender";
      sender.textContent = item.dir === "outgoing" ? "File sent" : "File received";
      fc.appendChild(sender);
      if (item.mime && item.mime.startsWith("image/") && item.url) {
        const prev = document.createElement("div");
        prev.className = "file-preview";
        const img = document.createElement("img");
        img.src = item.url;
        img.alt = item.name;
        prev.appendChild(img);
        fc.appendChild(prev);
      }
      const info = document.createElement("p");
      info.textContent = `${item.label} · ${fmtBytes(item.size)}`;
      fc.appendChild(info);
      if (item.meta) {
        const m = document.createElement("p");
        m.style.cssText = "font-size:0.78rem;color:var(--txt2);margin:0";
        m.textContent = item.meta;
        fc.appendChild(m);
      }
      if (item.url) {
        const a = document.createElement("button");
        a.className = "file-link";
        a.textContent = "Download";
        a.type = "button";
        const dlUrl = item.url;
        const dlName = item.dl || item.name || "kryptix-file";
        a.addEventListener("click", (e) => {
          e.preventDefault();
          downloadBlob(dlUrl, dlName);
        });
        fc.appendChild(a);
      }
      bubble.appendChild(fc);
    } else {
      const p = document.createElement("p");
      p.textContent = item.text;
      bubble.appendChild(p);
    }

    row.appendChild(bubble);

    if (item.k !== "sys") {
      const time = document.createElement("div");
      time.className = "entry-time";
      time.textContent = item.k === "msg" ? `${item.meta || "Mesh"} · ${fmtTime(item.ts)}` : fmtTime(item.ts);
      row.appendChild(time);
    }

    el.timeline.appendChild(row);
  }

  el.timeline.scrollTop = el.timeline.scrollHeight;
}

/* ─── Render Peers ──────────────────────────────────────────── */
function renderPeers() {
  el.peerList.textContent = "";
  const peers = [...state.conns.values()].sort((a, b) => a.pid.localeCompare(b.pid));

  for (const p of peers) {
    const card = document.createElement("div");
    card.className = "peer-card";

    const info = document.createElement("div");
    info.className = "peer-card-info";
    const name = document.createElement("div");
    name.className = "peer-card-name";
    name.textContent = p.pid;
    const status = document.createElement("div");
    status.className = "peer-card-status";
    info.appendChild(name);

    const badge = document.createElement("span");
    if (p.conn && p.conn.open && p.verified) {
      badge.className = "badge badge-ok";
      badge.textContent = "Secure ✓";
      status.textContent = "Connected & verified";
    } else if (p.conn && p.conn.open) {
      badge.className = "badge badge-wait";
      badge.textContent = "Handshaking…";
      status.textContent = "Connected, verifying secret…";
    } else {
      badge.className = "badge badge-off";
      badge.textContent = "Offline";
      status.textContent = "Disconnected";
    }
    info.appendChild(status);
    card.appendChild(info);

    const acts = document.createElement("div");
    acts.className = "peer-card-actions";
    acts.appendChild(badge);

    const drop = document.createElement("button");
    drop.className = "btn-small btn-outline";
    drop.textContent = "Drop";
    drop.type = "button";
    drop.addEventListener("click", () => closePeer(p.pid, true, `${p.pid} dropped.`, "warning"));
    acts.appendChild(drop);
    card.appendChild(acts);

    el.peerList.appendChild(card);
  }
}

/* ─── Render Media Grid ─────────────────────────────────────── */
function buildMediaTile({ label, sub, stream, self }) {
  const tile = document.createElement("article");
  tile.className = "media-tile";
  const stage = document.createElement("div");
  stage.className = "media-stage";
  const hasVid = stream.getVideoTracks().length > 0;

  if (hasVid) {
    const v = document.createElement("video");
    v.autoplay = true; v.playsInline = true; v.muted = Boolean(self);
    v.srcObject = stream;
    stage.appendChild(v);
    v.play().catch(() => {});
  } else {
    const shell = document.createElement("div");
    shell.className = "audio-stage";
    const wave = document.createElement("div");
    wave.className = "audio-wave";
    wave.textContent = "🎤";
    shell.appendChild(wave);
    const label2 = document.createElement("div");
    label2.textContent = self ? "Your mic is live" : "Remote audio";
    shell.appendChild(label2);
    const a = document.createElement("audio");
    a.autoplay = true; a.playsInline = true; a.muted = Boolean(self);
    a.srcObject = stream;
    shell.appendChild(a);
    a.play().catch(() => {});
    stage.appendChild(shell);
  }

  tile.appendChild(stage);

  const info = document.createElement("div");
  info.className = "media-info";
  const t = document.createElement("div");
  t.className = "media-title";
  t.textContent = label;
  info.appendChild(t);
  const c = document.createElement("div");
  c.className = "media-copy";
  c.textContent = sub;
  info.appendChild(c);
  tile.appendChild(info);
  return tile;
}

function renderMedia() {
  el.mediaGrid.textContent = "";
  const tiles = [];

  if (state.localStream) {
    tiles.push(buildMediaTile({
      label: "You",
      sub: state.localStream.getVideoTracks().length > 0 ? "Local video" : "Local audio",
      stream: state.localStream,
      self: true
    }));
  }

  for (const p of state.conns.values()) {
    if (p.activeCall && p.activeCall.remote) {
      tiles.push(buildMediaTile({
        label: p.pid,
        sub: p.activeCall.mode === "video" ? "Remote video" : "Remote audio",
        stream: p.activeCall.remote,
        self: false
      }));
    }
  }

  for (const t of tiles) el.mediaGrid.appendChild(t);
}

/* ─── Feature 1: LAN Discovery Renderer ─────────────────────── */
let discoveredLanPeers = [];

function renderNearbyDevices() {
  if (!IS_DESKTOP || !el.nearbyList) return;

  el.nearbyList.textContent = '';

  if (!discoveredLanPeers.length) {
    const empty = document.createElement('div');
    empty.className = 'nearby-empty';
    empty.textContent = state.id ? 'Scanning your network…' : 'Go online to discover nearby devices.';
    el.nearbyList.appendChild(empty);
    return;
  }

  for (const peer of discoveredLanPeers) {
    const row = document.createElement('div');
    row.className = 'nearby-peer';

    const alreadyConnected = state.conns.has(peer.peerId) &&
      state.conns.get(peer.peerId).conn &&
      state.conns.get(peer.peerId).conn.open;

    row.innerHTML = `
      <div class="nearby-peer-info">
        <div class="nearby-peer-dot ${peer.sameSecret ? 'match' : 'no-match'}"></div>
        <div>
          <div class="nearby-peer-name">${peer.peerId}</div>
          <div class="nearby-peer-ip">${peer.ip}${peer.sameSecret ? ' · <span class="nearby-peer-hint">Same password ✓</span>' : ''}</div>
        </div>
      </div>
    `;

    if (alreadyConnected) {
      const badge = document.createElement('span');
      badge.className = 'badge badge-ok';
      badge.textContent = 'Connected';
      badge.style.cssText = 'font-size:0.72rem;padding:4px 10px';
      row.appendChild(badge);
    } else {
      const btn = document.createElement('button');
      btn.className = 'nearby-connect-btn';
      btn.textContent = 'Connect';
      btn.type = 'button';
      const pid = peer.peerId;
      btn.addEventListener('click', () => {
        if (!state.peer || !state.id) { toast('Go online first.', 'danger'); return; }
        el.connectInput.value = pid;
        connectPeers().catch(e => {
          console.error(e);
          toast('Connection failed.', 'danger');
        });
      });
      row.appendChild(btn);
    }

    el.nearbyList.appendChild(row);
  }
}

async function computeSecretHash(secret) {
  if (!secret) return '';
  try {
    const data = new TextEncoder().encode(secret);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const arr = new Uint8Array(hash);
    return Array.from(arr.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) {
    return '';
  }
}

function initLanDiscovery() {
  if (!IS_DESKTOP || !window.electronAPI) return;

  // Show the nearby devices card
  if (el.nearbyCard) {
    el.nearbyCard.classList.remove('nearby-card-hidden');
    console.log('[KRYPTIX] Nearby Devices card activated');
  }

  // Listen for LAN peer updates from main process
  window.electronAPI.onLanPeers((peers) => {
    discoveredLanPeers = peers;
    renderNearbyDevices();
  });
}

async function startLanDiscovery() {
  if (!IS_DESKTOP || !window.electronAPI || !state.id) return;
  const secret = el.secretInput.value.trim();
  const secretHash = await computeSecretHash(secret);
  window.electronAPI.startDiscovery(state.id, secretHash);
  renderNearbyDevices();
}

function stopLanDiscovery() {
  if (!IS_DESKTOP || !window.electronAPI) return;
  window.electronAPI.stopDiscovery();
  discoveredLanPeers = [];
  renderNearbyDevices();
}

/* ─── Feature 4: Global Drag-and-Drop ───────────────────────── */
let dragCounter = 0;

function initDragDrop() {
  const dz = el.dropZone;
  if (!dz) return;

  // Prevent browser from opening dropped files
  window.addEventListener('dragover', (e) => e.preventDefault(), true);
  window.addEventListener('drop', (e) => e.preventDefault(), true);

  document.body.addEventListener('dragenter', (e) => {
    e.preventDefault();
    if (!e.dataTransfer || !e.dataTransfer.types.includes('Files')) return;
    dragCounter++;
    dz.classList.add('active');
  });

  document.body.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dragCounter--;
    if (dragCounter <= 0) {
      dragCounter = 0;
      dz.classList.remove('active');
    }
  });

  dz.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  });

  dz.addEventListener('drop', (e) => {
    e.preventDefault();
    dragCounter = 0;
    dz.classList.remove('active');

    const files = [...(e.dataTransfer.files || [])];
    if (!files.length) return;

    const open = getOpen();
    if (!open.length) {
      toast('Connect to a peer first before dropping files.', 'danger');
      return;
    }

    toast(`Sending ${files.length} file${files.length > 1 ? 's' : ''} via drag & drop…`, 'success');
    sendFiles(files).catch(err => {
      console.error(err);
      toast('Drag & drop send failed.', 'danger');
    });
  });
}

/* ─── Crypto (AES-256-GCM via PBKDF2) ──────────────────────── */
function b2s(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function s2b(str) {
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function deriveKey(secret) {
  const mat = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode(KDF_SALT), iterations: 310000, hash: "SHA-256" },
    mat,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function ensureKey() {
  const s = el.secretInput.value.trim();
  if (!s) throw new Error("Enter encryption password first.");
  if (state.key && state.secret === s) return state.key;
  state.key = await deriveKey(s);
  state.secret = s;
  // Initialize worker pool with the new secret (Strategy 1)
  try {
    await workerPool.init(s);
  } catch (e) {
    console.warn("Worker pool init failed, will use main-thread crypto:", e);
  }
  refresh();
  return state.key;
}

async function encText(plain) {
  const key = await ensureKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plain)));
  const packed = new Uint8Array(iv.length + ct.length);
  packed.set(iv); packed.set(ct, iv.length);
  return b2s(packed);
}

async function decText(cipher) {
  const packed = s2b(cipher);
  const iv = packed.slice(0, 12);
  const ct = packed.slice(12);
  const key = await ensureKey();
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}

async function encBytes(bytes) {
  const key = await ensureKey();
  const plain = toBytes(bytes);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain));
  const packed = new Uint8Array(iv.length + ct.length);
  packed.set(iv); packed.set(ct, iv.length);
  return packed;
}

async function decBytes(payload) {
  const packed = await toBytesAsync(payload);
  const iv = packed.subarray(0, 12);  // Zero-copy VIEW (no 1MB+ allocation)
  const ct = packed.subarray(12);     // Zero-copy VIEW (no 1MB+ allocation)
  const key = await ensureKey();
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}

// 🚀 TURBO: Combined encrypt + binary packet builder (eliminates 2MB intermediate alloc)
async function encChunkPacket(fid, chunkIdx, plainData) {
  const key = await ensureKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainData);
  const ctView = new Uint8Array(ct);
  // Single allocation: [KRYP(4)][idx(4)][fid(16)][iv(12)][ct(N+16)]
  const pkt = new Uint8Array(36 + ctView.length);
  pkt[0] = 0x4B; pkt[1] = 0x52; pkt[2] = 0x59; pkt[3] = 0x50;
  new DataView(pkt.buffer).setUint32(4, chunkIdx, true);
  for (let j = 0; j < 16; j++) pkt[8 + j] = j < fid.length ? fid.charCodeAt(j) : 0x00;
  pkt.set(iv, 24);
  pkt.set(ctView, 36);
  return pkt.buffer; // Return ArrayBuffer for zero-copy send
}

async function makePacket(kind, body) {
  return { kind, cipher: await encText(JSON.stringify(body)), v: 1, t: Date.now() };
}

async function sendPkt(conn, kind, body) {
  if (!conn || !conn.open) throw new Error("No connection");
  conn.send(await makePacket(kind, body));
}

/* ─── Peer Management ───────────────────────────────────────── */
function ensurePeer(pid) {
  if (!state.conns.has(pid)) {
    state.conns.set(pid, { pid, conn: null, verified: false, files: new Map(), activeCall: null, enqueue: makePeerQueue() });
  }
  return state.conns.get(pid);
}

function removePeer(pid, opts = {}) {
  const p = state.conns.get(pid);
  if (!p) return;
  if (p.activeCall && p.activeCall.call) try { p.activeCall.call.close(); } catch (e) { console.error(e); }
  if (p.conn) try { p.conn.close(); } catch (e) { console.error(e); }
  state.conns.delete(pid);
  renderPeers();
  renderMedia();
  refresh();
  if (!opts.quiet && opts.reason) sysMsg(opts.reason, opts.tone || "warning");
}

async function closePeer(pid, notify = true, reason = "", tone = "warning") {
  const p = state.conns.get(pid);
  if (!p) return;
  if (notify && p.conn && p.conn.open) await sendPkt(p.conn, "ctl", { action: "disconnect" }).catch(() => {});
  removePeer(pid, { reason, tone });
}

async function disconnectAll(notify = true, reason = "") {
  const ids = [...state.conns.keys()];
  for (const id of ids) await closePeer(id, notify, "", "warning");
  if (ids.length && reason) sysMsg(reason, "warning");
}

/* ─── Peer Options ──────────────────────────────────────────── */
function peerOpts() {
  const rtc = cfg.rtcConfig && typeof cfg.rtcConfig === "object" ? { ...cfg.rtcConfig } : {};
  const custom = Array.isArray(cfg.iceServers) && cfg.iceServers.length ? cfg.iceServers : null;
  if (!Array.isArray(rtc.iceServers) || !rtc.iceServers.length) rtc.iceServers = custom || ICE;
  return {
    ...(cfg.peerServer && typeof cfg.peerServer === "object" ? cfg.peerServer : {}),
    config: rtc,
    debug: Number.isFinite(cfg.peerDebug) ? cfg.peerDebug : 0
  };
}

/* ─── Attach Data Connection ────────────────────────────────── */
async function attachConn(conn, local) {
  if (!el.secretInput.value.trim()) {
    try { conn.close(); } catch (e) { console.error(e); }
    toast("Enter encryption password before connecting.", "danger");
    return;
  }

  await ensureKey();
  const p = ensurePeer(conn.peer);

  if (p.conn && p.conn !== conn && p.conn.open) {
    try { conn.close(); } catch (e) { console.error(e); }
    return;
  }

  p.conn = conn;
  p.verified = false;
  renderPeers();
  refresh();
  setStatus(local ? "Connecting…" : "Incoming peer…", "pending");

  conn.on("open", async () => {
    p.conn = conn;
    p.verified = false;
    setStatus("Mesh live", "ready");
    renderPeers();
    refresh();
    sysMsg(`${conn.peer} joined the mesh.`, "success");
    fails.n = 0;

    // Auto-scroll to chat on mobile
    if (window.innerWidth < MOBILE_BP && el.chatPanel) {
      el.chatPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    await sendPkt(conn, "ctl", { action: "hello", label: state.id }).catch(() => {});
  });

  conn.on("data", async (pkt) => {
    // Binary file chunks — fast path
    let u8;
    if (pkt instanceof Blob && pkt.size > 24) {
      u8 = new Uint8Array(await pkt.arrayBuffer());
    } else if (pkt instanceof ArrayBuffer && pkt.byteLength > 24) {
      u8 = new Uint8Array(pkt);
    } else if (ArrayBuffer.isView(pkt) && pkt.byteLength > 24) {
      u8 = new Uint8Array(pkt.buffer, pkt.byteOffset, pkt.byteLength);
    }

    if (u8) {
      if (u8[0] === 0x4B && u8[1] === 0x52 && u8[2] === 0x59 && u8[3] === 0x50) { // "KRYP"
        const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
        const i = view.getUint32(4, true);
        let fid = "";
        for (let b = 0; b < 16; b++) { if (u8[8 + b] === 0x00) break; fid += String.fromCharCode(u8[8 + b]); }
        const cipher = new Uint8Array(u8.buffer, u8.byteOffset + 24, u8.byteLength - 24);
        
        handlePkt(conn.peer, { kind: "file-chunk", fid, i, cipher }).catch(e => console.error("Chunk error", e));
        return;
      }
    }

    if (pkt && pkt.kind === "file-chunk") {
      handlePkt(conn.peer, pkt).catch(e => console.error("Chunk decryption error", e));
      return;
    }

    // Message packets must be serial to preserve chat order
    const p = ensurePeer(conn.peer);
    p.enqueue(() => handlePkt(conn.peer, pkt).catch(e => {
      console.error(e);
      toast(`Packet from ${conn.peer} failed. Check password.`, "danger");
    }));
  });

  conn.on("close", () => {
    if (state.conns.has(conn.peer)) {
      removePeer(conn.peer, { reason: `${conn.peer} left.`, tone: "warning" });
    }
  });

  conn.on("error", (e) => {
    console.error(e);
    toast(`Error with ${conn.peer}: ${e.message || "Unknown"}`, "danger");
  });
}

/* ─── Handle Incoming Packet ────────────────────────────────── */
async function handlePkt(pid, pkt) {
  if (!pkt || typeof pkt !== "object") return;
  const p = ensurePeer(pid);

  // File chunk — receiver side with progress tracking
  if (pkt.kind === "file-chunk") {
    const rec = p.files.get(pkt.fid);
    if (!rec) return;
    if (!rec.chunks[pkt.i]) {
      // 🚀 HyperTransfer: Decrypt using worker pool (off main thread) or raw turbo mode
      let decrypted;
      if (rec.turbo) {
        // Turbo mode: data is already plaintext (DTLS handles transport encryption)
        decrypted = pkt.cipher instanceof ArrayBuffer ? new Uint8Array(pkt.cipher) : toBytes(pkt.cipher);
      } else if (workerPool.ready) {
        // Strategy 1: Worker pool decryption (zero-copy via Transferable)
        const cipherBuf = pkt.cipher instanceof ArrayBuffer ? pkt.cipher
          : pkt.cipher.buffer.slice(pkt.cipher.byteOffset, pkt.cipher.byteOffset + pkt.cipher.byteLength);
        const plainBuf = await workerPool.decryptChunk(cipherBuf);
        decrypted = new Uint8Array(plainBuf);
      } else {
        // Fallback: main-thread decryption
        decrypted = await decBytes(pkt.cipher);
      }
      
      if (rec.writable) {
        // Direct stream to SSD/HDD (Strategy 4)
        await rec.writable.write(decrypted);
      } else {
        // Fallback to RAM Blobs
        rec.chunks[pkt.i] = new Blob([decrypted]);
      }
      
      rec.got++;
      // Update receiver progress bar — batch updates for performance
      const tf = state.transfers.get("rx-" + pkt.fid);
      if (tf) { 
        tf.sent = rec.got;
        tf.lastActivity = performance.now();
        if (rec.got % 4 === 0 || rec.got === rec.total) requestAnimationFrame(renderTransfers); 
      }
      // ACK for progress display (not flow control)
      const ackStep = rec.total < 16 ? 1 : K_ACK_STEP;
      if (rec.got % ackStep === 0 || rec.got === rec.total) {
        if (p.conn && p.conn.open) sendPkt(p.conn, "ctl", { action: "file-ack", fid: pkt.fid, i: rec.got }).catch(() => {});
      }
    }
    if (rec.got === rec.total) {
      const tf = state.transfers.get("rx-" + pkt.fid);
      const elapsed = tf ? ((performance.now() - tf.startTime) / 1000).toFixed(1) : "?";
      const speed = tf ? fmtBytes(rec.size / Math.max(0.1, (performance.now() - tf.startTime) / 1000)) : "?";

      let url = "";
      if (rec.writable) {
        await rec.writable.close();
        url = "#"; // Already saved to disk
      } else {
        const blob = new Blob(rec.chunks, { type: rec.mime || "application/octet-stream" });
        url = regUrl(URL.createObjectURL(blob));
      }
      
      state.transfers.delete("rx-" + pkt.fid);
      renderTransfers();
      fileMsg({ dir: "incoming", name: rec.dl, size: rec.size, mime: rec.mime, url, meta: `From ${pid} in ${elapsed}s (${speed}/s)`, label: rec.label, dl: rec.dl, auto: !!rec.writable });
      p.files.delete(pkt.fid);
      toast(`Received ${rec.label.toLowerCase()} from ${pid} • ${elapsed}s • ${speed}/s`, "success");
      if (document.hidden) showNotification(`✅ ${rec.label} downloaded`, `From ${pid} • ${elapsed}s • ${speed}/s`);
    }
    return;
  }

  if (pkt.kind !== "payload" && pkt.kind !== "ctl") return;

  const body = JSON.parse(await decText(pkt.cipher));

  // Anti-replay: reject packets older than 30 seconds
  if (pkt.t && Math.abs(Date.now() - pkt.t) > ANTI_REPLAY_MS) return;

  if (pkt.kind === "payload") {
    chatMsg({ dir: "incoming", text: body.text || "", meta: pid });
    if (document.hidden) showNotification(`Message from ${pid}`, body.text || "Sent a message");
    return;
  }

  // Control messages
  if (body.action === "hello") {
    p.verified = true;
    renderPeers();
    refresh();
    sysMsg(`${pid} verified ✓`, "success");
    return;
  }
  if (body.action === "disconnect") {
    removePeer(pid, { reason: `${pid} disconnected.`, tone: "warning" });
    return;
  }
  if (body.action === "panic-wipe") {
    await panicWipe(true);
    return;
  }
  if (body.action === "file-offer") {
    const chunkSize = body.size > 0 && body.totalChunks > 0 ? Math.ceil(body.size / body.totalChunks) : FILE_CHUNK_WAN;
    p.files.set(body.fid, {
      fid: body.fid, name: body.name, size: body.size, mime: body.type,
      label: body.label || fileKind(body.type), dl: body.dl || safeName(body.type, body.name),
      total: body.totalChunks, got: 0, chunks: new Array(body.totalChunks),
      turbo: !!body.turbo,  // Strategy 5: sender indicated turbo mode
      bonded: !!body.bonded // Strategy 2: sender is using bond channels
    });
    state.transfers.set("rx-" + body.fid, {
      id: "rx-" + body.fid, fid: body.fid, peer: pid,
      dir: "down", label: body.label || fileKind(body.type), fileSize: body.size,
      sent: 0, total: body.totalChunks, chunkSize,
      status: "offer", startTime: null, lastActivity: null,
      turbo: !!body.turbo
    });

    if (body.size < 20 * 1024 * 1024) {
      // AUTO-ACCEPT files under 20MB
      const tf = state.transfers.get("rx-" + body.fid);
      tf.status = "run";
      tf.startTime = performance.now();
      tf.lastActivity = performance.now();
      renderTransfers();
      if (p.conn && p.conn.open) sendPkt(p.conn, "ctl", { action: "file-accept", fid: body.fid });
      return;
    }

    renderTransfers();
    sysMsg(`Incoming ${body.label || "file"} from ${pid} (${fmtBytes(body.size)}).`, "warning");
    if (document.hidden) showNotification(`File from ${pid}`, `Accept or decline ${body.label} (${fmtBytes(body.size)})`);
    return;
  }
  if (body.action === "file-accept") {
    const tf = state.transfers.get("tx-" + body.fid);
    if (tf) tf.acceptedPeers.add(pid);
    return;
  }
  if (body.action === "file-decline") {
    const tf = state.transfers.get("tx-" + body.fid);
    if (tf) tf.declinedPeers.add(pid);
    return;
  }
  if (body.action === "file-ack") {
    const tf = state.transfers.get("tx-" + body.fid);
    if (tf && body.i > tf.acked) {
      tf.acked = body.i; // Progress the sliding window
    }
    return;
  }
  if (body.action === "file-cancel") {
    const tfTx = state.transfers.get("tx-" + body.fid);
    if (tfTx) {
       tfTx.acceptedPeers.delete(pid);
       if (tfTx.acceptedPeers.size === 0) {
          tfTx.cancelled = true;
          state.transfers.delete("tx-" + body.fid);
          renderTransfers();
       }
       toast(`Peer ${pid} cancelled the transfer.`, "warning");
    }
    const tfRx = state.transfers.get("rx-" + body.fid);
    if (tfRx) {
       // Only accept cancel if it came from the SENDER!
       if (tfRx.peer === pid) {
         const rec = p.files.get(body.fid);
         if (rec && rec.writable) try { rec.writable.close(); } catch(e){}
         state.transfers.delete("rx-" + body.fid);
         p.files.delete(body.fid);
         toast(`Transfer cancelled by sender ${pid}.`, "warning");
         renderTransfers();
       }
    }
    return;
  }

  // 🚀 HYPER-DRIVE: Native HTTP offer from another App user
  if (body.action === "hyper-drive-offer" && HyperDrive) {
    const fid = body.fid;
    const url = `http://${body.ip}:${body.port}`;
    const fileSize = body.fileSize;
    const fileName = body.fileName || "kryptix-download";
    const secret = el.secretInput.value.trim();

    state.transfers.set("rx-" + fid, {
      id: "rx-" + fid, fid, peer: pid, dir: "down",
      label: body.label || "File", fileSize,
      sent: 0, total: 100, chunkSize: 1,
      status: "run", startTime: performance.now()
    });
    renderTransfers();
    toast(`\u26a1 Hyper-Drive download from ${pid}!`, "success");

    const progressHandler = HyperDrive.addListener('hyper-progress', (ev) => {
      if (ev.fid !== fid) return;
      const tf = state.transfers.get("rx-" + fid);
      if (tf) {
        tf.sent = Math.round((ev.bytesWritten / ev.totalBytes) * 100);
        requestAnimationFrame(renderTransfers);
      }
    });

    try {
      const result = await HyperDrive.download({ url, fid, secret, fileName, fileSize });
      const tf = state.transfers.get("rx-" + fid);
      const elapsed = tf ? ((performance.now() - tf.startTime) / 1000).toFixed(1) : "?";
      const speed = tf ? fmtBytes(fileSize / Math.max(0.1, (performance.now() - tf.startTime) / 1000)) : "?";

      state.transfers.delete("rx-" + fid);
      renderTransfers();
      fileMsg({ dir: "incoming", name: fileName, size: fileSize, mime: "application/octet-stream", url: "#", meta: `\u26a1 Hyper-Drive from ${pid} in ${elapsed}s (${speed}/s)`, label: body.label || "File", dl: fileName });
      toast(`\u26a1 Hyper-Drive: ${fmtBytes(fileSize)} in ${elapsed}s (${speed}/s)`, "success");
      // Signal sender that download is complete
      if (p.conn && p.conn.open) sendPkt(p.conn, "ctl", { action: "hyper-drive-done", fid }).catch(() => {});
    } catch (e) {
      console.error("Hyper-Drive download failed:", e);
      state.transfers.delete("rx-" + fid);
      renderTransfers();
      toast(`Hyper-Drive failed: ${e.message || e}`, "danger");
    } finally {
      if (progressHandler && progressHandler.remove) progressHandler.remove();
    }
    return;
  }

  if (body.action === "hyper-drive-offer" && !HyperDrive) {
    if (p.conn && p.conn.open) sendPkt(p.conn, "ctl", { action: "hyper-drive-fallback", fid: body.fid });
    return;
  }
  if (body.action === "hyper-drive-fallback") {
    const tf = state.transfers.get("tx-" + body.fid);
    if (tf) tf.hyperFallback = true;
    return;
  }
  if (body.action === "hyper-drive-done") {
    const tf = state.transfers.get("tx-" + body.fid);
    if (tf) {
      tf.cancelled = true; // Signal the sender's wait loop to exit
      state.transfers.delete(tf.id);
      renderTransfers();
      const elapsed = ((performance.now() - tf.startTime) / 1000).toFixed(1);
      const speed = fmtBytes(tf.fileSize / Math.max(0.1, (performance.now() - tf.startTime) / 1000));
      fileMsg({ dir: "outgoing", name: tf.label, size: tf.fileSize, mime: "application/octet-stream", url: "#", meta: `\u26a1 Hyper-Drive sent in ${elapsed}s (${speed}/s)`, label: tf.label, dl: tf.label });
      toast(`\u26a1 Sent via Hyper-Drive \u2022 ${elapsed}s \u2022 ${speed}/s`, "success");
    }
    if (HyperDrive) HyperDrive.stopServer().catch(() => {});
    return;
  }
}

/* ─── Media ─────────────────────────────────────────────────── */
function stopLocal() {
  if (!state.localStream) return;
  state.localStream.getTracks().forEach(t => t.stop());
  state.localStream = null;
  state.streamMode = "none";
}

function stopAllMedia(quiet = false) {
  for (const p of state.conns.values()) {
    if (p.activeCall) {
      try { p.activeCall.call.close(); } catch (e) { console.error(e); }
      p.activeCall = null;
    }
  }
  stopLocal();
  renderPeers();
  renderMedia();
  refresh();
  if (!quiet) sysMsg("Media stopped.", "warning");
}

async function getStream(mode) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error("Browser does not support media capture.");
  }
  if (state.localStream) {
    const hasA = state.localStream.getAudioTracks().length > 0;
    const hasV = state.localStream.getVideoTracks().length > 0;
    if (mode === "voice" && hasA) return state.localStream;
    if (mode === "video" && hasA && hasV) return state.localStream;
    stopLocal();
  }
  const c = mode === "video"
    ? { audio: true, video: { width: { ideal: 1280 }, height: { ideal: 720 } } }
    : { audio: true, video: false };
  state.localStream = await navigator.mediaDevices.getUserMedia(c);
  state.streamMode = mode;
  renderMedia();
  refresh();
  return state.localStream;
}

function attachCall(pid, call, mode) {
  const p = ensurePeer(pid);
  const cid = call.metadata && call.metadata.cid ? call.metadata.cid : rndId();
  if (p.activeCall && p.activeCall.call !== call) {
    try { p.activeCall.call.close(); } catch (e) { console.error(e); }
  }
  p.activeCall = { call, cid, mode, remote: null };
  renderPeers(); renderMedia(); refresh();

  call.on("stream", (remote) => {
    const cur = state.conns.get(pid);
    if (!cur || !cur.activeCall || cur.activeCall.cid !== cid) return;
    cur.activeCall.remote = remote;
    renderPeers(); renderMedia(); refresh();
  });
  call.on("close", () => {
    const cur = state.conns.get(pid);
    if (!cur || !cur.activeCall || cur.activeCall.cid !== cid) return;
    cur.activeCall = null;
    renderPeers(); renderMedia(); refresh();
  });
  call.on("error", (e) => {
    console.error(e);
    toast(`Media error with ${pid}: ${e.message || "Unknown"}`, "danger");
  });
}

async function callPeer(pid, mode) {
  if (!state.peer || !state.id) { toast("Go online first.", "danger"); return; }
  const p = state.conns.get(pid);
  if (!p || !p.conn || !p.conn.open) { toast(`No connection to ${pid}.`, "danger"); return; }
  const stream = await getStream(mode);
  if (p.activeCall) {
    try { p.activeCall.call.close(); } catch (e) { console.error(e); }
    p.activeCall = null;
  }
  const call = state.peer.call(pid, stream, { metadata: { mode, cid: rndId() } });
  attachCall(pid, call, mode);
  sysMsg(`${mode === "video" ? "Video" : "Voice"} call started with ${pid}.`, "success");
}

async function callAll(mode) {
  const open = getOpen();
  if (!open.length) { toast("Connect a peer first.", "danger"); return; }
  for (const p of open) {
    await callPeer(p.pid, mode);
    await new Promise(r => setTimeout(r, 0));
  }
}

/* ─── Go Online / Offline ───────────────────────────────────── */
async function goOnline() {
  requestNotificationPermission();
  const raw = el.peerIdInput.value;
  const id = sanitizeId(raw);
  el.peerIdInput.value = id;

  if (!id) { toast("Enter a valid name (letters, numbers, hyphens).", "danger"); return; }
  if (!el.secretInput.value.trim()) { toast("Enter an encryption password.", "danger"); return; }
  if (state.peer || state.booting) { toast("Already online.", "warning"); return; }

  if (!window.Peer) {
    setStatus("PeerJS unavailable", "danger");
    toast("PeerJS library could not load. Check your internet and reload.", "danger");
    return;
  }

  state.booting = true;
  setStatus("Connecting…", "pending");
  refresh();

  state.peer = new Peer(id, peerOpts());

  state.peer.on("open", async (pid) => {
    state.id = pid;
    state.booting = false;
    setStatus("Online", "ready");
    el.idDisplay.style.display = "";
    el.myPeerId.textContent = pid;
    sysMsg(`You're online as ${pid}. Share your ID with friends!`, "success");
    refresh();
    // Feature 1: Start LAN auto-discovery
    startLanDiscovery();

    // Feature: Ensure mobile app runs entirely in the background
    if (IS_CAPACITOR && window.Capacitor && window.Capacitor.Plugins.BackgroundMode) {
      try {
        await window.Capacitor.Plugins.BackgroundMode.configure({
          title: "Kryptix Active",
          text: "Secure tunnel running",
          hidden: false,
          silent: true
        });
        await window.Capacitor.Plugins.BackgroundMode.enable();
      } catch(e) { console.error("Foreground Service error:", e); }
    }
  });

  state.peer.on("connection", async (incoming) => {
    // Bot protection: block UUID-format peer IDs (automated bots)
    const pid = incoming.peer || "";
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(pid)) {
      console.warn("Blocked bot connection:", pid);
      try { incoming.close(); } catch (e) {}
      return;
    }
    if (!rlIncoming.ok(incoming.peer)) {
      toast(`Blocked rapid connection from ${incoming.peer}.`, "warning");
      try { incoming.close(); } catch (e) { console.error(e); }
      return;
    }
    
    // Strategy 2: Bond Channel Receiver
    // We do NOT treat bond channels as UI-level peers. They only receive raw file chunks.
    if (incoming.metadata && incoming.metadata.bond) {
      incoming.on("data", async (pkt) => {
        let u8;
        if (pkt instanceof Blob && pkt.size > 24) {
          u8 = new Uint8Array(await pkt.arrayBuffer());
        } else if (pkt instanceof ArrayBuffer && pkt.byteLength > 24) {
          u8 = new Uint8Array(pkt);
        } else if (ArrayBuffer.isView(pkt) && pkt.byteLength > 24) {
          u8 = new Uint8Array(pkt.buffer, pkt.byteOffset, pkt.byteLength);
        }

        if (u8) {
          if (u8[0] === 0x4B && u8[1] === 0x52 && u8[2] === 0x59 && u8[3] === 0x50) { // "KRYP"
            const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
            const i = view.getUint32(4, true);
            let fid = "";
            for (let b = 0; b < 16; b++) { if (u8[8 + b] === 0x00) break; fid += String.fromCharCode(u8[8 + b]); }
            const cipher = new Uint8Array(u8.buffer, u8.byteOffset + 24, u8.byteLength - 24);
            
            handlePkt(pid, { kind: "file-chunk", fid, i, cipher }).catch(e => console.error("Bond Chunk error", e));
          }
        }
      });
      incoming.on("error", () => {}); // Ignore bond channel errors
      return; // Do NOT call attachConn
    }

    await attachConn(incoming, false);
  });

  state.peer.on("call", async (call) => {
    const mode = call.metadata && call.metadata.mode === "video" ? "video" : "voice";
    try {
      const stream = await getStream(mode);
      attachCall(call.peer, call, mode);
      call.answer(stream);
      sysMsg(`${call.peer} started a ${mode} call.`, "success");
    } catch (e) {
      console.error(e);
      toast(`Could not answer ${mode} call. Allow mic/camera access.`, "danger");
      try { call.close(); } catch (e2) { console.error(e2); }
    }
  });

  state.peer.on("disconnected", () => {
    setStatus("Reconnecting…", "pending");
    // Auto-reconnect with retry logic
    let retries = 0;
    const tryReconnect = () => {
      if (!state.peer || state.peer.destroyed) return;
      if (state.peer.open) { setStatus("Online", "ready"); return; }
      retries++;
      if (retries > 10) { toast("Could not reconnect. Go offline and back online.", "danger"); return; }
      try { state.peer.reconnect(); } catch (e) { console.error(e); }
      setTimeout(tryReconnect, Math.min(1000 * retries, 5000));
    };
    setTimeout(tryReconnect, 500);
  });

  state.peer.on("error", async (err) => {
    console.error(err);
    state.booting = false;
    fails.n++;
    if (fails.n >= 15) {
      fails.until = Date.now() + 60000;
      fails.n = 0;
      toast("Too many failures. Locked for 60 seconds.", "danger");
    }

    if (err.type === "unavailable-id") {
      toast("That name is already taken! Try a different one.", "danger");
      await destroyPeer();
      setStatus("Name taken", "danger");
      refresh();
      return;
    }
    if (err.type === "invalid-id") {
      toast("Invalid name. Use only letters, numbers, hyphens, or underscores.", "danger");
      await destroyPeer();
      setStatus("Invalid name", "danger");
      refresh();
      return;
    }
    if (err.type === "network" || err.type === "server-error") {
      setStatus("Network issue", "pending");
      toast("Network issue detected. Retrying…", "warning");
      return;
    }
    setStatus("Error", "danger");
    toast(err.message || "Unexpected error.", "danger");
  });
}

async function destroyPeer() {
  stopLanDiscovery(); // Feature 1: Stop broadcasting

  // Feature: Terminate Mobile Background Mode
  if (IS_CAPACITOR && window.Capacitor && window.Capacitor.Plugins.BackgroundMode) {
    try { await window.Capacitor.Plugins.BackgroundMode.disable(); } catch(e) {}
  }

  for (const pid of [...state.conns.keys()]) removePeer(pid, { quiet: true });
  stopAllMedia(true);
  if (state.peer) try { state.peer.destroy(); } catch (e) { console.error(e); }
  state.peer = null;
  state.id = "";
  state.booting = false;
  el.idDisplay.style.display = "none";
  el.myPeerId.textContent = "";
  refresh();
  renderPeers();
  renderMedia();
}

async function goOffline() {
  await destroyPeer();
  setStatus("Offline", "pending");
  sysMsg("You went offline.", "warning");
  refresh();
}

/* ─── Connect to Peers ──────────────────────────────────────── */
async function connectPeers() {
  if (!state.peer || !state.id) {
    toast("Go online first.", "danger");
    return;
  }
  if (!el.secretInput.value.trim()) {
    toast("Enter encryption password before connecting.", "danger");
    return;
  }

  if (Date.now() < fails.until) {
    toast(`Locked. Wait ${Math.ceil((fails.until - Date.now()) / 1000)}s.`, "danger");
    return;
  }
  if (!rlConnect.ok()) {
    toast("Too many connection attempts. Wait a moment.", "warning");
    return;
  }

  await ensureKey();
  const targets = parseTargets(el.connectInput.value);
  if (!targets.length) { toast("Paste a peer ID to connect.", "danger"); return; }

  let n = 0;
  for (const tid of targets) {
    if (tid === state.id) continue;
    const ex = state.conns.get(tid);
    if (ex && ex.conn && ex.conn.open) continue;
    const conn = state.peer.connect(tid, { reliable: true });
    await attachConn(conn, true);
    n++;
  }

  toast(n ? `Connecting to ${n} peer${n === 1 ? "" : "s"}…` : "Already connected or no new peers.");
  el.connectInput.value = "";
}

/* ─── Send Message ──────────────────────────────────────────── */
async function sendMessage(e) {
  e.preventDefault();
  let text = el.msgInput.value.trim();
  if (!text) return;

  if (text.length > MAX_MSG) {
    text = text.slice(0, MAX_MSG);
    toast(`Truncated to ${MAX_MSG.toLocaleString()} characters.`, "warning");
  }
  if (!rlMessage.ok()) {
    toast("Slow down! Too many messages.", "warning");
    return;
  }

  const open = getOpen();
  if (!open.length) { toast("No peers connected.", "danger"); return; }

  // Fire UI immediately so it feels instantaneous, then send in background
  chatMsg({ dir: "outgoing", text, meta: `You → ${open.length} peer${open.length === 1 ? "" : "s"}` });
  el.msgInput.value = "";
  autosize();

  Promise.allSettled(open.map(p => sendPkt(p.conn, "payload", { text }))).catch(e => console.error(e));
}

/* ─── Send Files ────────────────────────────────────────────── */

function detectNetworkMode() {
  if (navigator.connection) {
    const c = navigator.connection;
    if (c.type === 'wifi' || c.type === 'ethernet' || (c.downlink && c.downlink > 10)) return 'lan';
  }
  if (window.innerWidth >= MOBILE_BP) return 'lan';
  return 'wan';
}

function getChunkSize(mode) {
  if (mode === 'wan') return FILE_CHUNK_WAN;
  return FILE_CHUNK_LAN;
}

async function sendFiles(files) {
  const open = getOpen();
  if (!open.length) { toast("No peers connected.", "danger"); return; }

  const mode = detectNetworkMode();
  const isLAN = mode === 'lan';
  // Feature 5: Desktop speed overrides — larger chunks, bigger buffers
  const CHUNK = IS_DESKTOP && isLAN ? DESKTOP_CHUNK : getChunkSize(mode);
  const MAX_FILE = isLAN ? MAX_FILE_LAN : MAX_FILE_RELAY;
  const BUF_HIGH = IS_DESKTOP && isLAN ? DESKTOP_BUFFER_HIGH : (isLAN ? BUFFER_HIGH_LAN : BUFFER_HIGH_WAN);
  const BUF_LOW = IS_DESKTOP && isLAN ? DESKTOP_BUFFER_LOW : (isLAN ? BUFFER_LOW_LAN : BUFFER_LOW_WAN);

  for (const file of files) {
    // Launch each file transfer as an independent async task.
    // This allows concurrent uploads AND receiving messages simultaneously.
    (async () => {
    if (file.size > MAX_FILE) {
      toast(`"${file.name}" exceeds ${fmtBytes(MAX_FILE)} limit.`, "danger");
      return;
    }
    
    let prep;
    try {
      prep = await prepFile(file);
    } catch (err) {
      console.error(err);
      toast(`Could not process "${file.name}". Check storage permissions.`, "danger");
      return; // return inside IIFE, not continue
    }

    // 🚀 HYPER-DRIVE: If we are a native app, try to serve via raw HTTP first
    if (HyperDrive && await hyperDriveAvailable()) {
      const fid = rndId();
      const secret = el.secretInput.value.trim();

      try {
        // Write to cache for native server to access
        const cacheDir = '/data/data/com.kryptix.kryptix/cache/';
        const tempName = 'kryptix-hd-' + fid;
        const tempPath = cacheDir + tempName;

        // Use Capacitor Filesystem if available, otherwise fallback
        if (window.Capacitor && window.Capacitor.Plugins.Filesystem) {
          const reader = new FileReader();
          const b64 = await new Promise((resolve, reject) => {
            reader.onload = () => resolve(reader.result.split(',')[1]);
            reader.onerror = reject;
            reader.readAsDataURL(prep.blob);
          });
          await window.Capacitor.Plugins.Filesystem.writeFile({
            path: tempName, data: b64, directory: 'CACHE'
          });
        }

        const serverResult = await HyperDrive.startServer({ fid, filePath: tempPath, secret });

        const hdOffer = {
          action: "hyper-drive-offer", fid,
          ip: serverResult.ip, port: serverResult.port,
          fileSize: prep.size, fileName: prep.dl, label: prep.label
        };

        const tf = {
          id: "tx-" + fid, fid, dir: "up", label: prep.label, fileSize: prep.size,
          sent: 0, total: 100, chunkSize: 1, startTime: performance.now(),
          status: "run", acceptedPeers: new Set(open.map(p => p.pid)),
          declinedPeers: new Set(), cancelled: false, acked: 0, hyperFallback: false
        };
        state.transfers.set(tf.id, tf);
        renderTransfers();

        await Promise.allSettled(open.map(p => sendPkt(p.conn, "ctl", hdOffer)));
        await new Promise(r => setTimeout(r, 2000));

        if (tf.hyperFallback) {
          await HyperDrive.stopServer().catch(() => {});
          state.transfers.delete(tf.id);
          renderTransfers();
          toast("Peer is on web. Using WebRTC engine.", "warning");
          // Fall through to WebRTC below
        } else {
          // Server is active, receiver is downloading via native HTTP
          toast(`\u26a1 Hyper-Drive serving ${prep.label}`, "success");
          // Wait for hyper-drive-done signal
          while (state.transfers.has(tf.id) && !tf.cancelled) {
            await new Promise(r => setTimeout(r, 500));
          }
          await HyperDrive.stopServer().catch(() => {});
          return; // HyperDrive handled it completely
        }
      } catch (e) {
        console.warn("HyperDrive failed, falling back to WebRTC:", e);
        if (HyperDrive) await HyperDrive.stopServer().catch(() => {});
      }
    }

    // ─── HYPERTRANSFER V8 ENGINE (All 5 Strategies) ───
    const turboMode = state.turbo && isLAN; // Strategy 5: skip app-layer crypto on LAN
    const total = Math.max(1, Math.ceil(prep.size / CHUNK));
    const fid = fileId();
    const useBonding = isLAN && prep.size > BOND_THRESHOLD && open.length > 0; // Strategy 2

    await Promise.allSettled(open.map(p => sendPkt(p.conn, "ctl", {
      action: "file-offer", fid, name: prep.dl, dl: prep.dl, label: prep.label,
      size: prep.size, type: prep.type, totalChunks: total,
      turbo: turboMode,   // Strategy 5: tell receiver to skip decryption
      bonded: useBonding  // Strategy 2: tell receiver we may use bond channels
    })));

    const startTime_offer = performance.now();

    const tf = {
      id: "tx-" + fid, fid: fid, dir: "up", label: prep.label, fileSize: prep.size,
      sent: 0, total, chunkSize: CHUNK, startTime: startTime_offer,
      status: "wait", acceptedPeers: new Set(), declinedPeers: new Set(), cancelled: false,
      acked: 0, turbo: turboMode
    };
    state.transfers.set(tf.id, tf);
    
    // Show turbo indicator on transfer bar
    if (turboMode) {
      const bar = document.getElementById("transferBar");
      if (bar) bar.classList.add("turbo-active");
    }
    renderTransfers();

    // Wait for at least one peer to accept
    let waitTime = 0;
    while (tf.status === "wait" && waitTime < 120000 && !tf.cancelled) {
      if (tf.declinedPeers.size === open.length) {
         toast("All peers declined the file.", "warning");
         state.transfers.delete(tf.id);
         renderTransfers();
         break;
      }
      if (tf.acceptedPeers.size > 0) {
         tf.status = "run";
         tf.startTime = performance.now();
         renderTransfers();
         break;
      }
      await new Promise(r => setTimeout(r, 100)); // fast poll for auto-accept
      waitTime += 100;
    }

    if (tf.status === "wait" || tf.cancelled || tf.acceptedPeers.size === 0) {
      if (tf.status === "wait") toast("File offer timed out.", "warning");
      state.transfers.delete(tf.id);
      renderTransfers();
      return; // return inside IIFE
    }

    const startTime = tf.startTime;
    
    // Real-time progress update timer (runs even during backpressure waits)
    const renderTimer = setInterval(() => {
      if (state.transfers.has(tf.id)) renderTransfers();
      else clearInterval(renderTimer);
    }, 250);
    
    // ─── Strategy 2: Bond Channel Setup ───
    // For large files on LAN, open additional parallel PeerJS connections
    // Each bond = independent SCTP association = independent congestion window
    let bondConns = []; // Array of { conn, dataChannel } objects for bonded send
    if (useBonding && state.peer && state.peer.open) {
      const bondTarget = [...tf.acceptedPeers][0]; // Bond with first accepted peer
      const bondPromises = [];
      
      for (let b = 0; b < BOND_CHANNELS - 1; b++) { // -1 because main conn is bond #0
        bondPromises.push(new Promise((resolve) => {
          try {
            const bondId = `${bondTarget}`;
            const bondConn = state.peer.connect(bondId, { 
              reliable: true, 
              label: `kx-bond-${fid}-${b}`,
              metadata: { bond: true, fid, bondIdx: b + 1 }
            });
            
            const timeout = setTimeout(() => {
              resolve(null); // Bond failed, proceed without it
            }, 3000);
            
            bondConn.on('open', () => {
              clearTimeout(timeout);
              resolve(bondConn);
            });
            
            bondConn.on('error', () => {
              clearTimeout(timeout);
              resolve(null);
            });
          } catch (e) {
            resolve(null);
          }
        }));
      }
      
      const results = await Promise.all(bondPromises);
      bondConns = results.filter(c => c && c.open);
      
      if (bondConns.length > 0) {
        sysMsg(`⚡ ${bondConns.length + 1} bond channels active for ${prep.label}`, "success");
      }
    }
    
    // Build the "all send targets" array: main conn + bond conns
    function getAllSendConns() {
      const targets = open.filter(p => tf.acceptedPeers.has(p.pid));
      const conns = [];
      for (const t of targets) {
        if (t.conn && t.conn.open) conns.push(t.conn);
      }
      // Add bond connections
      for (const bc of bondConns) {
        if (bc && bc.open) conns.push(bc);
      }
      return conns;
    }

    // 🚀 HYPERTRANSFER V8: Worker pool + multi-bond + aggressive buffers
    // Feature 5: Desktop uses 16 threads for maximum LAN throughput
    const THREADS = IS_DESKTOP && isLAN ? DESKTOP_SEND_THREADS : (isLAN ? 8 : 3);
    let nextChunk = 0;
    const _cachedKey = await ensureKey();
    acquireWakeLock(); // Keep device awake during transfer

    async function sendWorker() {
      while (nextChunk < total) {
        if (tf.cancelled || !state.transfers.has(tf.id)) break;

        const sendConns = getAllSendConns();
        if (sendConns.length === 0) break;

        const i = nextChunk++;
        
        // 🚀 FEATURE FIXED: Yield explicitly to the Javascript event loop every 4 chunks
        // This ensures the thread is unblocked so SENDING MESSAGES works instantly during a massive transfer
        if (i > 0 && i % 4 === 0) {
          await new Promise(resolve => setTimeout(resolve, 0));
        }
        
        // Strategy 2: Round-robin across bond channels
        const connIdx = i % sendConns.length;
        const primaryConn = sendConns[connIdx];

        // SCTP buffer backpressure on the target connection
        const dc = primaryConn && primaryConn.dataChannel;
        if (dc && dc.bufferedAmount > BUF_HIGH) {
          await new Promise(r => {
            let done = false;
            const resolve = () => {
              if (done) return; done = true;
              dc.removeEventListener('bufferedamountlow', resolve);
              clearInterval(fallback);
              r();
            };
            dc.bufferedAmountLowThreshold = BUF_LOW;
            dc.addEventListener('bufferedamountlow', resolve);
            const fallback = setInterval(() => {
              if (!primaryConn.open || dc.bufferedAmount <= BUF_LOW) resolve();
            }, 10);
          });
        }
        if (tf.cancelled || !state.transfers.has(tf.id)) break;

        try {
          // Strategy 4: Streaming read via Blob.slice (no full file in RAM)
          const start = i * CHUNK;
          const end = Math.min(prep.size, start + CHUNK);
          const chunkBuf = await prep.blob.slice(start, end).arrayBuffer();
          
          // Strategy 1 + 5: Worker pool encryption (or turbo bypass)
          let packetBuf;
          if (workerPool.ready) {
            if (turboMode) {
              packetBuf = await workerPool.encryptChunkTurbo(fid, i, chunkBuf);
            } else {
              packetBuf = await workerPool.encryptChunk(fid, i, chunkBuf);
            }
          } else {
            // Fallback: main-thread crypto
            if (turboMode) {
              // Build raw turbo packet on main thread
              const plain = new Uint8Array(chunkBuf);
              const pkt = new Uint8Array(24 + plain.length);
              pkt[0] = 0x4B; pkt[1] = 0x52; pkt[2] = 0x59; pkt[3] = 0x50;
              new DataView(pkt.buffer).setUint32(4, i, true);
              for (let j = 0; j < 16; j++) pkt[8 + j] = j < fid.length ? fid.charCodeAt(j) : 0x00;
              pkt.set(plain, 24);
              packetBuf = pkt.buffer;
            } else {
              packetBuf = await encChunkPacket(fid, i, new Uint8Array(chunkBuf));
            }
          }
          
          // Send via the round-robin selected bond connection
          if (primaryConn && primaryConn.open) primaryConn.send(packetBuf);
          
          // Also send to other peers (non-bonded, for multi-peer broadcast)
          if (!useBonding) {
            for (const conn of sendConns) {
              if (conn !== primaryConn && conn.open) conn.send(packetBuf);
            }
          }
        } catch (err) {
          console.error("Chunk error:", err);
          if (!tf.cancelled) toast("Chunking failed.", "danger");
          tf.cancelled = true;
          break;
        }

        if (state.transfers.has(tf.id)) tf.sent++;
        if (i % 16 === 0) requestAnimationFrame(renderTransfers);
        // Yield to allow messages — every 32 chunks (less yielding = faster)
        if (i % 32 === 0) await new Promise(r => setTimeout(r, 0));
      }
    }

    // Launch send threads
    await Promise.all(Array.from({ length: THREADS }, () => sendWorker()));
    
    if (tf.cancelled || !state.transfers.has(tf.id)) {
        clearInterval(renderTimer);
        state.transfers.delete(tf.id);
        // Clean up bond connections
        for (const bc of bondConns) try { bc.close(); } catch(e) {}
        renderTransfers();
        return;
    }

    // Drain buffers on ALL connections (main + bonds)
    const allConns = getAllSendConns();
    for (const conn of allConns) {
      if (conn && conn.dataChannel) {
        while (conn.dataChannel.bufferedAmount > 0) {
          if (!conn.open || tf.cancelled || !state.transfers.has(tf.id)) break;
          await new Promise(r => setTimeout(r, 5));
        }
      }
    }

    // Brief wait for final ACK (5s max — don't block)
    const ackDeadline = performance.now() + 5000;
    while (tf.acked < total && !tf.cancelled && state.transfers.has(tf.id) && performance.now() < ackDeadline) {
      const anyAlive = open.some(p => p.conn && p.conn.open && tf.acceptedPeers.has(p.pid));
      if (!anyAlive) break;
      await new Promise(r => setTimeout(r, 50));
    }

    // Clean up bond connections
    for (const bc of bondConns) try { bc.close(); } catch(e) {}

    if (tf.cancelled || !state.transfers.has(tf.id)) {
        clearInterval(renderTimer);
        state.transfers.delete(tf.id);
        renderTransfers();
        return;
    }

    const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
    const speed = fmtBytes(prep.size / Math.max(0.1, (performance.now() - startTime) / 1000));
    const engineLabel = turboMode ? "⚡ Turbo" : (bondConns.length > 0 ? `⚡ ${bondConns.length + 1}x Bond` : "");

    clearInterval(renderTimer);
    state.transfers.delete(tf.id);
    renderTransfers();
    if (!state.transfers.size) {
      releaseWakeLock();
      const bar = document.getElementById("transferBar");
      if (bar) bar.classList.remove("turbo-active");
    }

    const blob = prep.blob instanceof Blob ? prep.blob : new Blob([prep.blob], { type: prep.type });
    const url = regUrl(URL.createObjectURL(blob));
    fileMsg({ dir: "outgoing", name: prep.dl, size: prep.size, mime: prep.type, url, meta: `${engineLabel} Sent to ${tf.acceptedPeers.size} peer(s) in ${elapsed}s (${speed}/s)`.trim(), label: prep.label, dl: prep.dl });
    toast(`${engineLabel} Sent ${prep.label.toLowerCase()} • ${elapsed}s • ${speed}/s`, "success");
    if (document.hidden) showNotification(`✅ ${prep.label} sent`, `${fmtBytes(prep.size)} in ${elapsed}s (${speed}/s)`);
    })(); // end of fire-and-forget async IIFE
  }
}

/* ─── Panic Wipe ────────────────────────────────────────────── */
async function panicWipe(remote = false) {
  if (!remote) {
    const open = getOpen();
    await Promise.allSettled(open.map(p => sendPkt(p.conn, "ctl", { action: "panic-wipe" })));
  }
  clearHistory();
  stopAllMedia(true);
  await destroyPeer();
  state.key = null;
  state.secret = "";
  el.secretInput.value = "";
  el.connectInput.value = "";
  el.msgInput.value = "";
  refresh();
  toast(remote ? "Remote wipe received. Everything cleared." : "Panic wipe complete.", remote ? "danger" : "success");
  setStatus(remote ? "Remote wipe" : "Wiped", remote ? "danger" : "pending");
}

/* ─── Copy ID ───────────────────────────────────────────────── */
async function copyId() {
  if (!state.id) { toast("Go online first.", "danger"); return; }
  try {
    await navigator.clipboard.writeText(state.id);
    toast("ID copied!", "success");
  } catch (e) {
    console.error(e);
    toast("Clipboard access failed.", "danger");
  }
}

/* ─── Autosize ──────────────────────────────────────────────── */
function autosize() {
  el.msgInput.style.height = "auto";
  el.msgInput.style.height = Math.min(Math.max(el.msgInput.scrollHeight, 44), 160) + "px";
}

/* ─── Event Binding ─────────────────────────────────────────── */
function bind() {
  el.themeToggle.addEventListener("click", () => {
    applyTheme(el.body.dataset.theme === "dark" ? "light" : "dark");
  });

  el.toggleSecret.addEventListener("click", () => {
    const hidden = el.secretInput.type === "password";
    el.secretInput.type = hidden ? "text" : "password";
    el.toggleSecret.textContent = hidden ? "Hide" : "Show";
  });

  el.goOnline.addEventListener("click", () => goOnline().catch(e => {
    console.error(e);
    toast("Failed to go online.", "danger");
  }));

  el.goOffline.addEventListener("click", () => goOffline().catch(e => {
    console.error(e);
    toast("Failed to go offline.", "danger");
  }));

  el.copyId.addEventListener("click", () => copyId());

  el.connectBtn.addEventListener("click", () => connectPeers().catch(e => {
    console.error(e);
    toast("Connection failed.", "danger");
  }));

  el.composer.addEventListener("submit", (e) => sendMessage(e).catch(err => {
    console.error(err);
    toast("Message failed.", "danger");
  }));

  el.msgInput.addEventListener("input", autosize);
  el.msgInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      el.composer.requestSubmit();
    }
  });

  el.voiceBtn.addEventListener("click", () => callAll("voice").catch(e => {
    console.error(e);
    toast("Voice call failed.", "danger");
  }));

  el.videoBtn.addEventListener("click", () => callAll("video").catch(e => {
    console.error(e);
    toast("Video call failed.", "danger");
  }));

  el.stopMedia.addEventListener("click", () => stopAllMedia(false));

  // Camera modal logic
  el.cameraBtn.addEventListener("click", () => {
    el.cameraModal.style.display = "flex";
  });
  el.cameraCancelBtn.addEventListener("click", () => {
    el.cameraModal.style.display = "none";
  });
  el.cameraModal.querySelector(".camera-modal-backdrop").addEventListener("click", () => {
    el.cameraModal.style.display = "none";
  });
  el.cameraPhotoBtn.addEventListener("click", () => {
    el.cameraModal.style.display = "none";
    el.cameraPhotoInput.click();
  });
  el.cameraVideoBtn.addEventListener("click", () => {
    el.cameraModal.style.display = "none";
    el.cameraVideoInput.click();
  });
  el.cameraPhotoInput.addEventListener("change", () => {
    const files = [...el.cameraPhotoInput.files];
    if (!files.length) return;
    sendFiles(files).catch(e => {
      console.error(e);
      toast("Camera photo failed.", "danger");
    }).finally(() => { el.cameraPhotoInput.value = ""; });
  });
  el.cameraVideoInput.addEventListener("change", () => {
    const files = [...el.cameraVideoInput.files];
    if (!files.length) return;
    sendFiles(files).catch(e => {
      console.error(e);
      toast("Camera video failed.", "danger");
    }).finally(() => { el.cameraVideoInput.value = ""; });
  });

  el.filesBtn.addEventListener("click", () => el.fileInput.click());
  el.fileInput.addEventListener("change", () => {
    const files = [...el.fileInput.files];
    if (!files.length) return;
    sendFiles(files).catch(e => {
      console.error(e);
      toast("File send failed.", "danger");
    }).finally(() => { el.fileInput.value = ""; });
  });

  el.clearBtn.addEventListener("click", () => {
    clearHistory();
    toast("Chat cleared.", "success");
  });

  el.panicBtn.addEventListener("click", () => panicWipe(false).catch(e => {
    console.error(e);
    toast("Wipe failed.", "danger");
  }));

  // Strategy 5: Turbo LAN Mode toggle
  if (el.turboToggle) {
    el.turboToggle.addEventListener("change", () => {
      state.turbo = el.turboToggle.checked;
      if (el.turboIndicator) {
        el.turboIndicator.style.display = state.turbo ? "" : "none";
      }
      if (state.turbo) {
        toast("⚡ Turbo LAN Mode ON — file transfers use DTLS-only encryption", "success");
      } else {
        toast("🔒 Turbo Mode OFF — full AES-256-GCM encryption restored", "success");
      }
    });
  }

  el.secretInput.addEventListener("input", () => {
    state.key = null;
    state.secret = "";
    workerPool.destroy(); // Strategy 1: destroy workers when secret changes
    for (const p of state.conns.values()) p.verified = false;
    if (getOpen().length) {
      disconnectAll(true, "Password changed. Reconnect peers.").catch(e => console.error(e));
    }
    renderPeers();
    refresh();
  });

  el.peerIdInput.addEventListener("blur", () => {
    el.peerIdInput.value = sanitizeId(el.peerIdInput.value);
  });

  // Allow Enter in connect input
  el.connectInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      el.connectBtn.click();
    }
  });

  window.addEventListener("beforeunload", () => {
    stopAllMedia(true);
    for (const p of state.conns.values()) {
      if (p.conn) try { p.conn.close(); } catch (e) { console.error(e); }
    }
    if (state.peer) try { state.peer.destroy(); } catch (e) { console.error(e); }
  });
}

/* ─── Anti-Inspect & Security ───────────────────────────────── */
document.addEventListener('contextmenu', e => e.preventDefault());
document.addEventListener('keydown', e => {
  if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) || (e.ctrlKey && e.key === 'U')) {
    e.preventDefault();
  }
});
setInterval(() => {
  const start = performance.now();
  debugger;
  if (performance.now() - start > 100) {
    document.body.innerHTML = "Security violation detected.";
  }
}, 1000);

/* ─── Boot ──────────────────────────────────────────────────── */
function boot() {
  // Desktop app initialization
  if (IS_DESKTOP) {
    document.body.classList.add('is-desktop');
    const db = document.getElementById('desktopTitlebar');
    if (db) db.style.display = 'flex';

    // Feature 1: Initialize LAN Discovery listener
    initLanDiscovery();

    // Feature 5: Log desktop mode
    console.log('[KRYPTIX] Desktop Mode — Speed optimizations active');
    console.log(`[KRYPTIX] Chunk: ${DESKTOP_CHUNK / 1024}KB | Buffers: ${DESKTOP_BUFFER_HIGH / (1024*1024)}MB/${DESKTOP_BUFFER_LOW / (1024*1024)}MB | Threads: ${DESKTOP_SEND_THREADS}`);
  }

  // Feature 4: Initialize global drag-and-drop for ALL platforms (Web & Desktop)
  initDragDrop();

  applyTheme(initTheme(), false);
  renderTimeline();
  renderPeers();
  renderMedia();
  renderNearbyDevices();
  refresh();
  bind();
  autosize();

  // Hide cinematic boot screen after intro
  setTimeout(() => {
    const loader = document.getElementById("bootScreen");
    if (loader) loader.classList.add("hidden");
  }, 2200);
}

boot();
