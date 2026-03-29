package com.kryptix.kryptix;

import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import fi.iki.elonen.NanoHTTPD;

/**
 * HyperDriveServer — Ultra-fast encrypted local HTTP file server.
 * Serves files over the local WiFi network with AES-256-GCM encryption.
 * Supports HTTP Range requests for multi-threaded parallel downloading.
 */
public class HyperDriveServer extends NanoHTTPD {

    private static final String TAG = "HyperDrive";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;
    // Serve in 2MB encrypted blocks for maximum throughput
    private static final int SERVE_BLOCK = 2 * 1024 * 1024;

    private final Map<String, File> activeFiles = new HashMap<>();
    private byte[] aesKeyBytes;

    public HyperDriveServer(int port) {
        super(port);
    }

    public void setKey(byte[] key) {
        this.aesKeyBytes = key;
    }

    public void registerFile(String fid, File file) {
        activeFiles.put(fid, file);
        Log.i(TAG, "Registered file: " + fid + " -> " + file.getAbsolutePath() + " (" + file.length() + " bytes)");
    }

    public void unregisterFile(String fid) {
        activeFiles.remove(fid);
    }

    public void clearAll() {
        activeFiles.clear();
    }

    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri(); // e.g. /file/<fid>
        String method = session.getMethod().name();

        // Health check
        if (uri.equals("/ping")) {
            return newFixedLengthResponse(Response.Status.OK, "text/plain", "KRYPTIX-HYPER-DRIVE");
        }

        // File info endpoint: GET /info/<fid>
        if (uri.startsWith("/info/")) {
            String fid = uri.substring(6);
            File f = activeFiles.get(fid);
            if (f == null || !f.exists()) {
                return newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "File not found");
            }
            String json = "{\"size\":" + f.length() + ",\"fid\":\"" + fid + "\"}";
            return newFixedLengthResponse(Response.Status.OK, "application/json", json);
        }

        // File download endpoint: GET /file/<fid>
        // Supports Range: bytes=start-end header for parallel downloading
        if (uri.startsWith("/file/")) {
            String fid = uri.substring(6);
            File f = activeFiles.get(fid);
            if (f == null || !f.exists()) {
                return newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "File not found");
            }

            long fileSize = f.length();
            long rangeStart = 0;
            long rangeEnd = fileSize - 1;

            // Parse Range header
            String rangeHeader = session.getHeaders().get("range");
            if (rangeHeader != null && rangeHeader.startsWith("bytes=")) {
                String rangeSpec = rangeHeader.substring(6);
                String[] parts = rangeSpec.split("-");
                try {
                    rangeStart = Long.parseLong(parts[0]);
                    if (parts.length > 1 && !parts[1].isEmpty()) {
                        rangeEnd = Long.parseLong(parts[1]);
                    }
                } catch (NumberFormatException e) {
                    return newFixedLengthResponse(Response.Status.BAD_REQUEST, "text/plain", "Bad range");
                }
            }

            if (rangeStart < 0 || rangeEnd >= fileSize || rangeStart > rangeEnd) {
                return newFixedLengthResponse(Response.Status.RANGE_NOT_SATISFIABLE, "text/plain", "Invalid range");
            }

            try {
                long contentLength = rangeEnd - rangeStart + 1;
                byte[] plainBytes = readFileRange(f, rangeStart, contentLength);

                // Encrypt with AES-256-GCM
                byte[] encrypted = encryptAesGcm(plainBytes);

                Response resp;
                if (rangeHeader != null) {
                    resp = newFixedLengthResponse(Response.Status.PARTIAL_CONTENT,
                            "application/octet-stream", new java.io.ByteArrayInputStream(encrypted), encrypted.length);
                    resp.addHeader("Content-Range", "bytes " + rangeStart + "-" + rangeEnd + "/" + fileSize);
                } else {
                    resp = newFixedLengthResponse(Response.Status.OK,
                            "application/octet-stream", new java.io.ByteArrayInputStream(encrypted), encrypted.length);
                }

                resp.addHeader("Accept-Ranges", "bytes");
                resp.addHeader("Content-Length", String.valueOf(encrypted.length));
                resp.addHeader("X-Kryptix-Plain-Length", String.valueOf(contentLength));
                resp.addHeader("Access-Control-Allow-Origin", "*");
                return resp;

            } catch (Exception e) {
                Log.e(TAG, "Serve error", e);
                return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, "text/plain", "Encryption error");
            }
        }

        // CORS preflight
        if (method.equals("OPTIONS")) {
            Response resp = newFixedLengthResponse(Response.Status.OK, "text/plain", "");
            resp.addHeader("Access-Control-Allow-Origin", "*");
            resp.addHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
            resp.addHeader("Access-Control-Allow-Headers", "Range");
            return resp;
        }

        return newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "Not found");
    }

    private byte[] readFileRange(File f, long offset, long length) throws IOException {
        byte[] buf = new byte[(int) length];
        try (FileInputStream fis = new FileInputStream(f)) {
            fis.skip(offset);
            int read = 0;
            while (read < length) {
                int n = fis.read(buf, read, (int) (length - read));
                if (n == -1) break;
                read += n;
            }
        }
        return buf;
    }

    private byte[] encryptAesGcm(byte[] plain) throws Exception {
        SecretKey key = new SecretKeySpec(aesKeyBytes, "AES");
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = cipher.doFinal(plain);

        // Output: [12-byte IV][ciphertext+tag]
        byte[] out = new byte[IV_BYTES + ct.length];
        System.arraycopy(iv, 0, out, 0, IV_BYTES);
        System.arraycopy(ct, 0, out, IV_BYTES, ct.length);
        return out;
    }
}
