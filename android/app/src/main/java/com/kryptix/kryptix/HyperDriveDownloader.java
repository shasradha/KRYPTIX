package com.kryptix.kryptix;

import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * HyperDriveDownloader — Multi-threaded parallel file downloader.
 * Opens N parallel HTTP connections, each downloading a byte range,
 * decrypts AES-256-GCM, and writes directly to disk.
 * Achieves 100+ MB/s on WiFi 5/6 by saturating the router bandwidth.
 */
public class HyperDriveDownloader {

    private static final String TAG = "HyperDrive";
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int CONNECT_TIMEOUT = 5000;
    private static final int READ_TIMEOUT = 30000;

    // 2MB download block per request — matches server SERVE_BLOCK
    private static final int BLOCK_SIZE = 2 * 1024 * 1024;

    private final int threadCount;
    private final byte[] aesKeyBytes;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final AtomicLong totalBytesWritten = new AtomicLong(0);
    private ExecutorService executor;

    public interface ProgressCallback {
        void onProgress(long bytesWritten, long totalBytes);
        void onComplete(String savedPath);
        void onError(String error);
    }

    public HyperDriveDownloader(int threadCount, byte[] aesKey) {
        this.threadCount = threadCount;
        this.aesKeyBytes = aesKey;
    }

    public void cancel() {
        cancelled.set(true);
        if (executor != null) executor.shutdownNow();
    }

    /**
     * Download a file from the Hyper-Drive server using parallel threads.
     * @param baseUrl  e.g. "http://192.168.1.5:4444"
     * @param fid      File ID registered on the server
     * @param savePath Absolute path to save the file
     * @param callback Progress and completion callbacks
     */
    public void download(String baseUrl, String fid, String savePath, long fileSize, ProgressCallback callback) {
        executor = Executors.newFixedThreadPool(threadCount);
        cancelled.set(false);
        totalBytesWritten.set(0);

        Handler mainHandler = new Handler(Looper.getMainLooper());

        executor.submit(() -> {
            try {
                File outFile = new File(savePath);
                outFile.getParentFile().mkdirs();

                // Calculate blocks
                int totalBlocks = (int) Math.ceil((double) fileSize / BLOCK_SIZE);
                
                // Pre-allocate file
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    // Just create/truncate
                }

                // Divide blocks among threads
                CountDownLatch latch = new CountDownLatch(totalBlocks);
                AtomicBoolean hasError = new AtomicBoolean(false);

                for (int blockIdx = 0; blockIdx < totalBlocks; blockIdx++) {
                    final int bi = blockIdx;
                    final long blockStart = (long) bi * BLOCK_SIZE;
                    final long blockEnd = Math.min(fileSize - 1, blockStart + BLOCK_SIZE - 1);
                    final long blockLen = blockEnd - blockStart + 1;

                    executor.submit(() -> {
                        if (cancelled.get() || hasError.get()) {
                            latch.countDown();
                            return;
                        }

                        try {
                            String url = baseUrl + "/file/" + fid;
                            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                            conn.setRequestMethod("GET");
                            conn.setRequestProperty("Range", "bytes=" + blockStart + "-" + blockEnd);
                            conn.setConnectTimeout(CONNECT_TIMEOUT);
                            conn.setReadTimeout(READ_TIMEOUT);
                            conn.connect();

                            int code = conn.getResponseCode();
                            if (code != 206 && code != 200) {
                                throw new Exception("HTTP " + code);
                            }

                            // Read entire encrypted response
                            InputStream is = conn.getInputStream();
                            byte[] encrypted = readAll(is, conn.getContentLength());
                            is.close();
                            conn.disconnect();

                            // Decrypt AES-256-GCM
                            byte[] plain = decryptAesGcm(encrypted);

                            // Write to exact position in file (thread-safe via RandomAccessFile)
                            synchronized (outFile) {
                                java.io.RandomAccessFile raf = new java.io.RandomAccessFile(outFile, "rw");
                                raf.seek(blockStart);
                                raf.write(plain);
                                raf.close();
                            }

                            long written = totalBytesWritten.addAndGet(plain.length);

                            // Report progress every block
                            final long w = written;
                            mainHandler.post(() -> callback.onProgress(w, fileSize));

                        } catch (Exception e) {
                            if (!cancelled.get()) {
                                Log.e(TAG, "Block " + bi + " failed", e);
                                hasError.set(true);
                                mainHandler.post(() -> callback.onError("Download failed: " + e.getMessage()));
                            }
                        } finally {
                            latch.countDown();
                        }
                    });
                }

                // Wait for all blocks
                latch.await();

                if (!cancelled.get() && !hasError.get()) {
                    mainHandler.post(() -> callback.onComplete(savePath));
                }

            } catch (Exception e) {
                Log.e(TAG, "Download orchestration failed", e);
                mainHandler.post(() -> callback.onError("Download setup failed: " + e.getMessage()));
            } finally {
                executor.shutdown();
            }
        });
    }

    private byte[] readAll(InputStream is, int expectedLen) throws Exception {
        byte[] buf;
        if (expectedLen > 0) {
            buf = new byte[expectedLen];
            int offset = 0;
            while (offset < expectedLen) {
                int n = is.read(buf, offset, expectedLen - offset);
                if (n == -1) break;
                offset += n;
            }
        } else {
            // Fallback: read dynamically
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] tmp = new byte[65536];
            int n;
            while ((n = is.read(tmp)) != -1) bos.write(tmp, 0, n);
            buf = bos.toByteArray();
        }
        return buf;
    }

    private byte[] decryptAesGcm(byte[] data) throws Exception {
        if (data.length < IV_BYTES + 1) throw new Exception("Encrypted data too short");

        byte[] iv = new byte[IV_BYTES];
        System.arraycopy(data, 0, iv, 0, IV_BYTES);

        byte[] ct = new byte[data.length - IV_BYTES];
        System.arraycopy(data, IV_BYTES, ct, 0, ct.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKeyBytes, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(ct);
    }
}
