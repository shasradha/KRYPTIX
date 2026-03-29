package com.kryptix.kryptix;

import android.content.Context;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Environment;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.List;

/**
 * HyperDrivePlugin — Capacitor bridge for the native file transfer engine.
 * Exposes startServer(), stopServer(), download(), getLocalIp() to JavaScript.
 */
@CapacitorPlugin(name = "HyperDrive")
public class HyperDrivePlugin extends Plugin {

    private static final String TAG = "HyperDrive";
    private static final int SERVER_PORT = 4444;
    private static final int DOWNLOAD_THREADS = 4;

    private HyperDriveServer server;
    private HyperDriveDownloader activeDownloader;

    /**
     * Start the local HTTP server to serve a file.
     * JS call: HyperDrive.startServer({ fid, filePath, secret })
     * Returns: { ip, port }
     */
    @PluginMethod
    public void startServer(PluginCall call) {
        String fid = call.getString("fid");
        String filePath = call.getString("filePath");
        String secret = call.getString("secret");

        if (fid == null || filePath == null || secret == null) {
            call.reject("Missing fid, filePath, or secret");
            return;
        }

        try {
            byte[] aesKey = deriveRawKey(secret);
            File file = new File(filePath);
            if (!file.exists()) {
                call.reject("File not found: " + filePath);
                return;
            }

            // Stop any existing server
            stopServerInternal();

            server = new HyperDriveServer(SERVER_PORT);
            server.setKey(aesKey);
            server.registerFile(fid, file);
            server.start();

            String ip = getLocalIpAddress();
            Log.i(TAG, "Server started on " + ip + ":" + SERVER_PORT);

            JSObject ret = new JSObject();
            ret.put("ip", ip);
            ret.put("port", SERVER_PORT);
            ret.put("fid", fid);
            ret.put("fileSize", file.length());
            call.resolve(ret);

        } catch (Exception e) {
            Log.e(TAG, "startServer failed", e);
            call.reject("Server start failed: " + e.getMessage());
        }
    }

    /**
     * Stop the local HTTP server.
     * JS call: HyperDrive.stopServer()
     */
    @PluginMethod
    public void stopServer(PluginCall call) {
        stopServerInternal();
        call.resolve();
    }

    /**
     * Download a file from a remote Hyper-Drive server using parallel threads.
     * JS call: HyperDrive.download({ url, fid, secret, fileName, fileSize })
     * Fires events: "hyper-progress" and resolves on completion.
     */
    @PluginMethod
    public void download(PluginCall call) {
        String baseUrl = call.getString("url");
        String fid = call.getString("fid");
        String secret = call.getString("secret");
        String fileName = call.getString("fileName", "kryptix-download");
        long fileSize = call.getInt("fileSize", 0);

        if (baseUrl == null || fid == null || secret == null || fileSize <= 0) {
            call.reject("Missing url, fid, secret, or fileSize");
            return;
        }

        try {
            byte[] aesKey = deriveRawKey(secret);

            // Save to Downloads folder
            File dlDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            File saveFile = new File(dlDir, fileName);

            // Cancel any active download
            if (activeDownloader != null) {
                activeDownloader.cancel();
            }

            activeDownloader = new HyperDriveDownloader(DOWNLOAD_THREADS, aesKey);
            activeDownloader.download(baseUrl, fid, saveFile.getAbsolutePath(), fileSize,
                new HyperDriveDownloader.ProgressCallback() {
                    @Override
                    public void onProgress(long bytesWritten, long totalBytes) {
                        JSObject data = new JSObject();
                        data.put("bytesWritten", bytesWritten);
                        data.put("totalBytes", totalBytes);
                        data.put("fid", fid);
                        notifyListeners("hyper-progress", data);
                    }

                    @Override
                    public void onComplete(String savedPath) {
                        JSObject ret = new JSObject();
                        ret.put("savedPath", savedPath);
                        ret.put("fid", fid);
                        ret.put("fileSize", fileSize);
                        call.resolve(ret);
                        activeDownloader = null;
                    }

                    @Override
                    public void onError(String error) {
                        call.reject(error);
                        activeDownloader = null;
                    }
                });

        } catch (Exception e) {
            Log.e(TAG, "download failed", e);
            call.reject("Download failed: " + e.getMessage());
        }
    }

    /**
     * Cancel an active download.
     * JS call: HyperDrive.cancelDownload()
     */
    @PluginMethod
    public void cancelDownload(PluginCall call) {
        if (activeDownloader != null) {
            activeDownloader.cancel();
            activeDownloader = null;
        }
        call.resolve();
    }

    /**
     * Get the local WiFi IP address.
     * JS call: HyperDrive.getLocalIp()
     */
    @PluginMethod
    public void getLocalIp(PluginCall call) {
        try {
            String ip = getLocalIpAddress();
            JSObject ret = new JSObject();
            ret.put("ip", ip);
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Could not determine local IP");
        }
    }

    // ─── Internal Helpers ──────────────────────────────────────

    private void stopServerInternal() {
        if (server != null) {
            server.clearAll();
            server.stop();
            server = null;
            Log.i(TAG, "Server stopped");
        }
    }

    /**
     * Derive a raw 256-bit AES key from the shared secret using SHA-256.
     * This matches what we'll do on the JS side for cross-compatibility.
     */
    private byte[] deriveRawKey(String secret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Get the device's local WiFi IP address (192.168.x.x).
     */
    private String getLocalIpAddress() throws Exception {
        // Try NetworkInterface first (most reliable)
        List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
        for (NetworkInterface ni : interfaces) {
            if (ni.isLoopback() || !ni.isUp()) continue;
            // Prefer wlan interfaces
            String name = ni.getName().toLowerCase();
            if (name.contains("wlan") || name.contains("eth") || name.contains("ap")) {
                List<InetAddress> addrs = Collections.list(ni.getInetAddresses());
                for (InetAddress addr : addrs) {
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        return addr.getHostAddress();
                    }
                }
            }
        }
        // Fallback: any non-loopback IPv4
        for (NetworkInterface ni : interfaces) {
            List<InetAddress> addrs = Collections.list(ni.getInetAddresses());
            for (InetAddress addr : addrs) {
                if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                    return addr.getHostAddress();
                }
            }
        }
        throw new Exception("No local IP found");
    }

    @Override
    protected void handleOnDestroy() {
        stopServerInternal();
        if (activeDownloader != null) activeDownloader.cancel();
        super.handleOnDestroy();
    }
}
