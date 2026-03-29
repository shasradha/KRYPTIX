/* ================================================================
   KRYPTIX Desktop — Electron Main Process
   Features: System Tray, LAN Discovery, Auto-Start, Speed Flags
   ================================================================ */

'use strict';

const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, Notification } = require('electron');
const path = require('path');
const dgram = require('dgram');
const os = require('os');

/* ─── Speed Flags (Feature 5) ───────────────────────────────── */
// Disable Chromium background throttling for sustained transfer speeds
app.commandLine.appendSwitch('disable-renderer-backgrounding');
app.commandLine.appendSwitch('disable-background-timer-throttling');
app.commandLine.appendSwitch('disable-backgrounding-occluded-windows');
// Force hardware acceleration for WebRTC
app.commandLine.appendSwitch('enable-features', 'WebRTCPipeWireCapturer');
// Allow larger SCTP buffers
app.commandLine.appendSwitch('force-fieldtrials', 'WebRTC-DataChannel/Enabled/');

/* ─── Constants ─────────────────────────────────────────────── */
const ICON_PATH = path.join(__dirname, 'www', 'logo.png');
const MULTICAST_ADDR = '239.77.77.77';
const MULTICAST_PORT = 41777;
const BROADCAST_INTERVAL = 3000;   // Broadcast every 3s
const PEER_STALE_MS = 10000;       // Remove peers after 10s silence

/* ─── State ─────────────────────────────────────────────────── */
let mainWindow = null;
let tray = null;
let isQuitting = false;

// LAN Discovery state
let discoverySocket = null;
let broadcastTimer = null;
let discoveryInfo = { peerId: '', secretHash: '' };
const lanPeers = new Map(); // peerId → { peerId, ip, secretHash, lastSeen }

/* ─── Helpers ───────────────────────────────────────────────── */
function getLocalIPs() {
  const nets = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) {
        ips.push(net.address);
      }
    }
  }
  return ips;
}

function getTrayIcon() {
  try {
    const img = nativeImage.createFromPath(ICON_PATH);
    return img.resize({ width: 16, height: 16 });
  } catch (e) {
    return null;
  }
}

/* ─── Create Window ─────────────────────────────────────────── */
function createWindow() {
  const startHidden = process.argv.includes('--hidden');

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 400,
    minHeight: 600,
    show: !startHidden,
    titleBarStyle: 'hidden',
    titleBarOverlay: {
      color: '#00000000',
      symbolColor: '#8fa8b0',
      height: 32
    },
    icon: ICON_PATH,
    backgroundColor: '#0a1118',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      backgroundThrottling: false,  // Feature 5: Never throttle in background
      preload: path.join(__dirname, 'desktop-preload.js')
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'www', 'index.html'));

  // Bug Fix: Handle Blob URLs so users can save small files / images
  mainWindow.webContents.session.on('will-download', (event, item, webContents) => {
    // Automatically prompts a Save dialog pointing to their standard Downloads folder
    item.setSaveDialogOptions({ defaultPath: item.getFilename() });
  });

  // Feature 2: Close → minimize to tray (don't quit)
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.hide();
      if (tray) {
        tray.displayBalloon({
          iconType: 'info',
          title: 'Kryptix',
          content: 'Running in background. Click the tray icon to restore.'
        });
      }
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Restore from tray on focus
  mainWindow.on('show', () => {
    mainWindow.focus();
  });
}

/* ─── System Tray (Feature 2) ───────────────────────────────── */
function createTray() {
  const icon = getTrayIcon();
  if (!icon) return;

  tray = new Tray(icon);
  tray.setToolTip('Kryptix — Secure Mesh Messenger');

  function buildTrayMenu() {
    const autoStart = app.getLoginItemSettings().openAtLogin;
    const menu = Menu.buildFromTemplate([
      {
        label: 'Show Kryptix',
        click: () => {
          if (mainWindow) {
            mainWindow.show();
            mainWindow.focus();
          }
        }
      },
      { type: 'separator' },
      {
        label: 'Start on Boot',
        type: 'checkbox',
        checked: autoStart,
        click: (item) => {
          app.setLoginItemSettings({
            openAtLogin: item.checked,
            args: item.checked ? ['--hidden'] : []
          });
          buildTrayMenu(); // Rebuild to reflect new state
        }
      },
      { type: 'separator' },
      {
        label: 'Quit Kryptix',
        click: () => {
          isQuitting = true;
          stopDiscovery();
          app.quit();
        }
      }
    ]);
    tray.setContextMenu(menu);
  }

  buildTrayMenu();

  // Click tray icon → show/hide window
  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        mainWindow.hide();
      } else {
        mainWindow.show();
        mainWindow.focus();
      }
    }
  });
}

/* ─── LAN Discovery (Feature 1) ─────────────────────────────── */
function startDiscovery(peerId, secretHash) {
  stopDiscovery();

  discoveryInfo = { peerId, secretHash };
  lanPeers.clear();

  try {
    discoverySocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    discoverySocket.on('error', (err) => {
      console.error('Discovery socket error:', err.message);
      stopDiscovery();
    });

    discoverySocket.on('message', (msg, rinfo) => {
      try {
        const data = JSON.parse(msg.toString());
        if (data.app !== 'KRYPTIX' || !data.peerId) return;
        if (data.peerId === discoveryInfo.peerId) return; // Ignore self

        const existing = lanPeers.get(data.peerId);
        const peer = {
          peerId: data.peerId,
          ip: rinfo.address,
          secretHash: data.secretHash || '',
          lastSeen: Date.now()
        };
        lanPeers.set(data.peerId, peer);

        // Notify renderer of updated peer list
        sendLanPeersToRenderer();
      } catch (e) {
        // Ignore malformed packets
      }
    });

    discoverySocket.bind(MULTICAST_PORT, '0.0.0.0', () => {
      try {
        discoverySocket.addMembership(MULTICAST_ADDR);
        discoverySocket.setMulticastTTL(2);
        discoverySocket.setBroadcast(true);
        discoverySocket.setMulticastLoopback(true); // Must be true to test multiple instances on the SAME computer
      } catch (e) {
        console.warn('Multicast setup error:', e.message);
      }

      // Start broadcasting
      broadcastTimer = setInterval(() => {
        broadcastPresence();
        cleanStalePeers();
      }, BROADCAST_INTERVAL);

      // Broadcast immediately
      broadcastPresence();
    });
  } catch (e) {
    console.error('Failed to start discovery:', e);
  }
}

function broadcastPresence() {
  if (!discoverySocket || !discoveryInfo.peerId) return;

  const packet = JSON.stringify({
    app: 'KRYPTIX',
    peerId: discoveryInfo.peerId,
    secretHash: discoveryInfo.secretHash,
    ts: Date.now()
  });

  const buf = Buffer.from(packet);
  try {
    discoverySocket.send(buf, 0, buf.length, MULTICAST_PORT, MULTICAST_ADDR);
  } catch (e) {
    // Socket may have closed
  }
}

function cleanStalePeers() {
  const now = Date.now();
  let changed = false;
  for (const [id, peer] of lanPeers) {
    if (now - peer.lastSeen > PEER_STALE_MS) {
      lanPeers.delete(id);
      changed = true;
    }
  }
  if (changed) sendLanPeersToRenderer();
}

function sendLanPeersToRenderer() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const peers = [...lanPeers.values()].map(p => ({
    peerId: p.peerId,
    ip: p.ip,
    sameSecret: p.secretHash === discoveryInfo.secretHash && p.secretHash !== ''
  }));
  mainWindow.webContents.send('lan-peers-updated', peers);
}

function stopDiscovery() {
  if (broadcastTimer) {
    clearInterval(broadcastTimer);
    broadcastTimer = null;
  }
  if (discoverySocket) {
    try {
      discoverySocket.dropMembership(MULTICAST_ADDR);
    } catch (e) {}
    try {
      discoverySocket.close();
    } catch (e) {}
    discoverySocket = null;
  }
  lanPeers.clear();
  discoveryInfo = { peerId: '', secretHash: '' };
}

/* ─── IPC Handlers ──────────────────────────────────────────── */
function setupIPC() {
  // Window controls
  ipcMain.on('window-minimize', () => {
    if (mainWindow) mainWindow.minimize();
  });
  
  // Feature: Native Desktop Notifications
  ipcMain.on('show-notification', (event, title, body) => {
    if (Notification.isSupported()) {
      new Notification({ title, body, icon: ICON_PATH }).show();
    }
  });
  ipcMain.on('window-close', () => {
    if (mainWindow) mainWindow.close();
  });

  // Feature 1: LAN Discovery
  ipcMain.on('start-discovery', (_e, { peerId, secretHash }) => {
    startDiscovery(peerId, secretHash);
  });
  ipcMain.on('stop-discovery', () => {
    stopDiscovery();
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('lan-peers-updated', []);
    }
  });
  ipcMain.handle('get-lan-peers', () => {
    return [...lanPeers.values()].map(p => ({
      peerId: p.peerId,
      ip: p.ip,
      sameSecret: p.secretHash === discoveryInfo.secretHash && p.secretHash !== ''
    }));
  });

  // Feature 3: Auto-Start
  ipcMain.handle('get-auto-start', () => {
    return app.getLoginItemSettings().openAtLogin;
  });
  ipcMain.handle('set-auto-start', (_e, enabled) => {
    app.setLoginItemSettings({
      openAtLogin: enabled,
      args: enabled ? ['--hidden'] : []
    });
    return app.getLoginItemSettings().openAtLogin;
  });

  // Feature 5: Get local IPs for network info
  ipcMain.handle('get-local-ips', () => getLocalIPs());
}

/* ─── App Lifecycle ─────────────────────────────────────────── */
app.whenReady().then(() => {
  setupIPC();
  createWindow();
  createTray();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  // On Windows, don't quit when window closes (tray keeps running)
  if (process.platform === 'darwin') {
    // macOS: standard behavior
  }
  // Windows/Linux: keep running in tray
});

app.on('before-quit', () => {
  isQuitting = true;
  stopDiscovery();
});
