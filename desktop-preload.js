/* ================================================================
   KRYPTIX Desktop — Preload Script
   Exposes secure IPC bridges to the renderer
   ================================================================ */

'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // ─── Window Controls ───────────────────────────────────────
  isDesktop: true,
  minimize: () => ipcRenderer.send('window-minimize'),
  close: () => ipcRenderer.send('window-close'),
  showNativeNotification: (title, body) => ipcRenderer.send('show-notification', title, body),

  // ─── Feature 1: LAN Discovery ─────────────────────────────
  startDiscovery: (peerId, secretHash) => {
    ipcRenderer.send('start-discovery', { peerId, secretHash });
  },
  stopDiscovery: () => {
    ipcRenderer.send('stop-discovery');
  },
  onLanPeers: (callback) => {
    ipcRenderer.on('lan-peers-updated', (_e, peers) => callback(peers));
  },
  getLanPeers: () => ipcRenderer.invoke('get-lan-peers'),

  // ─── Feature 3: Auto-Start ────────────────────────────────
  getAutoStart: () => ipcRenderer.invoke('get-auto-start'),
  setAutoStart: (enabled) => ipcRenderer.invoke('set-auto-start', enabled),

  // ─── Feature 5: Network Info ──────────────────────────────
  getLocalIPs: () => ipcRenderer.invoke('get-local-ips')
});
