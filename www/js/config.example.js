window.KRYPTIX_CONFIG = Object.freeze({
  peerDebug: 0,
  peerServer: null,

  rtcConfig: {
    iceTransportPolicy: "all"
  },

  iceServers: [
    // 1. Free Public STUN Servers (Reliable for most direct P2P connections)
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
    
    // 2. OpenRelay TURN Server (Free, public TURN server provided by Metered.ca for testing/development)
    // IMPORTANT: Public TURN servers are often slow and should not be used for heavy production traffic!
    {
      urls: "turn:openrelay.metered.ca:80",
      username: "openrelayproject",
      credential: "openrelayproject"
    },
    {
      urls: "turn:openrelay.metered.ca:443",
      username: "openrelayproject",
      credential: "openrelayproject"
    },
    {
      urls: "turn:openrelay.metered.ca:443?transport=tcp",
      username: "openrelayproject",
      credential: "openrelayproject"
    },

    // 3. YOUR CUSTOM SERVERS
    // Replace the details below with your own paid/private TURN servers for production reliability.
    /*
    {
      urls: "turn:YOUR_CUSTOM_SERVER:3478",
      username: "YOUR_USERNAME",
      credential: "YOUR_PASSWORD"
    }
    */
  ]
});
