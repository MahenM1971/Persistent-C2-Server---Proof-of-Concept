// ======================
// Server Implementation
// ======================
const express = require('express');
const app = express();
const http = require('http');
const https = require('https');
const fs = require('fs');
const ping = require('ping');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const dns = require('dns');
const { exec, spawn } = require('child_process');
const axios = require('axios');
const net = require('net');
const dgram = require('dgram');

// ======================
// Configuration
// ======================
const CONFIG = {
  PORTS: {
    HTTP: 5000,
    HTTPS: 5001,
    DNS_UDP: 5353,
    DNS_TCP: 5354,
    ICMP: 0,
    TCP_TUNNEL: 8080,
    UDP_TUNNEL: 9090 // Added UDP tunnel port
  },
  CHECK_INTERVALS: {
    AGENT_STATUS: 15000,
    PROTOCOL_STATUS: 30000
  },
  SECURITY: {
    SESSION_KEY: crypto.randomBytes(32).toString('hex'),
    ENCRYPTION_ALGO: 'aes-256-cbc',
    SELF_SIGNED_CERT: {
      KEY: 'key.pem',
      CERT: 'cert.pem'
    }
  },
  DNS: {
    DOMAIN: 'example.com',
    SUBDOMAIN: 'tunnel'
  }
};

// ======================
// Protocol Status
// ======================
let protocolStatus = {
  dns_udp: 'inactive',
  dns_tcp: 'inactive',
  dns_https: 'inactive',
  icmp: 'inactive',
  http: 'inactive',
  https: 'inactive',
  tcp: 'inactive',
  udp: 'inactive', // Added UDP status
  vpn: 'inactive'
};

// ======================
// UDP Tunnel Implementation
// ======================
class UDPTunnel {
  constructor() {
    this.server = dgram.createSocket('udp4');
    this.activeConnections = new Map(); // Track clients by their address:port
    this.connectionTimeout = 30000; // 30 seconds timeout
    this.heartbeatInterval = 10000; // 10 seconds between heartbeats
    this.lastActivity = Date.now();
  }

  start() {
    this.server.on('message', (msg, rinfo) => {
      try {
        this.lastActivity = Date.now();
        const clientKey = `${rinfo.address}:${rinfo.port}`;
        
        // Initialize client if new
        if (!this.activeConnections.has(clientKey)) {
          console.log(`[UDP] New connection from ${clientKey}`);
          this.activeConnections.set(clientKey, {
            lastSeen: Date.now(),
            address: rinfo.address,
            port: rinfo.port
          });
          protocolStatus.udp = 'active';
        } else {
          // Update last seen for existing client
          this.activeConnections.get(clientKey).lastSeen = Date.now();
        }

        // Process message
        const message = msg.toString();
        console.log(`[UDP] Received from ${clientKey}: ${message}`);

        // Handle heartbeat
        if (message === 'HEARTBEAT') {
          this.sendResponse(rinfo, 'ACK');
          return;
        }

        // Process command
        const response = this.processCommand(message);
        this.sendResponse(rinfo, response);
      } catch (err) {
        console.error('[UDP] Error:', err);
      }
    });

    this.server.on('error', (err) => {
      console.error('[UDP] Server error:', err);
      protocolStatus.udp = 'error';
    });

    this.server.on('listening', () => {
      const address = this.server.address();
      console.log(`[UDP] Server listening on ${address.address}:${address.port}`);
      protocolStatus.udp = 'active';
    });

    // Start server
    this.server.bind(CONFIG.PORTS.UDP_TUNNEL, () => {
      console.log(`[UDP] Server bound to port ${CONFIG.PORTS.UDP_TUNNEL}`);
    });

    // Start cleanup interval
    setInterval(() => this.cleanupConnections(), this.connectionTimeout / 2);

    // Start heartbeat interval
    setInterval(() => this.checkActivity(), this.heartbeatInterval);
  }

  sendResponse(rinfo, message) {
    if (this.server && this.server.listening) {
      this.server.send(message, rinfo.port, rinfo.address, (err) => {
        if (err) {
          console.error(`[UDP] Error sending response to ${rinfo.address}:${rinfo.port}:`, err);
        }
      });
    } else {
      console.warn('[UDP] Socket not running, unable to send response');
    }
  }

  processCommand(command) {
    // Simple command processing - extend as needed
    switch (command.toLowerCase()) {
      case 'ping':
        return 'PONG';
      case 'status':
        return JSON.stringify(protocolStatus);
      case 'time':
        return new Date().toISOString();
      default:
        return `ECHO: ${command}`;
    }
  }

  cleanupConnections() {
    const now = Date.now();
    const timeout = this.connectionTimeout;
    
    for (const [key, client] of this.activeConnections.entries()) {
      if (now - client.lastSeen > timeout) {
        console.log(`[UDP] Removing inactive client: ${key}`);
        this.activeConnections.delete(key);
      }
    }

    // Update status if no active connections
    if (this.activeConnections.size === 0 && 
        (now - this.lastActivity) > timeout) {
      protocolStatus.udp = 'inactive';
    }
  }

  checkActivity() {
    // Send heartbeat to all active connections
    for (const client of this.activeConnections.values()) {
      if (this.server && this.server.listening) {
        this.server.send('HEARTBEAT', client.port, client.address, (err) => {
          if (err) {
            console.error(`[UDP] Heartbeat failed for ${client.address}:${client.port}:`, err);
          }
        });
      } else {
        console.warn('[UDP] Socket not running, unable to send heartbeat');
      }
    }
  }
}

// ======================
// DNS Tunnel Implementation (All three methods)
// ======================
class DNSTunnel {
  constructor() {
    this.udpServer = dgram.createSocket('udp4');
    this.tcpServer = net.createServer();
    this.httpsAgent = new https.Agent({ rejectUnauthorized: false });
  }

  start() {
    this.startUDP();
    this.startTCP();
    this.startDNSOverHTTPS();
  }

  // Method 1: Traditional DNS over UDP
  startUDP() {
    this.udpServer.on('message', (msg, rinfo) => {
      try {
        const domain = msg.toString().split(' ')[0];
        if (domain.includes(CONFIG.DNS.SUBDOMAIN)) {
          const payload = domain.split('.')[0];
          const decoded = Buffer.from(payload, 'base64').toString('utf-8');
          console.log(`[DNS-UDP] Received: ${decoded} from ${rinfo.address}`);
          
          // Send response (encoded in TXT record)
          const response = Buffer.from(`TXT "cmd:ping"`);
          this.udpServer.send(response, 0, response.length, rinfo.port, rinfo.address);
        }
      } catch (err) {
        console.error('[DNS-UDP] Error:', err);
      }
    });

    this.udpServer.bind(CONFIG.PORTS.DNS_UDP, () => {
      console.log(`[DNS-UDP] Server listening on port ${CONFIG.PORTS.DNS_UDP}`);
      protocolStatus.dns_udp = 'active';
    });
  }

  // Method 2: DNS over TCP
  startTCP() {
    this.tcpServer.on('connection', (socket) => {
      socket.on('data', (data) => {
        try {
          const domain = data.toString().split(' ')[0];
          if (domain.includes(CONFIG.DNS.SUBDOMAIN)) {
            const payload = domain.split('.')[0];
            const decoded = Buffer.from(payload, 'base64').toString('utf-8');
            console.log(`[DNS-TCP] Received: ${decoded} from ${socket.remoteAddress}`);
            
            // Send response
            const response = Buffer.from(`TXT "cmd:ping"`);
            socket.write(response);
          }
        } catch (err) {
          console.error('[DNS-TCP] Error:', err);
        }
      });
    });

    this.tcpServer.listen(CONFIG.PORTS.DNS_TCP, () => {
      console.log(`[DNS-TCP] Server listening on port ${CONFIG.PORTS.DNS_TCP}`);
      protocolStatus.dns_tcp = 'active';
    });
  }

  // Method 3: DNS over HTTPS (DoH)
  async startDNSOverHTTPS() {
    app.post('/dns-query', bodyParser.raw({ type: 'application/dns-message' }), (req, res) => {
      try {
        const decoded = Buffer.from(req.body.toString('base64'), 'base64').toString('utf-8');
        console.log(`[DNS-HTTPS] Received: ${decoded}`);
        
        // Create minimal DNS response
        const response = Buffer.alloc(12);
        response.writeUInt16BE(0x8180, 2); // Flags: QR=1, RD=1, RA=1
        res.set('Content-Type', 'application/dns-message');
        res.send(response);
      } catch (err) {
        console.error('[DNS-HTTPS] Error:', err);
        res.status(500).send('DNS query failed');
      }
    });
    protocolStatus.dns_https = 'active';
  }
}

// ======================
// ICMP Tunnel Implementation
// ======================
class ICMPTunnel {
  constructor() {
    this.agents = new Map();
  }

  async start() {
    console.log('[ICMP] Starting ICMP tunnel monitoring');
    setInterval(() => this.checkAgents(), CONFIG.CHECK_INTERVALS.AGENT_STATUS);
  }

  async checkAgents() {
    try {
      const res = await ping.promise.probe('127.0.0.1', { timeout: 2 });
      protocolStatus.icmp = res.alive ? 'active' : 'inactive';
    } catch (err) {
      console.error('[ICMP] Error:', err);
      protocolStatus.icmp = 'error';
    }
  }
}

// ======================
// TCP Tunnel Implementation (for VPN testing)
// ======================
class TCPTunnel {
  constructor() {
    this.server = net.createServer();
    this.activeConnections = new Set();
    this.connectionTimeout = 30000; // 30 seconds
    
    // Track last activity time
    this.lastActivity = Date.now();
  }

  start() {
    this.server.on('connection', (socket) => {
      console.log(`[TCP] New connection from ${socket.remoteAddress}`);
      this.activeConnections.add(socket);
      this.lastActivity = Date.now();
      protocolStatus.tcp = 'active';

      socket.on('data', (data) => {
        this.lastActivity = Date.now();
        console.log(`[TCP] Received: ${data.toString()}`);
        socket.write('ACK');
      });

      socket.on('close', () => {
        console.log(`[TCP] Connection closed`);
        this.activeConnections.delete(socket);
        this.updateStatus();
      });

      socket.on('error', (err) => {
        console.error(`[TCP] Error: ${err}`);
        this.activeConnections.delete(socket);
        this.updateStatus();
      });

      socket.setTimeout(this.connectionTimeout, () => {
        socket.destroy();
      });
    });

    this.server.listen(CONFIG.PORTS.TCP_TUNNEL, () => {
      console.log(`[TCP] Listening on port ${CONFIG.PORTS.TCP_TUNNEL}`);
    });
  }

  updateStatus() {
    // Only mark as inactive if no connections for 5 seconds
    const inactiveThreshold = 5000;
    const now = Date.now();
    
    if (this.activeConnections.size === 0 && 
        (now - this.lastActivity) > inactiveThreshold) {
      protocolStatus.tcp = 'inactive';
    }
  }
}

// ======================
// Web Tunnel (HTTP/HTTPS)
// ======================
class WebTunnel {
  constructor() {
    this.httpServer = null;
    this.httpsServer = null;
    this.setupRoutes();
  }

  setupRoutes() {
    app.use(bodyParser.json());
    app.use(cors());

    // Health endpoint
    app.get('/health', (req, res) => {
      res.status(200).send('OK');
    });

    // Protocol status endpoint
    app.get('/api/protocol-status', (req, res) => {
      res.json(protocolStatus);
    });

    // Frontend endpoint
    app.get('/', (req, res) => {
      res.sendFile(__dirname + '/public/index.html');
    });

    // Static files
    app.use(express.static('public'));
  }

  start() {
    // HTTP Server
    this.httpServer = http.createServer(app);
    this.httpServer.listen(CONFIG.PORTS.HTTP, () => {
      console.log(`[HTTP] Server listening on port ${CONFIG.PORTS.HTTP}`);
      protocolStatus.http = 'active';
    });

    // HTTPS Server (with self-signed fallback)
    if (this.hasCertificates()) {
      const options = {
        key: fs.readFileSync(CONFIG.SECURITY.SELF_SIGNED_CERT.KEY),
        cert: fs.readFileSync(CONFIG.SECURITY.SELF_SIGNED_CERT.CERT),
        minVersion: 'TLSv1.2'
      };
      this.httpsServer = https.createServer(options, app);
      this.httpsServer.listen(CONFIG.PORTS.HTTPS, () => {
        console.log(`[HTTPS] Server listening on port ${CONFIG.PORTS.HTTPS}`);
        protocolStatus.https = 'active';
      });
    } else {
      console.warn('[HTTPS] Certificate files missing - HTTPS disabled');
    }
  }

  hasCertificates() {
    try {
      return fs.existsSync(CONFIG.SECURITY.SELF_SIGNED_CERT.KEY) && 
             fs.existsSync(CONFIG.SECURITY.SELF_SIGNED_CERT.CERT);
    } catch (err) {
      return false;
    }
  }
}

// ======================
// VPN Testing
// ======================
class VPNTester {
  static connection = null;
  static lastTest = 0;

  static async testVPN() {
    const now = Date.now();
    
    // Reuse existing connection if recent
    if (this.connection && (now - this.lastTest) < 10000) {
      return 'active (persistent connection)';
    }

    return new Promise((resolve) => {
      // Close previous connection if exists
      if (this.connection) {
        this.connection.destroy();
      }

      this.connection = net.createConnection({
        port: CONFIG.PORTS.TCP_TUNNEL,
        timeout: 2000
      });

      this.connection.on('connect', () => {
        this.lastTest = now;
        resolve('active (simulated VPN)');
      });

      this.connection.on('timeout', () => {
        this.connection.destroy();
        resolve('inactive (timeout)');
      });

      this.connection.on('error', () => {
        resolve('inactive (error)');
      });
    });
  }
}

// ======================
// Main Execution
// ======================
async function main() {
  // Create public directory for frontend
  if (!fs.existsSync('public')) {
    fs.mkdirSync('public');
  }

  // Write frontend files
  fs.writeFileSync('public/index.html', `
    <!DOCTYPE html>
    <html>
    <head>
      <title>C2 Connection Status</title>
      <link rel="stylesheet" href="styles.css">
    </head>
    <body>
      <h1>Connection Status Dashboard</h1>
      <div id="status-container"></div>
      <script src="app.js"></script>
    </body>
    </html>
  `);

  fs.writeFileSync('public/styles.css', `
    body { font-family: Arial, sans-serif; margin: 20px; }
    .status-card { 
      border: 1px solid #ddd; 
      padding: 15px; 
      margin: 10px; 
      border-radius: 5px; 
      display: inline-block;
      width: 200px;
    }
    .active { background-color: #d4edda; }
    .inactive { background-color: #f8d7da; }
    .unknown { background-color: #fff3cd; }
    .error { background-color: #f5b7b1; }
  `);

  fs.writeFileSync('public/app.js', `
    async function updateStatus() {
      try {
        const res = await fetch('/api/protocol-status');
        const status = await res.json();
        
        const container = document.getElementById('status-container');
        container.innerHTML = '';
        
        for (const [protocol, state] of Object.entries(status)) {
          const card = document.createElement('div');
          card.className = \`status-card \${state.split(' ')[0]}\`;
          card.innerHTML = \`
            <h3>\${protocol.toUpperCase()}</h3>
            <p>Status: \${state.toUpperCase()}</p>
            <p>Last checked: \${new Date().toLocaleTimeString()}</p>
          \`;
          container.appendChild(card);
        }
      } catch (err) {
        console.error('Failed to update status:', err);
      }
    }
    
    updateStatus();
    setInterval(updateStatus, 5000);
  `);

  // Start all tunnels
  const dnsTunnel = new DNSTunnel();
  const icmpTunnel = new ICMPTunnel();
  const webTunnel = new WebTunnel();
  const tcpTunnel = new TCPTunnel();
  const udpTunnel = new UDPTunnel(); // Added UDP tunnel

  dnsTunnel.start();
  icmpTunnel.start();
  webTunnel.start();
  tcpTunnel.start();
  udpTunnel.start(); // Start UDP tunnel

  // Initial status check
  await checkAllProtocols();
  protocolStatus.vpn = await VPNTester.testVPN();

  // Periodic status checks
  setInterval(async () => {
    await checkAllProtocols();
    protocolStatus.vpn = await VPNTester.testVPN();
  }, 60000); // Check every 60 seconds instead of 30
  (CONFIG.CHECK_INTERVALS.PROTOCOL_STATUS);
}

async function checkAllProtocols() {
  // Check HTTP
  try {
    await axios.get(`http://localhost:${CONFIG.PORTS.HTTP}/health`, { timeout: 2000 });
    protocolStatus.http = 'active';
  } catch {
    protocolStatus.http = 'inactive';
  }

  // Check HTTPS
  if (protocolStatus.https !== 'inactive') {
    try {
      await axios.get(`https://localhost:${CONFIG.PORTS.HTTPS}/health`, {
        timeout: 2000,
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
      });
      protocolStatus.https = 'active';
    } catch {
      protocolStatus.https = 'inactive';
    }
  }

  // Check DNS UDP
  try {
    const socket = dgram.createSocket('udp4');
    await new Promise((resolve) => {
      socket.on('error', () => resolve());
      socket.bind(() => {
        socket.close();
        resolve();
      });
    });
    protocolStatus.dns_udp = 'active';
  } catch {
    protocolStatus.dns_udp = 'inactive';
  }

  // Check DNS TCP
  try {
    const socket = net.createConnection(CONFIG.PORTS.DNS_TCP, 'localhost');
    await new Promise((resolve) => {
      socket.on('connect', () => {
        socket.end();
        resolve();
      });
      socket.on('error', () => resolve());
    });
    protocolStatus.dns_tcp = 'active';
  } catch {
    protocolStatus.dns_tcp = 'inactive';
  }

  // Check TCP Tunnel
  try {
    const socket = net.createConnection(CONFIG.PORTS.TCP_TUNNEL, 'localhost');
    await new Promise((resolve) => {
      socket.on('connect', () => {
        socket.end();
        resolve();
      });
      socket.on('error', () => resolve());
    });
    protocolStatus.tcp = 'active';
  } catch {
    protocolStatus.tcp = 'inactive';
  }

  // Check UDP Tunnel
  try {
    const socket = dgram.createSocket('udp4');
    await new Promise((resolve) => {
      socket.on('error', () => resolve());
      socket.send('PING', CONFIG.PORTS.UDP_TUNNEL, 'localhost', (err) => {
        if (err) {
          resolve();
          return;
        }
        
        socket.once('message', () => {
          socket.close();
          resolve();
        });
        
        // Timeout if no response
        setTimeout(() => {
          socket.close();
          resolve();
        }, 2000);
      });
    });
    protocolStatus.udp = 'active';
  } catch {
    protocolStatus.udp = 'inactive';
  }
}

main().catch(console.error);