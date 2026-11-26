// Zero-dependency signaling server for automated WebRTC handshakes between devices.
// Run with: node server.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = process.env.PORT || 3000;
const INDEX_PATH = path.join(__dirname, 'index.html');

// rooms: Map<roomName, Map<peerId, http.ServerResponse>>
const rooms = new Map();

function sendSSE(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function getRoom(name) {
  if (!rooms.has(name)) rooms.set(name, new Map());
  return rooms.get(name);
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Health check used by index.html Auto mode
  if (req.method === 'GET' && parsed.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, mode: 'local-signaling' }));
    return;
  }

  // Serve index.html
  if (req.method === 'GET' && (parsed.pathname === '/' || parsed.pathname === '/index.html')) {
    fs.readFile(INDEX_PATH, (err, content) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Could not read index.html');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(content);
    });
    return;
  }

  // Server-Sent Events stream for automated WebRTC signaling
  if (req.method === 'GET' && parsed.pathname === '/events') {
    const roomName = (parsed.searchParams.get('room') || '').trim();
    const peerId = (parsed.searchParams.get('peerId') || '').trim();
    if (!roomName || !peerId) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Missing room or peerId');
      return;
    }

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });
    res.write(': connected\n\n');

    const room = getRoom(roomName);
    // Notify any existing peer in the room so they automatically send an offer
    for (const [otherId, otherRes] of room.entries()) {
      if (otherId !== peerId) {
        sendSSE(otherRes, 'peer-joined', { peerId });
      }
    }
    room.set(peerId, res);

    const keepAlive = setInterval(() => {
      res.write(': ping\n\n');
    }, 20000);

    req.on('close', () => {
      clearInterval(keepAlive);
      room.delete(peerId);
      for (const otherRes of room.values()) {
        sendSSE(otherRes, 'peer-left', { peerId });
      }
      if (room.size === 0) rooms.delete(roomName);
    });
    return;
  }

  // Relay offers, answers, and ICE candidates to other peers in the room
  if (req.method === 'POST' && parsed.pathname === '/signal') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1e6) req.destroy();
    });
    req.on('end', () => {
      try {
        const { room: roomName, from, type, payload } = JSON.parse(body);
        const room = rooms.get(roomName);
        if (room) {
          for (const [otherId, otherRes] of room.entries()) {
            if (otherId !== from) {
              sendSSE(otherRes, type, { from, payload });
            }
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end('{"ok":false}');
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Video chat signaling server running:`);
  console.log(`  Local:   http://localhost:${PORT}`);
  const nets = os.networkInterfaces();
  for (const ifaces of Object.values(nets)) {
    for (const net of ifaces || []) {
      if (net.family === 'IPv4' && !net.internal) {
        console.log(`  Network: http://${net.address}:${PORT}`);
      }
    }
  }
  console.log(`\nNote: Other devices need HTTPS for camera access (e.g. cloudflared/ngrok tunnel).`);
});
