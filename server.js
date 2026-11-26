// Headless zero-dependency WebSocket (wss://) connection server for Whatsnap on Render.
// Serves no frontend HTML — handles WebSocket connections (/ws or /), rooms with cover images,
// live video/audio/file binary relay, and instant tab-close disconnect.
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin5923';
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_FRAME_BYTES = 12 * 1024 * 1024; // 12 MB limit for chat files & media
const MAX_COVER_CHARS = 120 * 1024;       // ~120 KB limit for compressed room cover image data URL

// All connected clients & active rooms
const clients = new Set();
// rooms: Map<roomName, { cover: string | null, members: Set<Client> }>
const rooms = new Map();

// ================= RFC 6455 WEBSOCKET HELPERS =================
function encodeFrame(opcode, payloadBuf) {
  const payload = Buffer.isBuffer(payloadBuf) ? payloadBuf : Buffer.from(payloadBuf || '');
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.allocUnsafe(2);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.allocUnsafe(4);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.allocUnsafe(10);
    header[0] = 0x80 | (opcode & 0x0f);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

function createClient(socket) {
  return {
    id: crypto.randomBytes(4).toString('hex'),
    name: 'User',
    room: null,
    isAdmin: false,
    showAdminTag: false,
    hidden: false,
    trolls: new Set(),
    alive: true,
    closed: false,
    socket,
    sendJSON(obj) {
      if (this.closed || this.socket.destroyed) return;
      try {
        this.socket.write(encodeFrame(0x1, Buffer.from(JSON.stringify(obj), 'utf8')));
      } catch (e) {}
    },
    sendBinary(buf, dropIfBackedUp = false) {
      if (this.closed || this.socket.destroyed) return;
      if (dropIfBackedUp && this.socket.writableLength > 192 * 1024) return;
      try {
        this.socket.write(encodeFrame(0x2, buf));
      } catch (e) {}
    },
    ping() {
      if (this.closed || this.socket.destroyed) return;
      try {
        this.socket.write(encodeFrame(0x9, Buffer.alloc(0)));
      } catch (e) {}
    },
    close() {
      if (this.closed) return;
      this.closed = true;
      try {
        this.socket.write(encodeFrame(0x8, Buffer.alloc(0)));
        this.socket.end();
      } catch (e) {}
    }
  };
}

// ================= ROOM MANAGEMENT =================
function sanitizeCover(rawCover) {
  if (typeof rawCover !== 'string') return null;
  if (!rawCover.startsWith('data:image/')) return null;
  if (rawCover.length > MAX_COVER_CHARS) return null;
  return rawCover;
}

function publicName(client) {
  return client.isAdmin && client.showAdminTag ? `${client.name} (admin)` : client.name;
}

function getRoomList(forAdmin = false) {
  return Array.from(rooms.entries())
    .map(([name, info]) => {
      let visibleCount = 0;
      let hiddenCount = 0;
      for (const m of info.members) {
        if (m.hidden) hiddenCount++;
        else visibleCount++;
      }
      return {
        name,
        count: visibleCount,
        ...(forAdmin ? { hiddenCount } : {}),
        cover: info.cover || null
      };
    })
    .filter((r) => (forAdmin ? r.count + (r.hiddenCount || 0) > 0 : r.count > 0))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

function broadcastRoomList() {
  const publicPayload = { type: 'rooms', rooms: getRoomList(false) };
  const adminPayload = { type: 'rooms', rooms: getRoomList(true) };
  for (const c of clients) {
    c.sendJSON(c.isAdmin ? adminPayload : publicPayload);
  }
}

function broadcastRoomTrolls(roomName) {
  const roomObj = rooms.get(roomName);
  if (!roomObj) return;
  const map = {};
  for (const m of roomObj.members) {
    if (!m.hidden) {
      map[m.id] = Array.from(m.trolls);
    }
  }
  const payload = { type: 'admin-trolls-sync', map };
  for (const m of roomObj.members) {
    if (m.isAdmin) m.sendJSON(payload);
  }
}

function leaveRoom(client) {
  if (!client.room) return;
  const roomName = client.room;
  const wasHidden = client.hidden;
  const roomObj = rooms.get(roomName);
  client.room = null;
  client.hidden = false;
  client.trolls.clear();
  if (roomObj) {
    roomObj.members.delete(client);
    if (!wasHidden) {
      for (const other of roomObj.members) {
        other.sendJSON({ type: 'peer-left', peerId: client.id });
      }
      broadcastRoomTrolls(roomName);
    }
    if (roomObj.members.size === 0) rooms.delete(roomName);
  }
  broadcastRoomList();
}

function disconnectClient(client) {
  if (!client || client.closed) return;
  client.closed = true;
  leaveRoom(client);
  clients.delete(client);
  try {
    if (!client.socket.destroyed) client.socket.destroy();
  } catch (e) {}
}

function joinRoom(client, rawRoom, rawName, rawCover) {
  const roomName = String(rawRoom || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
  if (!roomName) return;

  if (client.room === roomName) return;
  leaveRoom(client);

  client.name = String(rawName || client.name || 'User').trim().slice(0, 28) || 'User';
  client.room = roomName;
  // Admins join silently in stealth mode until they explicitly enable presence
  client.hidden = Boolean(client.isAdmin);

  const cleanCover = sanitizeCover(rawCover);
  if (!rooms.has(roomName)) {
    rooms.set(roomName, { cover: cleanCover, members: new Set() });
  } else if (cleanCover && !rooms.get(roomName).cover) {
    rooms.get(roomName).cover = cleanCover;
  }

  const roomObj = rooms.get(roomName);
  const members = roomObj.members;

  const peers = [];
  for (const other of members) {
    if (!other.hidden) {
      peers.push({ peerId: other.id, name: publicName(other) });
    }
    if (!client.hidden) {
      other.sendJSON({
        type: 'peer-joined',
        peerId: client.id,
        name: publicName(client)
      });
    }
  }

  members.add(client);
  client.sendJSON({ type: 'room-state', room: roomName, peers, hidden: client.hidden });
  broadcastRoomTrolls(roomName);
  broadcastRoomList();
}

function handleTextMessage(client, text) {
  let msg;
  try {
    msg = JSON.parse(text);
  } catch (e) {
    return;
  }

  if (msg.type === 'join') {
    joinRoom(client, msg.room, msg.name, msg.cover);
  } else if (msg.type === 'leave') {
    leaveRoom(client);
  } else if (msg.type === 'rooms') {
    client.sendJSON({ type: 'rooms', rooms: getRoomList(client.isAdmin) });
  } else if (msg.type === 'admin-auth') {
    const ok = String(msg.password || '').trim() === ADMIN_PASSWORD;
    client.isAdmin = ok;
    if (ok) {
      client.showAdminTag = msg.showAdminTag === true;
    }
    client.sendJSON({ type: 'admin-auth', ok });
    if (ok) {
      client.sendJSON({ type: 'rooms', rooms: getRoomList(true) });
      if (client.room) {
        broadcastRoomTrolls(client.room);
      }
      if (client.room && !client.hidden) {
        const roomObj = rooms.get(client.room);
        if (roomObj) {
          for (const other of roomObj.members) {
            if (other !== client) {
              other.sendJSON({ type: 'peer-updated', peerId: client.id, name: publicName(client) });
            }
          }
        }
      }
    }
  } else if (msg.type === 'admin-exit') {
    const wasHidden = client.hidden;
    client.isAdmin = false;
    client.showAdminTag = false;
    if (client.room && wasHidden) {
      leaveRoom(client);
    } else if (client.room) {
      const roomObj = rooms.get(client.room);
      if (roomObj) {
        for (const other of roomObj.members) {
          if (other !== client) {
            other.sendJSON({ type: 'peer-updated', peerId: client.id, name: publicName(client) });
          }
        }
      }
    }
    client.sendJSON({ type: 'rooms', rooms: getRoomList(false) });
  } else if (msg.type === 'admin-presence' && client.isAdmin && client.room) {
    const wantVisible = Boolean(msg.visible);
    const roomObj = rooms.get(client.room);
    if (!roomObj) return;
    if (wantVisible && client.hidden) {
      client.hidden = false;
      for (const other of roomObj.members) {
        if (other !== client) {
          other.sendJSON({ type: 'peer-joined', peerId: client.id, name: publicName(client) });
        }
      }
      client.sendJSON({ type: 'admin-presence', visible: true });
      broadcastRoomList();
    } else if (!wantVisible && !client.hidden) {
      client.hidden = true;
      for (const other of roomObj.members) {
        if (other !== client) {
          other.sendJSON({ type: 'peer-left', peerId: client.id });
        }
      }
      client.sendJSON({ type: 'admin-presence', visible: false });
      broadcastRoomList();
    }
  } else if (msg.type === 'admin-tag' && client.isAdmin) {
    client.showAdminTag = Boolean(msg.showAdminTag);
    if (client.room && !client.hidden) {
      const roomObj = rooms.get(client.room);
      if (roomObj) {
        for (const other of roomObj.members) {
          if (other !== client) {
            other.sendJSON({ type: 'peer-updated', peerId: client.id, name: publicName(client) });
          }
        }
      }
    }
  } else if (msg.type === 'admin-announce' && client.isAdmin && client.room) {
    const clean = String(msg.text || '').trim().slice(0, 500);
    if (!clean) return;
    const roomObj = rooms.get(client.room);
    if (roomObj) {
      for (const member of roomObj.members) {
        member.sendJSON({ type: 'system', text: `[Notice] ${clean}` });
      }
    }
  } else if (msg.type === 'admin-troll' && client.isAdmin && client.room) {
    const toggleTrolls = new Set([
      'corrupt-video',
      'deepfry-video',
      'freeze-video',
      'fnaf-twitch',
      'corrupt-audio',
      'cutout-audio',
      'echo-audio'
    ]);
    const action = String(msg.action || '');
    if (!toggleTrolls.has(action) && action !== 'popup' && action !== 'reset') return;
    const targetId = msg.targetId ? String(msg.targetId) : 'all';
    const value = typeof msg.value === 'string' ? msg.value.trim().slice(0, 140) : '';
    const forceOff = Boolean(msg.forceOff);
    const roomObj = rooms.get(client.room);
    if (!roomObj) return;

    for (const member of roomObj.members) {
      if (member === client) continue;
      if (targetId !== 'all' && member.id !== targetId) continue;

      if (action === 'popup') {
        member.sendJSON({ type: 'troll', action: 'popup', value });
      } else if (action === 'reset') {
        member.trolls.clear();
        member.sendJSON({ type: 'troll-state', trolls: [] });
      } else {
        if (forceOff || member.trolls.has(action)) {
          member.trolls.delete(action);
        } else {
          member.trolls.add(action);
        }
        member.sendJSON({ type: 'troll-state', trolls: Array.from(member.trolls) });
      }
    }
    if (action !== 'popup') {
      broadcastRoomTrolls(client.room);
    }
  } else if (msg.type === 'admin-kick' && client.isAdmin && msg.peerId) {
    for (const c of clients) {
      if (c.id === msg.peerId && c !== client) {
        leaveRoom(c);
        c.sendJSON({ type: 'kicked', reason: 'Removed from room by admin.' });
        break;
      }
    }
  } else if (msg.type === 'admin-close-room' && client.isAdmin && msg.room) {
    const roomObj = rooms.get(String(msg.room));
    if (roomObj) {
      for (const member of Array.from(roomObj.members)) {
        member.room = null;
        member.hidden = false;
        member.sendJSON({ type: 'kicked', reason: `Room "${msg.room}" was closed by admin.` });
      }
      rooms.delete(String(msg.room));
      broadcastRoomList();
    }
  } else if (msg.type === 'chat' && client.room) {
    const clean = String(msg.text || '').trim().slice(0, 1000);
    if (!clean) return;
    const roomObj = rooms.get(client.room);
    if (roomObj) {
      const senderName = publicName(client);
      for (const other of roomObj.members) {
        if (other !== client) {
          other.sendJSON({
            type: 'chat',
            from: client.id,
            name: senderName,
            text: clean
          });
        }
      }
    }
  }
}

// Binary relay:
// Incoming: [kind(1: 1=video, 2=audio, 3=file), ...payload]
// Outgoing: [kind(1), peerIdLen(1), ...peerIdBytes, ...payload]
function handleBinaryMessage(client, data) {
  if (!client.room || data.length < 2) return;
  const roomObj = rooms.get(client.room);
  if (!roomObj || roomObj.members.size <= 1) return;

  const kind = data[0];
  if (kind !== 1 && kind !== 2 && kind !== 3) return;
  // Never leak video or audio while an admin is in stealth mode
  if (client.hidden && (kind === 1 || kind === 2)) return;

  const idBuf = Buffer.from(client.id, 'ascii');
  const out = Buffer.allocUnsafe(2 + idBuf.length + (data.length - 1));
  out[0] = kind;
  out[1] = idBuf.length;
  idBuf.copy(out, 2);
  data.copy(out, 2 + idBuf.length, 1);

  const isVideo = kind === 1;
  for (const other of roomObj.members) {
    if (other !== client) {
      other.sendBinary(out, isVideo);
    }
  }
}

// ================= HEADLESS HTTP + WEBSOCKET SERVER =================
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (req.method === 'GET' && (parsed.pathname === '/' || parsed.pathname === '/health' || parsed.pathname === '/api/health')) {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ ok: true, service: 'whatsnap-server', transport: 'wss', rooms: rooms.size, clients: clients.size }));
    return;
  }

  if (req.method === 'GET' && (parsed.pathname === '/rooms' || parsed.pathname === '/api/rooms')) {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(getRoomList()));
    return;
  }

  // Instant tab-close disconnect beacon endpoint (called via navigator.sendBeacon)
  if (req.method === 'POST' && parsed.pathname === '/leave') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 4096) req.destroy();
    });
    req.on('end', () => {
      try {
        const { peerId } = JSON.parse(body || '{}');
        if (peerId) {
          for (const c of clients) {
            if (c.id === peerId) {
              disconnectClient(c);
              break;
            }
          }
        }
      } catch (e) {}
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true}');
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.on('upgrade', (req, socket, head) => {
  if (ALLOWED_ORIGIN !== '*' && req.headers.origin && req.headers.origin !== ALLOWED_ORIGIN) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    socket.destroy();
    return;
  }

  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return;
  }

  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
  socket.setNoDelay(true);

  const client = createClient(socket);
  clients.add(client);
  client.sendJSON({ type: 'welcome', peerId: client.id, rooms: getRoomList() });

  let buffer = Buffer.alloc(0);
  let fragOpcode = 0;
  let fragChunks = [];

  function processBuffer() {
    while (buffer.length >= 2) {
      const b0 = buffer[0];
      const b1 = buffer[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let offset = 2;

      if (len === 126) {
        if (buffer.length < 4) return;
        len = buffer.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (buffer.length < 10) return;
        len = Number(buffer.readBigUInt64BE(2));
        offset = 10;
      }

      if (len > MAX_FRAME_BYTES) {
        disconnectClient(client);
        return;
      }

      const maskLen = masked ? 4 : 0;
      if (buffer.length < offset + maskLen + len) return;

      const payload = Buffer.allocUnsafe(len);
      if (masked) {
        const mask = [buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]];
        const start = offset + 4;
        for (let i = 0; i < len; i++) {
          payload[i] = buffer[start + i] ^ mask[i & 3];
        }
      } else {
        buffer.copy(payload, 0, offset, offset + len);
      }

      buffer = buffer.subarray(offset + maskLen + len);
      client.alive = true;

      if (opcode === 0x8) {
        disconnectClient(client);
        return;
      } else if (opcode === 0x9) {
        try { socket.write(encodeFrame(0xA, payload)); } catch (e) {}
      } else if (opcode === 0xA) {
        // Pong
      } else if (opcode === 0x0) {
        if (fragOpcode) {
          fragChunks.push(payload);
          if (fin) {
            const full = Buffer.concat(fragChunks);
            const op = fragOpcode;
            fragOpcode = 0;
            fragChunks = [];
            if (op === 0x1) handleTextMessage(client, full.toString('utf8'));
            else if (op === 0x2) handleBinaryMessage(client, full);
          }
        }
      } else if (opcode === 0x1 || opcode === 0x2) {
        if (fin) {
          if (opcode === 0x1) handleTextMessage(client, payload.toString('utf8'));
          else handleBinaryMessage(client, payload);
        } else {
          fragOpcode = opcode;
          fragChunks = [payload];
        }
      }
    }
  }

  socket.on('data', (chunk) => {
    buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
    processBuffer();
  });

  if (head && head.length > 0) {
    buffer = head;
    processBuffer();
  }

  const cleanup = () => disconnectClient(client);
  socket.on('close', cleanup);
  socket.on('end', cleanup);
  socket.on('error', cleanup);
});

// Keep WebSockets alive behind Render's proxy & clean up dead sockets quickly
setInterval(() => {
  for (const c of clients) {
    if (!c.alive) {
      disconnectClient(c);
      continue;
    }
    c.alive = false;
    c.ping();
  }
}, 12000);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Whatsnap wss:// connection server listening on port ${PORT}`);
});
