// Headless zero-dependency encrypted WebSocket + HTTPS long-polling relay server.
// All traffic (WS binary frames & HTTP fallback) uses ephemeral ECDH (P-256) + HKDF-SHA256 + AES-256-GCM
// with masked handshakes, randomized packet padding, and neutral endpoints.
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || '*')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin5923';
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_FRAME_BYTES = 12 * 1024 * 1024; // 12 MB limit for chat files & media
const MAX_HANDSHAKE_BYTES = 512;
const MAX_COVER_CHARS = 120 * 1024;       // ~120 KB limit for compressed room cover image data URL
const HANDSHAKE_TIMEOUT_MS = 10000;       // 10s limit to complete WS ECDH handshake
const HEARTBEAT_MS = 25000;               // 25s heartbeat interval (tolerant of higher-latency proxies)
const MAX_MISSED_PINGS = 2;               // ~50s grace before closing idle WS sockets
const HTTP_POLL_HOLD_MS = 20000;          // 20s long-poll hold (well under Render/proxy HTTP timeouts)
const HTTP_BATCH_DELAY_MS = 20;           // Coalesce burst frames into one HTTP poll response
const HTTP_IDLE_TIMEOUT_MS = 45000;       // 45s idle timeout for HTTP polling clients
const HTTP_MAX_QUEUE_BYTES = 2 * 1024 * 1024;

// Encrypted inner envelope types (never visible in plaintext on the wire)
const INNER_JSON = 1;
const INNER_BINARY = 2;
const INNER_CHAFF = 3;
const INNER_BATCH = 4;

const KDF_INFO = Buffer.from('sync-v2-session', 'utf8');

// All authenticated clients, session lookups & active rooms
const clients = new Set();
// Lookup by opaque session ID (for both WS & HTTP encrypted close beacons)
const sessionsById = new Map();
// HTTP polling client lookup: Map<sessionId, Client>
const httpClients = new Map();
// rooms: Map<roomName, { cover: string | null, members: Set<Client> }>
const rooms = new Map();

function isOriginAllowed(origin) {
  if (ALLOWED_ORIGINS.includes('*')) return true;
  if (!origin) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

function applyCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Cache-Control', 'no-store');
}

// ================= APPLICATION-LAYER ENCRYPTION (ECDH P-256 + HKDF + AES-256-GCM) =================
function randomInt(min, max) {
  return min + crypto.randomInt(max - min + 1);
}

function deriveMask(nonce, label, length) {
  const labelBuf = Buffer.from(label, 'utf8');
  const out = Buffer.allocUnsafe(length);
  let written = 0;
  let counter = 0;
  while (written < length) {
    const block = crypto.createHash('sha256')
      .update(nonce)
      .update(labelBuf)
      .update(Buffer.from([counter & 0xff]))
      .digest();
    const take = Math.min(block.length, length - written);
    block.copy(out, written, 0, take);
    written += take;
    counter++;
  }
  return out;
}

function deriveSessionCrypto(sharedSecret, clientNonce, serverNonce) {
  const salt = Buffer.concat([clientNonce, serverNonce]);
  const okm = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, KDF_INFO, 80));
  return {
    c2sKey: okm.subarray(0, 32),
    s2cKey: okm.subarray(32, 64),
    c2sIvMask: okm.subarray(64, 72),
    s2cIvMask: okm.subarray(72, 80),
    txCounter: 0n
  };
}

function computePadLength(innerType, payloadLen) {
  if (innerType === INNER_JSON || innerType === INNER_CHAFF) {
    const rem = (3 + payloadLen) % 128;
    const align = rem === 0 ? 0 : (128 - rem);
    return align + randomInt(32, 191);
  }
  if (innerType === INNER_BATCH) {
    return randomInt(32, 223);
  }
  return randomInt(32, 287);
}

function encryptEnvelope(sessionCrypto, innerType, payloadBuf) {
  const payload = Buffer.isBuffer(payloadBuf) ? payloadBuf : Buffer.from(payloadBuf || '');
  const padLen = computePadLength(innerType, payload.length);
  // Zero-filled buffer safely clears padding bytes; AES-GCM ciphertext is indistinguishable from random
  const plain = Buffer.alloc(3 + payload.length + padLen);
  plain[0] = innerType;
  plain.writeUInt16BE(padLen, 1);
  if (payload.length > 0) {
    payload.copy(plain, 3);
  }

  sessionCrypto.txCounter += 1n;
  const iv = Buffer.allocUnsafe(12);
  crypto.randomBytes(4).copy(iv, 0);
  const cntBuf = Buffer.allocUnsafe(8);
  cntBuf.writeBigUInt64BE(sessionCrypto.txCounter, 0);
  for (let i = 0; i < 8; i++) {
    iv[4 + i] = cntBuf[i] ^ sessionCrypto.s2cIvMask[i];
  }

  const cipher = crypto.createCipheriv('aes-256-gcm', sessionCrypto.s2cKey, iv);
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]);
}

function decryptEnvelope(sessionCrypto, encryptedBuf) {
  if (!sessionCrypto || !Buffer.isBuffer(encryptedBuf) || encryptedBuf.length < 12 + 3 + 16) {
    return null;
  }
  const iv = encryptedBuf.subarray(0, 12);
  const tag = encryptedBuf.subarray(encryptedBuf.length - 16);
  const ct = encryptedBuf.subarray(12, encryptedBuf.length - 16);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionCrypto.c2sKey, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    if (plain.length < 3) return null;
    const innerType = plain[0];
    const padLen = plain.readUInt16BE(1);
    if (3 + padLen > plain.length) return null;
    const payload = plain.subarray(3, plain.length - padLen);
    return { innerType, payload };
  } catch (e) {
    return null;
  }
}

// Parse ClientHello: [clientNonce(16) || maskedClientPub(65) || maskedPadLen(1) || randomPad(padLen)]
function processClientHandshake(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 82 || buf.length > MAX_HANDSHAKE_BYTES) {
    return null;
  }
  const clientNonce = buf.subarray(0, 16);
  const maskC = deriveMask(clientNonce, 'hs-c', 66);
  const clientPubRaw = Buffer.allocUnsafe(65);
  for (let i = 0; i < 65; i++) {
    clientPubRaw[i] = buf[16 + i] ^ maskC[i];
  }
  const padLen = buf[81] ^ maskC[65];
  if (clientPubRaw[0] !== 0x04 || 82 + padLen !== buf.length) {
    return null;
  }

  let sharedSecret;
  let serverPubRaw;
  try {
    const ecdh = crypto.createECDH('prime256v1');
    serverPubRaw = ecdh.generateKeys();
    sharedSecret = ecdh.computeSecret(clientPubRaw);
  } catch (e) {
    return null;
  }

  const serverNonce = crypto.randomBytes(16);
  const sessionCrypto = deriveSessionCrypto(sharedSecret, clientNonce, serverNonce);
  return { serverNonce, serverPubRaw, sessionCrypto };
}

// Build WS ServerHello: [serverNonce(16) || maskedServerPub(65) || maskedPadLen(1) || randomPad]
function buildWsServerHello(serverNonce, serverPubRaw) {
  const padLen = randomInt(24, 87);
  const maskS = deriveMask(serverNonce, 'hs-s', 66);
  const out = Buffer.allocUnsafe(16 + 65 + 1 + padLen);
  serverNonce.copy(out, 0);
  for (let i = 0; i < 65; i++) {
    out[16 + i] = serverPubRaw[i] ^ maskS[i];
  }
  out[81] = padLen ^ maskS[65];
  crypto.randomBytes(padLen).copy(out, 82);
  return out;
}

// Build HTTP Sync ServerHello: [serverNonce(16) || maskedServerPub(65) || maskedInitLen(4) || encInit || randomPad]
function buildHttpServerHello(serverNonce, serverPubRaw, encInit) {
  const padLen = randomInt(24, 87);
  const maskS = deriveMask(serverNonce, 'hs-s', 69);
  const lenBuf = Buffer.allocUnsafe(4);
  lenBuf.writeUInt32BE(encInit.length, 0);

  const out = Buffer.allocUnsafe(16 + 65 + 4 + encInit.length + padLen);
  serverNonce.copy(out, 0);
  for (let i = 0; i < 65; i++) {
    out[16 + i] = serverPubRaw[i] ^ maskS[i];
  }
  for (let i = 0; i < 4; i++) {
    out[81 + i] = lenBuf[i] ^ maskS[65 + i];
  }
  encInit.copy(out, 85);
  crypto.randomBytes(padLen).copy(out, 85 + encInit.length);
  return out;
}

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

function encodeInnerBatch(items) {
  let total = 0;
  for (const item of items) {
    total += 5 + item.payload.length;
  }
  const out = Buffer.allocUnsafe(total);
  let offset = 0;
  for (const item of items) {
    out[offset] = item.frameType; // 1 = JSON UTF-8, 2 = Binary
    out.writeUInt32BE(item.payload.length, offset + 1);
    item.payload.copy(out, offset + 5);
    offset += 5 + item.payload.length;
  }
  return out;
}

function createWsClient(socket) {
  return {
    id: crypto.randomBytes(4).toString('hex'),
    sessionId: crypto.randomBytes(16).toString('hex'),
    transport: 'ws',
    crypto: null,
    cryptoReady: false,
    handshakeTimer: null,
    name: 'User',
    room: null,
    isAdmin: false,
    showAdminTag: false,
    hidden: false,
    trolls: new Set(),
    missedPings: 0,
    lastSeen: Date.now(),
    closed: false,
    socket,
    markAlive() {
      this.missedPings = 0;
      this.lastSeen = Date.now();
    },
    sendJSON(obj) {
      if (this.closed || this.socket.destroyed || !this.cryptoReady) return;
      try {
        const enc = encryptEnvelope(this.crypto, INNER_JSON, Buffer.from(JSON.stringify(obj), 'utf8'));
        this.socket.write(encodeFrame(0x2, enc));
      } catch (e) {}
    },
    sendBinary(buf, dropIfBackedUp = false) {
      if (this.closed || this.socket.destroyed || !this.cryptoReady) return;
      if (dropIfBackedUp && this.socket.writableLength > 192 * 1024) return;
      try {
        const enc = encryptEnvelope(this.crypto, INNER_BINARY, buf);
        this.socket.write(encodeFrame(0x2, enc));
      } catch (e) {}
    },
    ping() {
      if (this.closed || this.socket.destroyed || !this.cryptoReady) return;
      try {
        // Send both RFC 6455 control ping and an encrypted app-level ping for strict proxy keepalive
        this.socket.write(encodeFrame(0x9, Buffer.alloc(0)));
        this.sendJSON({ type: 'ping', ts: Date.now() });
      } catch (e) {}
    },
    close() {
      if (this.closed) return;
      this.closed = true;
      try {
        if (!this.socket.destroyed) {
          this.socket.write(encodeFrame(0x8, Buffer.alloc(0)));
          this.socket.end();
        }
      } catch (e) {}
    }
  };
}

function createHttpClient(sessionCrypto) {
  const client = {
    id: crypto.randomBytes(4).toString('hex'),
    sessionId: crypto.randomBytes(16).toString('hex'),
    transport: 'http',
    crypto: sessionCrypto,
    cryptoReady: true,
    name: 'User',
    room: null,
    isAdmin: false,
    showAdminTag: false,
    hidden: false,
    trolls: new Set(),
    lastSeen: Date.now(),
    closed: false,
    queue: [],
    queuedBytes: 0,
    pollRes: null,
    pollTimer: null,
    batchTimer: null,
    markAlive() {
      this.lastSeen = Date.now();
    },
    flushPoll() {
      if (this.batchTimer) {
        clearTimeout(this.batchTimer);
        this.batchTimer = null;
      }
      if (!this.pollRes) return;
      const res = this.pollRes;
      this.pollRes = null;
      if (this.pollTimer) {
        clearTimeout(this.pollTimer);
        this.pollTimer = null;
      }
      const items = this.queue.splice(0, this.queue.length);
      this.queuedBytes = 0;
      const body = items.length
        ? encryptEnvelope(this.crypto, INNER_BATCH, encodeInnerBatch(items))
        : encryptEnvelope(this.crypto, INNER_CHAFF, Buffer.alloc(0));
      try {
        if (!res.writableEnded) {
          res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': body.length
          });
          res.end(body);
        }
      } catch (e) {}
    },
    enqueue(frameType, payloadBuf, dropIfBackedUp = false) {
      if (this.closed || !this.cryptoReady) return;
      if (dropIfBackedUp && (this.queue.length > 18 || this.queuedBytes > 384 * 1024)) {
        return;
      }
      while (this.queue.length > 0 && this.queuedBytes + payloadBuf.length > HTTP_MAX_QUEUE_BYTES) {
        const droppedIdx = this.queue.findIndex((item) => item.droppable);
        if (droppedIdx >= 0) {
          const [removed] = this.queue.splice(droppedIdx, 1);
          this.queuedBytes -= removed.payload.length;
        } else {
          break;
        }
      }
      this.queue.push({ frameType, payload: payloadBuf, droppable: dropIfBackedUp });
      this.queuedBytes += payloadBuf.length;

      if (this.pollRes) {
        if (frameType === INNER_JSON || !dropIfBackedUp) {
          this.flushPoll();
        } else if (!this.batchTimer) {
          this.batchTimer = setTimeout(() => this.flushPoll(), HTTP_BATCH_DELAY_MS);
        }
      }
    },
    attachPoll(res) {
      this.markAlive();
      if (this.pollRes) {
        const oldRes = this.pollRes;
        this.pollRes = null;
        if (this.pollTimer) {
          clearTimeout(this.pollTimer);
          this.pollTimer = null;
        }
        if (this.batchTimer) {
          clearTimeout(this.batchTimer);
          this.batchTimer = null;
        }
        try {
          if (!oldRes.writableEnded) {
            const chaff = encryptEnvelope(this.crypto, INNER_CHAFF, Buffer.alloc(0));
            oldRes.writeHead(200, {
              'Content-Type': 'application/octet-stream',
              'Content-Length': chaff.length
            });
            oldRes.end(chaff);
          }
        } catch (e) {}
      }

      this.pollRes = res;
      res.on('close', () => {
        if (this.pollRes === res) {
          this.pollRes = null;
          if (this.pollTimer) {
            clearTimeout(this.pollTimer);
            this.pollTimer = null;
          }
          if (this.batchTimer) {
            clearTimeout(this.batchTimer);
            this.batchTimer = null;
          }
        }
      });

      if (this.queue.length > 0) {
        this.flushPoll();
        return;
      }

      this.pollTimer = setTimeout(() => {
        if (this.pollRes === res) {
          this.flushPoll();
        }
      }, HTTP_POLL_HOLD_MS);
    },
    sendJSON(obj) {
      if (this.closed) return;
      this.enqueue(INNER_JSON, Buffer.from(JSON.stringify(obj), 'utf8'), false);
    },
    sendBinary(buf, dropIfBackedUp = false) {
      if (this.closed) return;
      this.enqueue(INNER_BINARY, Buffer.isBuffer(buf) ? buf : Buffer.from(buf), dropIfBackedUp);
    },
    ping() {},
    close() {
      if (this.closed) return;
      this.closed = true;
      this.queue.length = 0;
      this.queuedBytes = 0;
      this.flushPoll();
    }
  };
  return client;
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
  if (client.handshakeTimer) {
    clearTimeout(client.handshakeTimer);
    client.handshakeTimer = null;
  }
  leaveRoom(client);
  clients.delete(client);
  if (client.sessionId) {
    sessionsById.delete(client.sessionId);
  }
  if (client.transport === 'http') {
    httpClients.delete(client.sessionId);
    client.queue.length = 0;
    client.queuedBytes = 0;
    client.flushPoll();
  } else if (client.socket) {
    try {
      if (!client.socket.destroyed) client.socket.destroy();
    } catch (e) {}
  }
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
  client.markAlive();
  let msg;
  try {
    msg = JSON.parse(text);
  } catch (e) {
    return;
  }

  if (msg.type === 'ping') {
    client.sendJSON({ type: 'pong', ts: msg.ts || Date.now() });
    return;
  }
  if (msg.type === 'pong') {
    return;
  }
  if (msg.type === 'close') {
    disconnectClient(client);
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

// Decrypted binary relay:
// Incoming: [kind(1: 1=video, 2=audio, 3=file), ...payload]
// Outgoing: [kind(1), peerIdLen(1), ...peerIdBytes, ...payload] (re-encrypted per recipient)
function handleBinaryMessage(client, data) {
  client.markAlive();
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

function handleDecryptedEnvelope(client, encryptedBuf) {
  const envelope = decryptEnvelope(client.crypto, encryptedBuf);
  if (!envelope) {
    return false;
  }
  client.markAlive();
  if (envelope.innerType === INNER_JSON) {
    handleTextMessage(client, envelope.payload.toString('utf8'));
  } else if (envelope.innerType === INNER_BINARY) {
    handleBinaryMessage(client, envelope.payload);
  }
  // INNER_CHAFF is intentionally ignored after authentication
  return true;
}

function readRequestBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    req.on('data', (chunk) => {
      if (settled) return;
      total += chunk.length;
      if (total > maxBytes) {
        settled = true;
        reject(Object.assign(new Error('Payload too large'), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks, total));
    });
    req.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });
  });
}

function authenticateHttpClient(parsed) {
  const sid = parsed.searchParams.get('s');
  if (!sid) return null;
  const client = httpClients.get(String(sid));
  if (!client || client.closed || !client.cryptoReady) return null;
  return client;
}

// ================= HEADLESS ENCRYPTED HTTP + WEBSOCKET SERVER =================
const server = http.createServer((req, res) => {
  applyCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (!isOriginAllowed(req.headers.origin)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  // Neutral status endpoint (also handles Render's / and /health checks without leaking app details)
  if (req.method === 'GET' && (parsed.pathname === '/' || parsed.pathname === '/health' || parsed.pathname === '/api/health' || parsed.pathname === '/v1/status')) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true,"v":2,"m":1}');
    return;
  }

  // ---- Encrypted HTTPS Long-Polling Fallback Endpoints ----
  // Opaque ECDH handshake + encrypted initial session state
  if (req.method === 'POST' && parsed.pathname === '/v1/sync') {
    readRequestBody(req, MAX_HANDSHAKE_BYTES)
      .then((buf) => {
        const hs = processClientHandshake(buf);
        if (!hs) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Bad Request');
          return;
        }
        const client = createHttpClient(hs.sessionCrypto);
        clients.add(client);
        sessionsById.set(client.sessionId, client);
        httpClients.set(client.sessionId, client);

        const initPayload = Buffer.from(JSON.stringify({
          peerId: client.id,
          sid: client.sessionId,
          rooms: getRoomList()
        }), 'utf8');
        const encInit = encryptEnvelope(client.crypto, INNER_JSON, initPayload);
        const body = buildHttpServerHello(hs.serverNonce, hs.serverPubRaw, encInit);
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': body.length
        });
        res.end(body);
      })
      .catch((err) => {
        if (!res.headersSent) {
          res.writeHead(err.statusCode || 400, { 'Content-Type': 'text/plain' });
          res.end('Bad Request');
        }
      });
    return;
  }

  // Encrypted long-poll downstream feed
  if (req.method === 'GET' && parsed.pathname === '/v1/feed') {
    const client = authenticateHttpClient(parsed);
    if (!client) {
      res.writeHead(401, { 'Content-Type': 'text/plain' });
      res.end('Unauthorized');
      return;
    }
    client.attachPoll(res);
    return;
  }

  // Encrypted upstream message push
  if (req.method === 'POST' && parsed.pathname === '/v1/push') {
    const client = authenticateHttpClient(parsed);
    if (!client) {
      res.writeHead(401, { 'Content-Type': 'text/plain' });
      res.end('Unauthorized');
      return;
    }
    readRequestBody(req, MAX_FRAME_BYTES)
      .then((buf) => {
        const ok = handleDecryptedEnvelope(client, buf);
        if (!ok) {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Bad Request');
          return;
        }
        res.writeHead(204);
        res.end();
      })
      .catch((err) => {
        if (!res.headersSent) {
          res.writeHead(err.statusCode || 400, { 'Content-Type': 'text/plain' });
          res.end('Bad Request');
        }
      });
    return;
  }

  // Encrypted tab-close disconnect beacon (called via navigator.sendBeacon for both WS & HTTP)
  if (req.method === 'POST' && parsed.pathname === '/v1/close') {
    const sid = parsed.searchParams.get('s');
    const client = sid ? sessionsById.get(String(sid)) : null;
    readRequestBody(req, 4096)
      .then((buf) => {
        if (client && !client.closed && client.cryptoReady) {
          const envelope = decryptEnvelope(client.crypto, buf);
          if (envelope && envelope.innerType === INNER_JSON) {
            try {
              const msg = JSON.parse(envelope.payload.toString('utf8'));
              if (msg && msg.type === 'close') {
                disconnectClient(client);
              }
            } catch (e) {}
          }
        }
        res.writeHead(204);
        res.end();
      })
      .catch(() => {
        if (!res.headersSent) {
          res.writeHead(204);
          res.end();
        }
      });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

// Render-recommended Node.js timeouts to prevent intermittent 502s behind Render's proxy
server.keepAliveTimeout = 120000;
server.headersTimeout = 125000;

server.on('upgrade', (req, socket, head) => {
  let client = null;
  const cleanup = () => {
    if (client) {
      disconnectClient(client);
    } else if (!socket.destroyed) {
      try { socket.destroy(); } catch (e) {}
    }
  };
  socket.on('error', cleanup);
  socket.on('close', cleanup);
  socket.on('end', cleanup);

  if (!isOriginAllowed(req.headers.origin)) {
    socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  if (parsed.pathname !== '/' && parsed.pathname !== '/ws' && parsed.pathname !== '/v1/stream') {
    socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  const upgradeHeader = String(req.headers.upgrade || '').toLowerCase();
  const key = req.headers['sec-websocket-key'];
  if (!key || upgradeHeader !== 'websocket') {
    socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  const accept = crypto.createHash('sha1').update(key.trim() + WS_GUID).digest('base64');
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 15000);
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );

  client = createWsClient(socket);
  client.handshakeTimer = setTimeout(() => {
    if (client && !client.cryptoReady) {
      disconnectClient(client);
    }
  }, HANDSHAKE_TIMEOUT_MS);

  let buffer = Buffer.alloc(0);
  let fragOpcode = 0;
  let fragChunks = [];

  function handleWsBinaryFrame(payload) {
    if (!client.cryptoReady) {
      const hs = processClientHandshake(payload);
      if (!hs) {
        disconnectClient(client);
        return;
      }
      if (client.handshakeTimer) {
        clearTimeout(client.handshakeTimer);
        client.handshakeTimer = null;
      }
      client.crypto = hs.sessionCrypto;
      client.cryptoReady = true;
      clients.add(client);
      sessionsById.set(client.sessionId, client);

      try {
        const serverHello = buildWsServerHello(hs.serverNonce, hs.serverPubRaw);
        socket.write(encodeFrame(0x2, serverHello));
        client.sendJSON({
          type: 'welcome',
          peerId: client.id,
          sid: client.sessionId,
          rooms: getRoomList()
        });
      } catch (e) {
        disconnectClient(client);
      }
      return;
    }

    if (!handleDecryptedEnvelope(client, payload)) {
      disconnectClient(client);
    }
  }

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

      const maxAllowed = client.cryptoReady ? MAX_FRAME_BYTES : MAX_HANDSHAKE_BYTES;
      if (len > maxAllowed) {
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
      client.markAlive();

      if (opcode === 0x8) {
        disconnectClient(client);
        return;
      } else if (opcode === 0x9) {
        try { socket.write(encodeFrame(0xA, payload)); } catch (e) {}
      } else if (opcode === 0xA) {
        // Pong already marked client alive
      } else if (opcode === 0x0) {
        if (fragOpcode) {
          fragChunks.push(payload);
          if (fin) {
            const full = Buffer.concat(fragChunks);
            const op = fragOpcode;
            fragOpcode = 0;
            fragChunks = [];
            if (op === 0x2) handleWsBinaryFrame(full);
            else {
              disconnectClient(client);
              return;
            }
          }
        }
      } else if (opcode === 0x2) {
        if (fin) {
          handleWsBinaryFrame(payload);
        } else {
          fragOpcode = opcode;
          fragChunks = [payload];
        }
      } else if (opcode === 0x1) {
        // Reject unencrypted text frames
        disconnectClient(client);
        return;
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
});

// Keep WebSockets alive behind proxies & clean up dead WS / HTTP polling clients
setInterval(() => {
  const now = Date.now();
  for (const c of Array.from(clients)) {
    if (c.transport === 'http') {
      if (!c.pollRes && (now - c.lastSeen) > HTTP_IDLE_TIMEOUT_MS) {
        disconnectClient(c);
      }
      continue;
    }
    if (!c.cryptoReady) continue;
    if (c.missedPings >= MAX_MISSED_PINGS) {
      disconnectClient(c);
      continue;
    }
    c.missedPings++;
    c.ping();
  }
}, HEARTBEAT_MS);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Encrypted relay server listening on port ${PORT}`);
});
