// Headless HTTPS polling & relay connection server for Whatsnap on Render.
// Uses 100% standard HTTP GET / POST / DELETE (no WebSockets, no SSE) so it works
// through strict Chromebook / school / corporate firewalls.
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const MAX_BODY_BYTES = 12 * 1024 * 1024; // 12 MB (supports up to 8 MB files base64-encoded)
const MAX_COVER_CHARS = 120 * 1024;      // ~120 KB compressed room cover data URL
const PLAYER_TIMEOUT_MS = 12000;         // Auto-remove players who stop polling for 12s

// rooms: Map<roomName, { cover: string | null, players: Map<playerId, Player> }>
const rooms = new Map();

function sanitizeRoomName(raw) {
  return String(raw || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
}

function sanitizeCover(rawCover) {
  if (typeof rawCover !== 'string') return null;
  if (!rawCover.startsWith('data:image/')) return null;
  if (rawCover.length > MAX_COVER_CHARS) return null;
  return rawCover;
}

function getRoomList() {
  return Array.from(rooms.entries())
    .map(([name, info]) => ({
      name,
      count: info.players.size,
      cover: info.cover || null
    }))
    .filter((r) => r.count > 0)
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

function totalPlayers() {
  let n = 0;
  for (const r of rooms.values()) n += r.players.size;
  return n;
}

function removePlayer(roomName, playerId) {
  const roomObj = rooms.get(roomName);
  if (!roomObj) return false;
  const removed = roomObj.players.delete(playerId);
  if (!removed) return false;

  for (const other of roomObj.players.values()) {
    other.queue.push({ type: 'peer-left', peerId: playerId });
    other.latestVideo.delete(playerId);
    if (other.queue.length > 200) other.queue.shift();
  }
  if (roomObj.players.size === 0) {
    rooms.delete(roomName);
  }
  return true;
}

function readJSONBody(req, maxBytes = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(Object.assign(new Error('Payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

// Sweep stale players who closed/lost connection without sending /leave
setInterval(() => {
  const now = Date.now();
  for (const [roomName, roomObj] of rooms.entries()) {
    for (const [playerId, player] of roomObj.players.entries()) {
      if (now - player.lastSeen > PLAYER_TIMEOUT_MS) {
        removePlayer(roomName, playerId);
      }
    }
  }
}, 4000);

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsed.pathname;

  try {
    // Health check (also wakes Render from sleep)
    if (req.method === 'GET' && (pathname === '/' || pathname === '/health' || pathname === '/api/health')) {
      return sendJSON(res, 200, {
        ok: true,
        service: 'whatsnap-server',
        transport: 'https-poll-v1',
        rooms: rooms.size,
        players: totalPlayers()
      });
    }

    // Active room list
    if (req.method === 'GET' && (pathname === '/rooms' || pathname === '/api/rooms')) {
      return sendJSON(res, 200, { rooms: getRoomList() });
    }

    // POST /api/rooms/:room/join
    const joinMatch = pathname.match(/^\/api\/rooms\/([^/]+)\/join$/);
    if (req.method === 'POST' && joinMatch) {
      const roomName = sanitizeRoomName(decodeURIComponent(joinMatch[1]));
      if (!roomName) return sendJSON(res, 400, { error: 'Invalid room name.' });

      const body = await readJSONBody(req, 256 * 1024);
      const name = String(body.name || 'User').trim().slice(0, 28) || 'User';
      const cover = sanitizeCover(body.cover);

      if (!rooms.has(roomName)) {
        rooms.set(roomName, { cover, players: new Map() });
      } else if (cover && !rooms.get(roomName).cover) {
        rooms.get(roomName).cover = cover;
      }

      const roomObj = rooms.get(roomName);
      const playerId = crypto.randomUUID();
      const peers = [];

      for (const [otherId, other] of roomObj.players.entries()) {
        peers.push({ peerId: otherId, name: other.name });
        other.queue.push({ type: 'peer-joined', peerId: playerId, name });
        if (other.queue.length > 200) other.queue.shift();
      }

      roomObj.players.set(playerId, {
        id: playerId,
        name,
        lastSeen: Date.now(),
        queue: [],
        audioQueue: [],
        latestVideo: new Map()
      });

      return sendJSON(res, 200, {
        playerId,
        room: roomName,
        peers,
        rooms: getRoomList()
      });
    }

    // DELETE /api/rooms/:room/players/:playerId  OR  POST /api/rooms/:room/players/:playerId/leave
    const leaveMatch = pathname.match(/^\/api\/rooms\/([^/]+)\/players\/([^/]+?)(?:\/leave)?$/);
    if (leaveMatch && (req.method === 'DELETE' || (req.method === 'POST' && pathname.endsWith('/leave')))) {
      const roomName = sanitizeRoomName(decodeURIComponent(leaveMatch[1]));
      const playerId = decodeURIComponent(leaveMatch[2]);
      removePlayer(roomName, playerId);
      return sendJSON(res, 200, { ok: true });
    }

    // GET /api/rooms/:room/players/:playerId/poll
    const pollMatch = pathname.match(/^\/api\/rooms\/([^/]+)\/players\/([^/]+)\/poll$/);
    if (req.method === 'GET' && pollMatch) {
      const roomName = sanitizeRoomName(decodeURIComponent(pollMatch[1]));
      const playerId = decodeURIComponent(pollMatch[2]);
      const roomObj = rooms.get(roomName);
      const player = roomObj?.players.get(playerId);
      if (!player) {
        return sendJSON(res, 404, { error: 'Player is not connected to this room.' });
      }

      player.lastSeen = Date.now();
      const messages = player.queue.splice(0, player.queue.length);
      const audio = player.audioQueue.splice(0, player.audioQueue.length);
      const video = [];
      for (const [fromId, frameData] of player.latestVideo.entries()) {
        video.push({ from: fromId, data: frameData });
      }
      player.latestVideo.clear();

      return sendJSON(res, 200, {
        messages,
        audio,
        video,
        rooms: getRoomList()
      });
    }

    // POST /api/rooms/:room/players/:playerId/send
    const sendMatch = pathname.match(/^\/api\/rooms\/([^/]+)\/players\/([^/]+)\/send$/);
    if (req.method === 'POST' && sendMatch) {
      const roomName = sanitizeRoomName(decodeURIComponent(sendMatch[1]));
      const playerId = decodeURIComponent(sendMatch[2]);
      const roomObj = rooms.get(roomName);
      const player = roomObj?.players.get(playerId);
      if (!player) {
        return sendJSON(res, 404, { error: 'Player is not connected to this room.' });
      }

      player.lastSeen = Date.now();
      const body = await readJSONBody(req, MAX_BODY_BYTES);

      // Media batch (video latest-wins + audio chunks)
      if (typeof body.video === 'string' && body.video.length <= 200 * 1024) {
        for (const [otherId, other] of roomObj.players.entries()) {
          if (otherId !== playerId) {
            other.latestVideo.set(playerId, body.video);
          }
        }
      }

      if (Array.isArray(body.audio) && body.audio.length) {
        for (const chunk of body.audio.slice(-4)) {
          if (typeof chunk !== 'string' || chunk.length > 64 * 1024) continue;
          for (const [otherId, other] of roomObj.players.entries()) {
            if (otherId !== playerId) {
              other.audioQueue.push({ from: playerId, data: chunk });
              if (other.audioQueue.length > 8) other.audioQueue.shift();
            }
          }
        }
      }

      // Chat text message
      if (body.type === 'chat') {
        const clean = String(body.text || '').trim().slice(0, 1000);
        if (clean) {
          for (const [otherId, other] of roomObj.players.entries()) {
            if (otherId !== playerId) {
              other.queue.push({ type: 'chat', from: playerId, name: player.name, text: clean });
              if (other.queue.length > 200) other.queue.shift();
            }
          }
        }
      }

      // File / image / video / audio attachment
      if (body.type === 'file' && typeof body.data === 'string') {
        const fileName = String(body.name || 'file').slice(0, 180);
        const mime = String(body.mime || 'application/octet-stream').slice(0, 120);
        const size = Number.isFinite(body.size) ? body.size : 0;
        for (const [otherId, other] of roomObj.players.entries()) {
          if (otherId !== playerId) {
            other.queue.push({
              type: 'file',
              from: playerId,
              sender: player.name,
              name: fileName,
              mime,
              size,
              data: body.data
            });
            if (other.queue.length > 200) other.queue.shift();
          }
        }
      }

      return sendJSON(res, 200, { ok: true });
    }

    return sendJSON(res, 404, { error: 'Not found' });
  } catch (err) {
    return sendJSON(res, err.status || 500, { error: err.message || 'Server error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Whatsnap HTTPS connection server listening on port ${PORT}`);
});
