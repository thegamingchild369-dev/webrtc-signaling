const express = require('express');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

/*
 rooms structure:
 {
   roomName: {
     clientId: {
       queue: [],    // queued signals
       lastSeen: ms  // last poll / join timestamp
     }
   }
 }
*/
const rooms = {};

// Cleanup interval (ms)
const CLEANUP_INTERVAL = 10000;
const TIMEOUT = 15000; // inactive client timeout (15s)

/* ========== HEALTH CHECK ========== */
app.get('/', (req, res) => {
  res.send("✅ HTTP signaling server is running");
});

/* ========== ROOM LIST ========== */
app.get('/rooms', (req, res) => {
  res.json({ rooms: Object.keys(rooms) });
});

/* ========== JOIN ROOM ========== */
app.post('/join', (req, res) => {
  const { room, clientId } = req.body;
  if (!room || !clientId) return res.status(400).json({ error: "Missing room or clientId" });

  rooms[room] = rooms[room] || {};
  rooms[room][clientId] = { queue: [], lastSeen: Date.now() };

  const peers = Object.keys(rooms[room]).filter(id => id !== clientId);

  console.log(`📥 ${clientId} joined room "${room}", peers now: ${peers.length}`);

  res.json({ peers });
});

/* ========== SEND SIGNALS ========== */
app.post('/signal', (req, res) => {
  const { room, to, from, data } = req.body;
  if (!room || !to || !from || !data) return res.status(400).json({ error: "Missing signaling fields" });

  if (rooms[room]?.[to]) {
    rooms[room][to].queue.push({ from, data });
    rooms[room][to].lastSeen = Date.now();
    rooms[room][from].lastSeen = Date.now();
    console.log(`📡 ${from} -> ${to} in "${room}"`);
  }

  res.sendStatus(200);
});

/* ========== POLL SIGNALS ========== */
app.post('/poll', (req, res) => {
  const { room, clientId } = req.body;
  if (!rooms[room] || !rooms[room][clientId]) return res.json({ messages: [] });

  rooms[room][clientId].lastSeen = Date.now();

  const messages = rooms[room][clientId].queue;
  rooms[room][clientId].queue = [];
  res.json({ messages });
});

/* ========== LEAVE ========== */
app.post('/leave', (req, res) => {
  const { room, clientId } = req.body;
  if (rooms[room]) {
    delete rooms[room][clientId];
    if (Object.keys(rooms[room]).length === 0) {
      delete rooms[room];
      console.log(`🗑 Room "${room}" removed (empty)`);
    } else {
      console.log(`👋 ${clientId} left room "${room}"`);
    }
  }
  res.sendStatus(200);
});

/* ========== AUTO CLEANUP ========== */
setInterval(() => {
  const now = Date.now();
  for (const room in rooms) {
    for (const client in rooms[room]) {
      if (now - rooms[room][client].lastSeen > TIMEOUT) {
        console.log(`⏱ Removing inactive client ${client} from "${room}"`);
        delete rooms[room][client];
      }
    }
    if (Object.keys(rooms[room]).length === 0) {
      console.log(`🗑 Auto-remove room "${room}" (all inactive)`);
      delete rooms[room];
    }
  }
}, CLEANUP_INTERVAL);

app.listen(port, () => {
  console.log(`✅ HTTP signaling server running on port ${port}`);
});
