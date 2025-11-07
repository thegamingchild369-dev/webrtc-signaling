const express = require('express');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const rooms = {};

// Health check
app.get('/', (req, res) => {
  res.send("✅ HTTP signaling server is running");
});

// Join a room
app.post('/join', (req, res) => {
  const { room, clientId } = req.body;
  if (!room || !clientId) {
    return res.status(400).json({ error: "Missing room or clientId" });
  }

  rooms[room] = rooms[room] || {};
  rooms[room][clientId] = [];

  const peers = Object.keys(rooms[room]).filter(id => id !== clientId);
  console.log(`📥 ${clientId} joined room ${room}, peers: ${peers.length}`);
  res.json({ peers });
});

// Send signaling data (SDP or ICE)
app.post('/signal', (req, res) => {
  const { room, to, from, data } = req.body;
  if (!room || !to || !from || !data) {
    return res.status(400).json({ error: "Missing signaling fields" });
  }

  if (rooms[room]?.[to]) {
    rooms[room][to].push({ from, data });
    console.log(`📡 Signal from ${from} to ${to} in room ${room}`);
  }
  res.sendStatus(200);
});

// Poll for incoming messages
app.post('/poll', (req, res) => {
  const { room, clientId } = req.body;
  if (!room || !clientId) {
    return res.status(400).json({ error: "Missing room or clientId" });
  }

  const messages = rooms[room]?.[clientId] || [];
  rooms[room][clientId] = [];
  res.json({ messages });
});

app.listen(port, () => {
  console.log(`✅ HTTP signaling server running on port ${port}`);
});
