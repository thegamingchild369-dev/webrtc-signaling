const express = require('express');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const rooms = {}; 
/*
rooms = {
  roomName: {
    clientId: {
      queue: [],       // stored signaling messages
      lastSeen: 0      // timestamp of last poll
    }
  }
}
*/

// Health check
app.get('/', (req,res)=>res.send("✅ Server Running"));

// Return list of rooms
app.get('/rooms', (req,res)=>{
  res.json({ rooms: Object.keys(rooms) });
});

// Join room
app.post('/join',(req,res)=>{
  const { room, clientId } = req.body;
  rooms[room] = rooms[room] || {};
  rooms[room][clientId] = { queue: [], lastSeen: Date.now() };

  const peers = Object.keys(rooms[room]).filter(id => id !== clientId);
  res.json({ peers });
});

// Signal relay
app.post('/signal',(req,res)=>{
  const { room, to, from, data } = req.body;
  if (rooms[room] && rooms[room][to]) {
    rooms[room][to].queue.push({ from, data });
  }
  res.sendStatus(200);
});

// Poll for data
app.post('/poll',(req,res)=>{
  const { room, clientId } = req.body;

  if (rooms[room] && rooms[room][clientId]) {
    rooms[room][clientId].lastSeen = Date.now(); // ✅ Update heartbeat
    const messages = rooms[room][clientId].queue;
    rooms[room][clientId].queue = [];
    return res.json({ messages });
  }
  res.json({ messages: [] });
});

// Leave room
app.post('/leave',(req,res)=>{
  const { room, clientId } = req.body;
  if (rooms[room]) {
    delete rooms[room][clientId];
    if (Object.keys(rooms[room]).length === 0) delete rooms[room];
  }
  res.sendStatus(200);
});

// ✅ Automatically remove stale users every 10 seconds
setInterval(() => {
  const now = Date.now();
  const timeout = 8000; // 8 seconds of no poll = client gone

  for (const room in rooms) {
    for (const clientId in rooms[room]) {
      if (now - rooms[room][clientId].lastSeen > timeout) {
        delete rooms[room][clientId]; // Remove ghost peer
      }
    }
    if (Object.keys(rooms[room]).length === 0) delete rooms[room]; // Remove empty room
  }
}, 10000);

app.listen(port,()=>console.log(`✅ Signaling server on ${port}`));
