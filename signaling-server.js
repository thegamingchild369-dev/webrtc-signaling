const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: process.env.PORT || 3000 });

const rooms = {};

wss.on('connection', socket => {
  let roomId = null;
  let clientId = Math.random().toString(36).substr(2, 9);

  socket.on('message', msg => {
    const data = JSON.parse(msg);

    if (data.join) {
      roomId = data.join;
      rooms[roomId] = rooms[roomId] || {};
      rooms[roomId][clientId] = socket;

      // Notify new client of existing peers
      Object.keys(rooms[roomId]).forEach(id => {
        if (id !== clientId) {
          socket.send(JSON.stringify({ type: "peer", id }));
        }
      });

      // Notify existing peers of new client
      Object.entries(rooms[roomId]).forEach(([id, peer]) => {
        if (id !== clientId && peer.readyState === WebSocket.OPEN) {
          peer.send(JSON.stringify({ type: "peer", id: clientId }));
        }
      });

      return;
    }

    // Relay signaling messages
    if (data.to && rooms[roomId]?.[data.to]) {
      rooms[roomId][data.to].send(JSON.stringify({ ...data, from: clientId }));
    }
  });

  socket.on('close', () => {
    if (roomId && rooms[roomId]) {
      delete rooms[roomId][clientId];
    }
  });
});

console.log("✅ Signaling server running");
