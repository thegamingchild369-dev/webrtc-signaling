const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: process.env.PORT || 3000 });

const rooms = {};

wss.on('connection', socket => {
  let roomId = null;

  socket.on('message', msg => {
    const data = JSON.parse(msg);

    if (data.join) {
      roomId = data.join;
      rooms[roomId] = rooms[roomId] || [];
      rooms[roomId].push(socket);
      return;
    }

    if (roomId && rooms[roomId]) {
      rooms[roomId].forEach(peer => {
        if (peer !== socket && peer.readyState === WebSocket.OPEN) {
          peer.send(JSON.stringify(data));
        }
      });
    }
  });

  socket.on('close', () => {
    if (roomId && rooms[roomId]) {
      rooms[roomId] = rooms[roomId].filter(p => p !== socket);
    }
  });
});

console.log("✅ Signaling server running");
