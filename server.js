const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: [
      "https://drift-frontend-alpha.vercel.app", 
      "http://localhost:3000"
    ],
    methods: ["GET", "POST"],
    credentials: true
  }
});

app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Access-Control-Allow-Origin', '*'); 
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
const rooms = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

function verifyPassword(password, salt, storedHash) {
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash === storedHash;
}

function generateSecureRoomId() {
  return crypto.randomBytes(8).toString('hex').toUpperCase();
}

function destroyRoom(id) {
  const room = rooms.get(id);
  if (room) {
    clearTimeout(room.timeoutId);
    rooms.delete(id);
  }
  io.to(id).emit('room-shredded');
  io.in(id).socketsLeave(id);
}

io.on('connection', (socket) => {
  
  socket.on('create-room', ({ password }, callback) => {
    if (!password) return callback({ success: false });

    const id = generateSecureRoomId();
    const { hash, salt } = hashPassword(password);
    
    const timeoutId = setTimeout(() => { destroyRoom(id); }, 30 * 60 * 1000);
    rooms.set(id, { passwordHash: hash, salt: salt, timeoutId: timeoutId });
    
    socket.join(id);
    socket.currentRoom = id;
    callback({ success: true, id });
  });

  socket.on('join-room', ({ id, password }, callback) => {
    const normalizedId = (id || '').trim().toUpperCase();
    const room = rooms.get(normalizedId);

    if (!room || !verifyPassword(password, room.salt, room.passwordHash)) {
      return callback({ success: false });
    }

    socket.join(normalizedId);
    socket.currentRoom = normalizedId;
    
    callback({ success: true, id: normalizedId });
    
    // Notify the room creator that a peer has arrived
    socket.to(normalizedId).emit('peer-joined');
  });
  
  // --- ROBUST SIGNALING RELAYS ---
  socket.on('webrtc-offer', (offer) => {
    socket.to(socket.currentRoom).emit('webrtc-offer', offer);
  });

  socket.on('webrtc-answer', (answer) => {
    socket.to(socket.currentRoom).emit('webrtc-answer', answer);
  });

  socket.on('webrtc-ice', (candidate) => {
    socket.to(socket.currentRoom).emit('webrtc-ice', candidate);
  });

  socket.on('call-request', (data) => socket.to(socket.currentRoom).emit('call-request', data));
  socket.on('call-response', (data) => socket.to(socket.currentRoom).emit('call-response', data));
  socket.on('call-end', () => socket.to(socket.currentRoom).emit('call-end'));
  socket.on('call-offer', (offer) => socket.to(socket.currentRoom).emit('call-offer', offer));
  socket.on('call-answer', (answer) => socket.to(socket.currentRoom).emit('call-answer', answer));
  socket.on('call-ice', (candidate) => socket.to(socket.currentRoom).emit('call-ice', candidate));

  socket.on('shred-room', () => {
    if (socket.currentRoom) destroyRoom(socket.currentRoom);
  });

  socket.on('disconnect', () => {
    if (socket.currentRoom) destroyRoom(socket.currentRoom);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log(`Drift Secure Server running on port ${PORT}`));
