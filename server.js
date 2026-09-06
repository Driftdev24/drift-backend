const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);

// Dynamic origin validation to support localhost, local IPs, and all Vercel preview URLs
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (!origin || 
          origin.startsWith('http://localhost') || 
          origin.startsWith('http://127.0.0.1') || 
          origin.startsWith('http://192.168.') || 
          origin.includes('vercel.app')) {
        callback(null, true);
      } else {
        callback(null, true); // Permissive for P2P signaling tunnel
      }
    },
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Standard security headers
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

const rooms = new Map();
const failedAttempts = new Map();

// Helper to provide robust STUN + dual-transport TURN configuration
function getIceServers() {
  const turnUser = process.env.TURN_USERNAME || "000000002103972211";
  const turnPass = process.env.TURN_CREDENTIAL || "Z3WQQwReDRX41Vl1sjRp9j/vFnI=";

  return [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' },
    {
      urls: [
        "turn:free.expressturn.com:3478?transport=udp",
        "turn:free.expressturn.com:3478?transport=tcp"
      ],
      username: turnUser,
      credential: turnPass
    }
  ];
}

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
  const ip = socket.handshake.address;

  socket.on('create-room', ({ password }, callback) => {
    if (!password) return callback({ success: false });

    const id = generateSecureRoomId();
    const { hash, salt } = hashPassword(password);
    
    const timeoutId = setTimeout(() => { destroyRoom(id); }, 30 * 60 * 1000);
    rooms.set(id, { passwordHash: hash, salt: salt, timeoutId: timeoutId });
    
    socket.join(id);
    socket.currentRoom = id;
    
    // Deliver ICE configuration directly through WebSocket
    callback({ 
      success: true, 
      id, 
      iceServers: getIceServers() 
    });
  });

  socket.on('join-room', ({ id, password }, callback) => {
    // Rate Limiting: 5 attempts per minute per IP
    const attempts = failedAttempts.get(ip) || { count: 0, lockedUntil: 0 };
    if (Date.now() < attempts.lockedUntil) {
      return callback({ success: false, error: 'Too many failed attempts. Locked for 1 minute.' });
    }

    const normalizedId = (id || '').trim().toUpperCase();
    const room = rooms.get(normalizedId);

    // 1. Authenticate Password
    if (!room || !verifyPassword(password, room.salt, room.passwordHash)) {
      attempts.count++;
      if (attempts.count >= 5) {
        attempts.lockedUntil = Date.now() + 60000;
      }
      failedAttempts.set(ip, attempts);
      return callback({ success: false, error: 'Invalid Room ID or Password' });
    }

    // 2. Enforce Strict 2-Peer Maximum Capacity
    const roomSockets = io.sockets.adapter.rooms.get(normalizedId);
    if (roomSockets && roomSockets.size >= 2) {
      return callback({ success: false, error: 'Access Denied: Room is already full (2/2).' });
    }

    // Reset attempts on success
    attempts.count = 0;
    failedAttempts.set(ip, attempts);

    socket.join(normalizedId);
    socket.currentRoom = normalizedId;
    
    // Deliver ICE configuration directly through WebSocket
    callback({ 
      success: true, 
      id: normalizedId, 
      iceServers: getIceServers() 
    });
    
    socket.to(normalizedId).emit('peer-joined');
  });
  
  // WebRTC Relays
  socket.on('webrtc-offer', (offer) => socket.to(socket.currentRoom).emit('webrtc-offer', offer));
  socket.on('webrtc-answer', (answer) => socket.to(socket.currentRoom).emit('webrtc-answer', answer));
  socket.on('webrtc-ice', (candidate) => socket.to(socket.currentRoom).emit('webrtc-ice', candidate));

  // Voice Call Relays
  socket.on('call-request', (data) => socket.to(socket.currentRoom).emit('call-request', data));
  socket.on('call-response', (data) => socket.to(socket.currentRoom).emit('call-response', data));
  socket.on('call-end', () => socket.to(socket.currentRoom).emit('call-end'));
  socket.on('call-offer', (offer) => socket.to(socket.currentRoom).emit('call-offer', offer));
  socket.on('call-answer', (answer) => socket.to(socket.currentRoom).emit('call-answer', answer));
  socket.on('call-ice', (candidate) => socket.to(socket.currentRoom).emit('call-ice', candidate));

  // Auto-Destruction Triggers
  socket.on('shred-room', () => {
    if (socket.currentRoom) destroyRoom(socket.currentRoom);
  });

  socket.on('disconnect', () => {
    if (socket.currentRoom) destroyRoom(socket.currentRoom);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => console.log(`Drift Secure Server running on port ${PORT}`));
