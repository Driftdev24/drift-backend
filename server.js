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

// FIX: Removed conflicting wildcard CORS. Left security headers intact.
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
const rooms = new Map();
const turnTokens = new Map(); // Stores one-time tokens for ICE credential auth
const failedAttempts = new Map(); // Tracks failed join attempts by IP

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

// FIX: Secure ICE Credentials Endpoint
app.get('/api/ice-credentials', (req, res) => {
  const token = req.query.token;
  if (!token || !turnTokens.has(token)) {
    return res.status(401).json({ error: 'Unauthorized or expired token' });
  }

  // Generate time-limited credentials (Standard TURN REST API format)
  const TURN_SECRET = process.env.TURN_SECRET || 'fallback-secret-replace-me';
  const unixTimeStamp = Math.floor(Date.now() / 1000) + 24 * 3600; // 24-hour validity
  const username = `${unixTimeStamp}:drift-user`;
  
  const hmac = crypto.createHmac('sha1', TURN_SECRET);
  hmac.setEncoding('base64');
  hmac.write(username);
  hmac.end();
  const credential = hmac.read();

  // Revoke token after use
  turnTokens.delete(token);

  res.json({
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun.cloudflare.com:3478' },
      {
        urls: [
          "turn:free.expressturn.com:3478?transport=udp",
          "turn:free.expressturn.com:3478?transport=tcp"
        ],
        username: username,
        credential: credential
      }
    ],
    iceCandidatePoolSize: 10
  });
});

io.on('connection', (socket) => {
  const ip = socket.handshake.address;

  socket.on('create-room', ({ password }, callback) => {
    if (!password) return callback({ success: false });

    const id = generateSecureRoomId();
    const { hash, salt } = hashPassword(password);
    
    const timeoutId = setTimeout(() => { destroyRoom(id); }, 30 * 60 * 1000);
    rooms.set(id, { passwordHash: hash, salt: salt, timeoutId: timeoutId });
    
    // Generate auth token for TURN credentials
    const turnToken = crypto.randomBytes(32).toString('hex');
    turnTokens.set(turnToken, id);
    
    socket.join(id);
    socket.currentRoom = id;
    callback({ success: true, id, turnToken });
  });

  socket.on('join-room', ({ id, password }, callback) => {
    // FIX: Rate Limiting to prevent brute force
    const attempts = failedAttempts.get(ip) || { count: 0, lockedUntil: 0 };
    if (Date.now() < attempts.lockedUntil) {
        return callback({ success: false, error: 'Too many attempts. Try again later.' });
    }

    const normalizedId = (id || '').trim().toUpperCase();
    const room = rooms.get(normalizedId);

    if (!room || !verifyPassword(password, room.salt, room.passwordHash)) {
      attempts.count++;
      if (attempts.count >= 5) {
        attempts.lockedUntil = Date.now() + 60000; // Lock for 1 minute
      }
      failedAttempts.set(ip, attempts);
      return callback({ success: false, error: 'Invalid Room ID or Password' });
    }

    attempts.count = 0; // Reset on success
    failedAttempts.set(ip, attempts);

    // Generate auth token for TURN credentials
    const turnToken = crypto.randomBytes(32).toString('hex');
    turnTokens.set(turnToken, normalizedId);

    socket.join(normalizedId);
    socket.currentRoom = normalizedId;
    
    callback({ success: true, id: normalizedId, turnToken });
    socket.to(normalizedId).emit('peer-joined');
  });
  
  // --- ROBUST SIGNALING RELAYS ---
  socket.on('webrtc-offer', (offer) => socket.to(socket.currentRoom).emit('webrtc-offer', offer));
  socket.on('webrtc-answer', (answer) => socket.to(socket.currentRoom).emit('webrtc-answer', answer));
  socket.on('webrtc-ice', (candidate) => socket.to(socket.currentRoom).emit('webrtc-ice', candidate));

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
