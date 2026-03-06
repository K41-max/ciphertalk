/**
 * CipherTalk v3 — Server
 *
 * 変更点:
 *  - 人数制限なし (1人でも複数人でも OK)
 *  - 各クライアントに一意の clientId を割り当て
 *  - メッセージは from/to フィールド付きで中継
 *  - 暗号化ペイロードはサーバーに不透明
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT       = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const FILE_TTL   = 10 * 60 * 1000;

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ── HTTP ──────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost`);

  // POST /api/file
  if (req.method === 'POST' && url.pathname === '/api/file') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const body  = JSON.parse(Buffer.concat(chunks).toString());
        const fileId = crypto.randomBytes(16).toString('hex');
        const record = { fileId, ...body, uploadedAt: Date.now() };
        const fp = path.join(UPLOAD_DIR, fileId + '.json');
        fs.writeFileSync(fp, JSON.stringify(record));
        setTimeout(() => { try { fs.unlinkSync(fp); } catch {} }, FILE_TTL);
        res.writeHead(200, jh()); res.end(JSON.stringify({ fileId }));
        // Notify room
        notifyRoom(body.roomId, null, { type:'file_available', fileId,
          filename:body.filename, mimeType:body.mimeType,
          size:body.size, senderName:body.senderName, senderId:body.senderId });
      } catch(e) { res.writeHead(400, jh()); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  // GET /api/file/:id
  if (req.method === 'GET' && url.pathname.startsWith('/api/file/')) {
    const fp = path.join(UPLOAD_DIR, url.pathname.split('/')[3] + '.json');
    if (!fs.existsSync(fp)) { res.writeHead(404, jh()); res.end(JSON.stringify({ error:'expired' })); return; }
    res.writeHead(200, jh()); res.end(fs.readFileSync(fp));
    return;
  }

  // Static files
  const reqPath = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\//, '');
  const fp      = path.resolve(path.join(__dirname, 'public', reqPath));
  const pub     = path.resolve(path.join(__dirname, 'public'));
  if (!fp.startsWith(pub)) { res.writeHead(403); res.end('Forbidden'); return; }
  const mime = { '.html':'text/html;charset=utf-8', '.js':'text/javascript',
    '.css':'text/css', '.ico':'image/x-icon' }[path.extname(fp)] || 'application/octet-stream';
  fs.readFile(fp, (err, data) => {
    if (err) {
      fs.readFile(path.join(__dirname, 'public', 'index.html'), (e2, html) => {
        if (e2) { res.writeHead(500); res.end('index.html missing'); return; }
        res.writeHead(200, { 'Content-Type':'text/html;charset=utf-8' }); res.end(html);
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': mime }); res.end(data);
  });
});

function jh() { return { 'Content-Type':'application/json', 'Access-Control-Allow-Origin':'*' }; }

// ── WebSocket ─────────────────────────────────────────────────────
const wss   = new WebSocketServer({ server });
// rooms: Map<roomId, Map<clientId, { ws, name }>>
const rooms = new Map();

wss.on('connection', ws => {
  ws.clientId = crypto.randomBytes(8).toString('hex');
  ws.roomId   = null;
  ws.name     = null;

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {

      case 'join': {
        const { room, name } = msg;
        if (!rooms.has(room)) rooms.set(room, new Map());
        const r = rooms.get(room);

        ws.roomId = room;
        ws.name   = name || 'User';
        r.set(ws.clientId, { ws, name: ws.name });

        // Tell this client their ID + list of existing members
        const members = [...r.entries()]
          .filter(([id]) => id !== ws.clientId)
          .map(([id, m]) => ({ id, name: m.name }));

        ws.send(js({ type:'joined', clientId: ws.clientId, room, members }));

        // Tell existing members someone joined
        broadcast(r, ws, { type:'peer_joined', clientId: ws.clientId, name: ws.name });
        log(`[${room}] "${ws.name}" joined (${r.size} total)`);
        break;
      }

      // Key exchange: targeted at a specific client
      case 'hello':      // new joiner → all: "here are my public keys"
      case 'room_key':   // existing → new joiner: "here is the room key (RSA-OAEP wrapped)"
      case 'chat':       // broadcast encrypted message
      case 'keyx_ack': {
        const r = rooms.get(ws.roomId);
        if (!r) break;
        // Add sender info
        msg.from = ws.clientId;
        msg.fromName = ws.name;
        if (msg.to) {
          // Targeted message
          const target = r.get(msg.to);
          if (target && target.ws.readyState === 1) target.ws.send(js(msg));
        } else {
          // Broadcast to all others
          broadcast(r, ws, msg);
        }
        break;
      }

      case 'leave':
        leaveRoom(ws);
        break;
    }
  });

  ws.on('close', () => leaveRoom(ws));
  ws.on('error', e => log(`[WS Error] ${e.message}`));
});

function broadcast(room, sender, msg) {
  const data = js(msg);
  for (const [, m] of room) {
    if (m.ws !== sender && m.ws.readyState === 1) m.ws.send(data);
  }
}

function notifyRoom(roomId, sender, msg) {
  const r = rooms.get(roomId);
  if (r) broadcast(r, sender, msg);
}

function leaveRoom(ws) {
  if (!ws.roomId) return;
  const r = rooms.get(ws.roomId);
  if (r) {
    r.delete(ws.clientId);
    broadcast(r, ws, { type:'peer_left', clientId: ws.clientId, name: ws.name });
    if (r.size === 0) rooms.delete(ws.roomId);
    log(`[${ws.roomId}] "${ws.name}" left (${r?.size ?? 0} remaining)`);
  }
  ws.roomId = null;
}

const js  = o => JSON.stringify(o);
const log = s => console.log(`[${new Date().toISOString().slice(11,19)}] ${s}`);

server.listen(PORT, () => {
  log(`CipherTalk v3 → http://localhost:${PORT}`);
  log(`人数制限なし | ECDHE + RSA-OAEP + RSA-PSS + AES-256-GCM`);
});
