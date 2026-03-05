/**
 * CipherTalk v2 — Server
 *
 * 役割:
 *   1. 静的ファイル配信 (public/)
 *   2. WebSocket でメッセージを中継（暗号化済み。内容は不透明）
 *   3. REST API でファイルを一時保存・配信（暗号化済み。内容は不透明）
 *
 * サーバーは「配管」であり、平文を一切見ません。
 * 暗号化・復号・鍵交換はすべてブラウザ内（Web Crypto API）で実行されます。
 */

const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const { WebSocketServer } = require('ws');

const PORT          = process.env.PORT || 3000;
const UPLOAD_DIR    = path.join(__dirname, 'uploads');
const FILE_TTL_MS   = 10 * 60 * 1000; // 10 分でファイル自動削除

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ══════════════════════════════════════════
//  HTTP Server  (静的ファイル + REST API)
// ══════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // ── POST /api/file  (暗号化ファイルのアップロード) ──
  if (req.method === 'POST' && url.pathname === '/api/file') {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const fileId = crypto.randomBytes(16).toString('hex');
        const record = {
          fileId,
          roomId:      body.roomId,
          filename:    body.filename,
          mimeType:    body.mimeType,
          size:        body.size,
          iv:          body.iv,
          ciphertext:  body.ciphertext,
          wrappedKey:  body.wrappedKey,
          signature:   body.signature,
          senderName:  body.senderName,
          uploadedAt:  Date.now(),
        };
        const filePath = path.join(UPLOAD_DIR, fileId + '.json');
        fs.writeFileSync(filePath, JSON.stringify(record));

        setTimeout(() => { try { fs.unlinkSync(filePath); } catch {} }, FILE_TTL_MS);

        res.writeHead(200, jsonHeader());
        res.end(JSON.stringify({ fileId }));

        notifyRoom(body.roomId, null, {
          type:       'file_available',
          fileId,
          filename:   body.filename,
          mimeType:   body.mimeType,
          size:       body.size,
          senderName: body.senderName,
        });
      } catch (e) {
        res.writeHead(400, jsonHeader());
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // ── GET /api/file/:fileId  (暗号化ファイルのダウンロード) ──
  if (req.method === 'GET' && url.pathname.startsWith('/api/file/')) {
    const fileId = url.pathname.split('/')[3];
    const filePath = path.join(UPLOAD_DIR, fileId + '.json');
    if (!fs.existsSync(filePath)) {
      res.writeHead(404, jsonHeader());
      res.end(JSON.stringify({ error: 'not found or expired' }));
      return;
    }
    const record = fs.readFileSync(filePath, 'utf8');
    res.writeHead(200, jsonHeader());
    res.end(record);
    return;
  }

  // ── 静的ファイル配信 ──
  const reqPath  = url.pathname === '/' ? 'index.html' : url.pathname.replace(/^\//, '');
  const filePath = path.resolve(path.join(__dirname, 'public', reqPath));
  const publicDir = path.resolve(path.join(__dirname, 'public'));

  // ディレクトリトラバーサル防止
  if (!filePath.startsWith(publicDir)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  const ext = path.extname(filePath);
  const mime = {
    '.html': 'text/html; charset=utf-8',
    '.js':   'text/javascript',
    '.css':  'text/css',
    '.ico':  'image/x-icon',
    '.png':  'image/png',
    '.svg':  'image/svg+xml',
  }[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // ファイルが見つからない場合は index.html にフォールバック
      const indexPath = path.join(__dirname, 'public', 'index.html');
      log(`[STATIC] not found: ${filePath} → fallback index.html`);
      fs.readFile(indexPath, (err2, html) => {
        if (err2) {
          log(`[ERROR] public/index.html が見つかりません (${indexPath})`);
          res.writeHead(500); res.end('Server misconfiguration: public/index.html missing');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
});

function jsonHeader() {
  return { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' };
}

// ══════════════════════════════════════════
//  WebSocket — メッセージ中継
// ══════════════════════════════════════════
const wss = new WebSocketServer({ server });
const rooms = new Map();  // roomId -> { clients: Set<ws> }

wss.on('connection', (ws) => {
  ws.roomId   = null;
  ws.userName = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    switch (msg.type) {
      case 'join': {
        const { room, name } = msg;
        if (!rooms.has(room)) rooms.set(room, { clients: new Set() });
        const r = rooms.get(room);

        if (r.clients.size >= 2) {
          ws.send(js({ type: 'error', code: 'room_full' }));
          return;
        }

        r.clients.add(ws);
        ws.roomId   = room;
        ws.userName = name || 'Anonymous';

        const isInitiator = r.clients.size === 1;
        ws.send(js({ type: 'joined', initiator: isInitiator, peers: r.clients.size, room }));
        log(`[Room:${room}] "${ws.userName}" joined (${r.clients.size}/2)`);

        if (r.clients.size === 2) {
          broadcast(r, ws, { type: 'peer_joined', name: ws.userName });
        }
        break;
      }

      // 暗号化済みペイロードはそのまま転送
      case 'chat':
      case 'keyx':
      case 'keyx_ack': {
        const r = rooms.get(ws.roomId);
        if (r) broadcast(r, ws, msg);
        break;
      }

      case 'leave':
        leaveRoom(ws);
        break;
    }
  });

  ws.on('close', () => leaveRoom(ws));
  ws.on('error', (e) => log(`[WS Error] ${e.message}`));
});

function broadcast(room, sender, msg) {
  const data = js(msg);
  for (const client of room.clients) {
    if (client !== sender && client.readyState === 1) client.send(data);
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
    r.clients.delete(ws);
    broadcast(r, ws, { type: 'peer_left', name: ws.userName });
    if (r.clients.size === 0) rooms.delete(ws.roomId);
    log(`[Room:${ws.roomId}] "${ws.userName}" left`);
  }
  ws.roomId = null;
}

const js  = (o) => JSON.stringify(o);
const log = (s) => console.log(`[${new Date().toISOString().slice(11,19)}] ${s}`);

server.listen(PORT, () => {
  log(`CipherTalk v2 起動 → http://localhost:${PORT}`);
  log(`暗号化: ECDHE-P256 / RSA-OAEP / RSA-PSS / AES-256-GCM`);
});
