import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const HEARTBEAT_TTL_MS = 30_000; // expire presence if no heartbeat for 30s
const PRESENCE_PUSH_MS = 2000;   // how often to push presence updates

// --- in-memory stores (ok for demo) ---
const presenceByUuid = new Map();   // uuid -> { uuid, name, server, dimension, coords?, hasTracker, lastSeen }
const connections = new Map();      // ws -> { uuid, hasTracker }
const entitlements = new Map();     // uuid -> { tracker: { expMs } }  // dev-only issue

// --- express app (REST) ---
const app = express();
app.use(cors());
app.use(express.json());

// health
app.get('/health', (req,res)=>res.json({ok:true}));

// validate entitlement: ?mcUuid=...&token=...
app.get('/entitlements/validate', (req,res)=>{
  const { mcUuid, token } = req.query;
  if (!mcUuid || !token) return res.status(400).json({ valid:false, error:'missing params' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.sub !== mcUuid) return res.json({ valid:false, error:'uuid mismatch' });
    const now = Date.now();
    const scopes = payload.scopes || [];
    const expMs = payload.expMs || 0;
    const valid = now < expMs && scopes.includes('tracker');
    return res.json({ valid, scope: scopes, exp: expMs });
  } catch (e) {
    return res.json({ valid:false, error:'invalid token' });
  }
});

// dev-only: issue token (you’ll call this from your store/admin)
app.post('/entitlements/issue', (req,res)=>{
  const { mcUuid, days=365 } = req.body || {};
  if (!mcUuid) return res.status(400).json({ error:'mcUuid required' });
  const expMs = Date.now() + Number(days)*24*60*60*1000;
  const token = jwt.sign({ sub: mcUuid, scopes:['tracker'], expMs }, JWT_SECRET, { expiresIn: Math.ceil((expMs-Date.now())/1000) });
  // keep a simple record
  entitlements.set(mcUuid, { tracker: { expMs } });
  return res.json({ token, expMs });
});

// wallet credit stub (optional, for later)
app.post('/wallet/credit', (req,res)=>{
  // body: { mcUuid, delta, nonce, ts, server, target } + HMAC in a real impl
  console.log('wallet/credit', req.body);
  res.json({ ok:true });
});

// --- create HTTP + WS server ---
const server = createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

// helper: clean expired presence
function sweepPresence() {
  const now = Date.now();
  for (const [uuid, p] of presenceByUuid.entries()) {
    if (now - p.lastSeen > HEARTBEAT_TTL_MS) {
      presenceByUuid.delete(uuid);
    }
  }
}

// helper: send per-connection tailored presence (coords only if mutual tracker)
function pushPresence() {
  sweepPresence();
  for (const [ws, viewer] of connections.entries()) {
    if (ws.readyState !== ws.OPEN) continue;
    const players = [];
    for (const p of presenceByUuid.values()) {
      const base = {
        mcUuid: p.uuid,
        mcName: p.name,
        server: p.server,
        dimension: p.dimension,
        lastSeen: p.lastSeen,
        hasTracker: !!p.hasTracker
      };
      // coords visible only if viewer and target both have tracker
      if (viewer?.hasTracker && p.hasTracker && p.coords) {
        base.coords = p.coords;
      }
      players.push(base);
    }
    ws.send(JSON.stringify({ type:'presence', players }));
  }
}

setInterval(pushPresence, PRESENCE_PUSH_MS);

// --- WS protocol: hello + heartbeat ---
wss.on('connection', (ws)=>{
  console.log('WS connected');
  connections.set(ws, { uuid:null, hasTracker:false });

  ws.on('message', (data)=>{
    let msg;
    try { msg = JSON.parse(data); } catch { return; }

    if (msg.type === 'hello') {
      const { mcUuid, mcName, server, clientNonce, hasTracker=false } = msg;
      connections.set(ws, { uuid: mcUuid, hasTracker: !!hasTracker, clientNonce });
      presenceByUuid.set(mcUuid, {
        uuid: mcUuid,
        name: mcName,
        server,
        dimension: 'overworld',
        hasTracker: !!hasTracker,
        lastSeen: Date.now(),
      });
      ws.send(JSON.stringify({ type:'hello_ack', ok:true }));
      return;
    }

    if (msg.type === 'heartbeat') {
      const viewer = connections.get(ws);
      if (!viewer?.uuid) return;

      const p = presenceByUuid.get(viewer.uuid) || { uuid: viewer.uuid };
      p.server = msg.server || p.server;
      p.dimension = msg.dimension || p.dimension || 'overworld';
      p.hasTracker = !!viewer.hasTracker;

      // only record coords if client says it hasTracker and sent coords
      if (viewer.hasTracker && msg.coords && Number.isFinite(msg.coords.x) && Number.isFinite(msg.coords.y) && Number.isFinite(msg.coords.z)) {
        p.coords = { x:Number(msg.coords.x), y:Number(msg.coords.y), z:Number(msg.coords.z) };
      } else {
        delete p.coords;
      }

      p.lastSeen = Date.now();
      presenceByUuid.set(viewer.uuid, p);
      return;
    }

    if (msg.type === 'set_tracker_flag') {
      const viewer = connections.get(ws);
      if (!viewer) return;
      viewer.hasTracker = !!msg.hasTracker;
      connections.set(ws, viewer);
      const p = presenceByUuid.get(viewer.uuid);
      if (p) { p.hasTracker = viewer.hasTracker; presenceByUuid.set(viewer.uuid, p); }
      return;
    }
  });

  ws.on('close', ()=>{
    const viewer = connections.get(ws);
    if (viewer?.uuid) {
      // let heartbeat TTL clear it naturally; or delete immediately:
      // presenceByUuid.delete(viewer.uuid);
    }
    connections.delete(ws);
    console.log('WS disconnected');
  });
});

server.listen(PORT, ()=>console.log('HTTP+WS on :' + PORT));
