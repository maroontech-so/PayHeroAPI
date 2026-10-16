require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// SECURITY: Trust proxy (Render runs behind a load balancer)
// ============================================================
app.set('trust proxy', 1);
app.disable('x-powered-by');

// ============================================================
// SECURITY: Helmet with CSP for inline handlers
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: [
        "'self'",
        "https://api.payhero.co.ke",
        "https://backend.payhero.co.ke",
        "https://cdn.jsdelivr.net",
      ],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// ============================================================
// SECURITY: CORS with wildcard subdomain support
// ============================================================
const rawOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : ['https://payheroapi.onrender.com'];

const allowAllOrigins = rawOrigins.includes('*');
const exactOrigins = new Set();
const wildcardSuffixes = [];

for (const o of rawOrigins) {
  if (o === '*') continue;
  if (o.startsWith('*.')) {
    wildcardSuffixes.push(o.slice(1).toLowerCase());
  } else {
    exactOrigins.add(o.toLowerCase());
  }
}

function isOriginAllowed(origin) {
  if (!origin) return true;
  if (allowAllOrigins) return true;
  const lower = origin.toLowerCase();
  if (exactOrigins.has(lower)) return true;
  for (const suffix of wildcardSuffixes) {
    if (lower.endsWith(suffix)) return true;
  }
  return false;
}

app.use(cors({
  origin: (origin, callback) => {
    if (isOriginAllowed(origin)) return callback(null, true);
    console.warn('CORS blocked origin:', origin);
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-token', 'x-api-key', 'idempotency-key'],
  maxAge: 86400,
}));

// Express 5-safe preflight handler (no '*path' string)
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    return cors()(req, res, next);
  }
  next();
});

// ============================================================
// SECURITY: Body size limits
// ============================================================
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
  etag: true,
}));

// ============================================================
// ERROR HANDLING: Custom Error Class
// ============================================================
class AppError extends Error {
  constructor(message, statusCode = 500, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}

// ============================================================
// SMALL UTILITIES
// ============================================================
function withTimeout(promise, ms, label = 'operation') {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)
    ),
  ]);
}

function safeJsonParse(str, fallback = null) {
  try { return JSON.parse(str); } catch { return fallback; }
}

// ============================================================
// VALIDATE REQUIRED ENV
// ============================================================
const REQUIRED_ENV = ['ADMIN_PASSWORD', 'PAYHERO_API_USERNAME', 'PAYHERO_API_PASSWORD'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingEnv.length) {
  console.error(`FATAL: Missing required environment variables: ${missingEnv.join(', ')}`);
  // Don't exit — let Render show the error in /health, but log loudly.
}

// ============================================================
// LOCAL SQLITE BUFFER
// ============================================================
const DB_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const LOCAL_DB_PATH = path.join(DB_DIR, 'buffer.db');

const local = new Database(LOCAL_DB_PATH);
local.pragma('journal_mode = WAL');
local.pragma('synchronous = NORMAL');
local.pragma('foreign_keys = ON');
local.pragma('busy_timeout = 5000');

function initLocalSchema() {
  local.exec(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_hash TEXT UNIQUE NOT NULL,
      key_preview TEXT,
      name TEXT,
      app_identifier TEXT,
      channel_id TEXT,
      webhook_url TEXT,
      webhook_secret TEXT,
      rate_limit_per_min INTEGER DEFAULT 100,
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      last_used_at TEXT,
      expires_at TEXT
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_reference TEXT UNIQUE,
      app_identifier TEXT,
      payhero_reference TEXT,
      mpesa_receipt TEXT,
      channel_id TEXT,
      phone_number TEXT,
      amount REAL,
      status TEXT DEFAULT 'pending',
      callback_payload TEXT,
      verified_with_payhero INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS request_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      api_key_id INTEGER,
      app_identifier TEXT,
      endpoint TEXT,
      method TEXT,
      status_code INTEGER,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS callback_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_reference TEXT,
      raw_payload TEXT,
      verified INTEGER DEFAULT 0,
      source_ip TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_txn_ext_ref ON transactions(external_reference);
    CREATE INDEX IF NOT EXISTS idx_txn_payhero_ref ON transactions(payhero_reference);
    CREATE INDEX IF NOT EXISTS idx_txn_mpesa_ref ON transactions(mpesa_receipt);
    CREATE INDEX IF NOT EXISTS idx_txn_status ON transactions(status);
    CREATE INDEX IF NOT EXISTS idx_log_created ON request_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_callback_ext_ref ON callback_log(external_reference);
    CREATE INDEX IF NOT EXISTS idx_callback_verified ON callback_log(verified);
  `);
  console.log('Local DB schema ready');
}

initLocalSchema();

// ============================================================
// TURSO CLOUD (durability layer)
// ============================================================
let turso = null;
let tursoReady = false;
const tursoWriteQueue = [];
let tursoFlushing = false;
const MAX_QUEUE = 5000;

function makeTursoClient() {
  return createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
  });
}

if (process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN) {
  try {
    turso = makeTursoClient();
  } catch (e) {
    console.error('Turso client init failed:', e.message);
  }
} else {
  console.warn('Turso credentials missing — running in local-only mode');
}

async function initTursoSchema() {
  if (!turso) return;
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_hash TEXT UNIQUE NOT NULL,
      key_preview TEXT,
      name TEXT,
      app_identifier TEXT,
      channel_id TEXT,
      webhook_url TEXT,
      webhook_secret TEXT,
      rate_limit_per_min INTEGER DEFAULT 100,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_used_at DATETIME,
      expires_at DATETIME
    )
  `);
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_reference TEXT UNIQUE,
      app_identifier TEXT,
      payhero_reference TEXT,
      mpesa_receipt TEXT,
      channel_id TEXT,
      phone_number TEXT,
      amount REAL,
      status TEXT DEFAULT 'pending',
      callback_payload TEXT,
      verified_with_payhero INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS request_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      api_key_id INTEGER,
      app_identifier TEXT,
      endpoint TEXT,
      method TEXT,
      status_code INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS callback_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_reference TEXT,
      raw_payload TEXT,
      verified INTEGER DEFAULT 0,
      source_ip TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

async function executeWithRetry(sql, args, label = 'turso') {
  if (!turso) return false;

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await withTimeout(
        turso.execute({ sql, args: args || [] }),
        10000,
        `${label} execute`
      );
      return true;
    } catch (e) {
      console.error(`Turso ${label} attempt ${attempt + 1} failed:`, e.message);
      if (attempt === 0) {
        // Recreate client on first failure
        try {
          turso = makeTursoClient();
        } catch (re) {
          console.error('Turso client recreation failed:', re.message);
          return false;
        }
      } else {
        return false;
      }
    }
  }
  return false;
}

function syncToTurso(sql, args = []) {
  if (!turso) return;
  if (!tursoReady) {
    tursoWriteQueue.push({ sql, args });
    if (tursoWriteQueue.length > MAX_QUEUE) tursoWriteQueue.shift();
    return;
  }
  executeWithRetry(sql, args).catch((e) => {
    console.error('Turso sync error:', e.message);
  });
}

async function flushTursoQueue() {
  if (tursoFlushing || !tursoReady || !turso) return;
  tursoFlushing = true;
  let flushed = 0;
  try {
    while (tursoWriteQueue.length > 0) {
      const item = tursoWriteQueue[0];
      const ok = await executeWithRetry(item.sql, item.args);
      if (!ok) break;
      tursoWriteQueue.shift();
      flushed++;
    }
    if (flushed > 0) {
      console.log(`Flushed ${flushed} queued Turso writes`);
    }
  } finally {
    tursoFlushing = false;
  }
}

async function hydrateFromTurso() {
  if (!turso) {
    console.log('No Turso — skipping hydration');
    return;
  }

  try {
    await initTursoSchema();
    tursoReady = true;
    console.log('Turso schema ready');

    // Pull API keys
    const remoteKeys = await withTimeout(turso.execute('SELECT * FROM api_keys'), 20000, 'turso pull keys');
    const insertKey = local.prepare(`
      INSERT OR IGNORE INTO api_keys
      (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min, is_active, created_at, last_used_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let keyCount = 0;
    const insertKeysTx = local.transaction((rows) => {
      for (const k of rows) {
        const info = insertKey.run(
          k.key_hash, k.key_preview, k.name, k.app_identifier,
          k.channel_id, k.webhook_url || null, k.webhook_secret || null,
          k.rate_limit_per_min || 100, k.is_active, k.created_at, k.last_used_at, k.expires_at || null
        );
        if (info.changes) keyCount++;
      }
    });
    insertKeysTx(remoteKeys.rows);

    // Pull transactions
    const remoteTxns = await withTimeout(turso.execute('SELECT * FROM transactions'), 20000, 'turso pull txns');
    const insertTxn = local.prepare(`
      INSERT OR IGNORE INTO transactions
      (external_reference, app_identifier, payhero_reference, mpesa_receipt, channel_id,
       phone_number, amount, status, callback_payload, verified_with_payhero, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let txnCount = 0;
    const insertTxnsTx = local.transaction((rows) => {
      for (const t of rows) {
        const info = insertTxn.run(
          t.external_reference, t.app_identifier, t.payhero_reference,
          t.mpesa_receipt || null, t.channel_id, t.phone_number, t.amount, t.status,
          t.callback_payload, t.verified_with_payhero || 0, t.created_at, t.updated_at
        );
        if (info.changes) txnCount++;
      }
    });
    insertTxnsTx(remoteTxns.rows);

    // Push any local keys/transactions that aren't yet in Turso
    const localKeys = local.prepare('SELECT * FROM api_keys').all();
    for (const k of localKeys) {
      await executeWithRetry(
        `INSERT OR IGNORE INTO api_keys
         (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min, is_active, created_at, last_used_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [k.key_hash, k.key_preview, k.name, k.app_identifier, k.channel_id,
         k.webhook_url, k.webhook_secret, k.rate_limit_per_min, k.is_active,
         k.created_at, k.last_used_at, k.expires_at]
      );
    }

    const localTxns = local.prepare('SELECT * FROM transactions').all();
    for (const t of localTxns) {
      await executeWithRetry(
        `INSERT OR IGNORE INTO transactions
         (external_reference, app_identifier, payhero_reference, mpesa_receipt, channel_id,
          phone_number, amount, status, callback_payload, verified_with_payhero, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [t.external_reference, t.app_identifier, t.payhero_reference, t.mpesa_receipt,
         t.channel_id, t.phone_number, t.amount, t.status, t.callback_payload,
         t.verified_with_payhero, t.created_at, t.updated_at]
      );
    }

    console.log(`Hydrated from Turso: +${keyCount} keys, +${txnCount} transactions`);

    // Flush any writes queued during hydration
    await flushTursoQueue();
  } catch (e) {
    console.error('Hydration failed:', e.message);
    console.log('Continuing with local-only data');
    tursoReady = true; // still allow queue to drain
  }
}

// ============================================================
// READY GATE — block API routes until hydration done
// ============================================================
let appReady = false;

function requireReady(req, res, next) {
  if (appReady) return next();
  res.set('Retry-After', '5');
  return res.status(503).json({
    error: 'Service warming up',
    message: 'Server is initializing. Please retry in a few seconds.',
  });
}

// ============================================================
// HELPERS
// ============================================================
function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function generateApiKey() {
  return 'phk_' + crypto.randomBytes(32).toString('hex');
}

function generateWebhookSecret() {
  return 'whsec_' + crypto.randomBytes(32).toString('hex');
}

function getPayHeroAuthHeader() {
  const u = process.env.PAYHERO_API_USERNAME;
  const p = process.env.PAYHERO_API_PASSWORD;
  if (!u || !p) {
    throw new AppError('PayHero credentials not configured', 500, false);
  }
  const credentials = Buffer.from(`${u}:${p}`).toString('base64');
  return `Basic ${credentials}`;
}

function signWebhookPayload(secret, payload) {
  if (!secret) return null;
  return crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
}

function normalizeStatus(raw) {
  const v = String(raw || '').toLowerCase().trim();
  if (['success', 'successful', 'complete', 'completed', 'paid', '1'].includes(v)) return 'success';
  if (v.includes('fail') || v.includes('cancel') || v === '0' || v === 'rejected') return 'failed';
  if (v.includes('pending') || v.includes('process') || v === '2') return 'pending';
  return 'unknown';
}

function logRequest(apiKeyRecord, req, statusCode) {
  try {
    local.prepare(
      `INSERT INTO request_log (api_key_id, app_identifier, endpoint, method, status_code)
       VALUES (?, ?, ?, ?, ?)`
    ).run(
      apiKeyRecord ? apiKeyRecord.id : null,
      apiKeyRecord ? apiKeyRecord.app_identifier : null,
      req.path,
      req.method,
      statusCode
    );
    syncToTurso(
      `INSERT INTO request_log (api_key_id, app_identifier, endpoint, method, status_code)
       VALUES (?, ?, ?, ?, ?)`,
      [apiKeyRecord ? apiKeyRecord.id : null, apiKeyRecord ? apiKeyRecord.app_identifier : null,
       req.path, req.method, statusCode]
    );
  } catch (e) {
    console.error('Log error:', e.message);
  }
}

// ============================================================
// SECURITY: Per-key rate limiter
// ============================================================
const keyRateLimits = new Map();

function checkKeyRateLimit(keyRecord) {
  const now = Date.now();
  const limit = keyRecord.rate_limit_per_min || 100;
  const entry = keyRateLimits.get(keyRecord.id) || { count: 0, resetAt: now + 60000 };

  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + 60000;
  }

  entry.count++;
  keyRateLimits.set(keyRecord.id, entry);

  return {
    allowed: entry.count <= limit,
    remaining: Math.max(0, limit - entry.count),
    reset: entry.resetAt,
  };
}

// Periodic cleanup of stale rate-limit entries (prevents memory leak)
setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of keyRateLimits.entries()) {
    if (now > entry.resetAt + 300000) keyRateLimits.delete(id);
  }
}, 60000);

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;

  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  const keyHash = hashKey(apiKey);
  const keyRecord = local
    .prepare('SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1')
    .get(keyHash);

  if (!keyRecord) {
    logRequest(null, req, 403);
    return res.status(403).json({ error: 'Invalid or inactive API key' });
  }

  if (keyRecord.expires_at && new Date(keyRecord.expires_at) < new Date()) {
    logRequest(keyRecord, req, 403);
    return res.status(403).json({ error: 'API key expired' });
  }

  const rate = checkKeyRateLimit(keyRecord);
  res.set('X-RateLimit-Limit', String(keyRecord.rate_limit_per_min || 100));
  res.set('X-RateLimit-Remaining', String(rate.remaining));

  if (!rate.allowed) {
    logRequest(keyRecord, req, 429);
    return res.status(429).json({ error: 'Rate limit exceeded for this API key' });
  }

  try {
    local.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?").run(keyRecord.id);
    syncToTurso("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?", [keyRecord.id]);
  } catch (e) {
    console.error('last_used_at update failed:', e.message);
  }

  req.apiKeyRecord = keyRecord;
  next();
}

function adminAuth(req, res, next) {
  const adminToken = req.headers['x-admin-token'] || req.query.admin_token;
  const expected = process.env.ADMIN_PASSWORD;

  if (!expected) {
    return res.status(500).json({ error: 'Admin password not configured' });
  }

  const provided = Buffer.from(String(adminToken || ''));
  const correct = Buffer.from(String(expected));

  if (provided.length !== correct.length || !crypto.timingSafeEqual(provided, correct)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}

// ============================================================
// HEALTH CHECK (always available, even before ready)
// ============================================================
app.get('/health', (req, res) => {
  res.status(200).json({
    status: appReady ? 'ok' : 'warming_up',
    turso: tursoReady ? 'connected' : 'local-only',
    queue: tursoWriteQueue.length,
    timestamp: new Date().toISOString(),
  });
});

// ============================================================
// ADMIN ROUTES
// ============================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { password } = req.body || {};

  if (!process.env.ADMIN_PASSWORD) {
    return res.status(500).json({ error: 'Admin password not configured' });
  }

  const provided = Buffer.from(String(password || ''));
  const correct = Buffer.from(String(process.env.ADMIN_PASSWORD));

  if (provided.length === correct.length && crypto.timingSafeEqual(provided, correct)) {
    return res.json({ success: true });
  }
  res.status(403).json({ error: 'Invalid password' });
});

app.get('/api/admin/keys', requireReady, adminAuth, (req, res) => {
  try {
    const rows = local.prepare(
      `SELECT id, key_preview, name, app_identifier, channel_id, webhook_url,
              rate_limit_per_min, is_active, created_at, last_used_at, expires_at
       FROM api_keys ORDER BY created_at DESC`
    ).all();
    res.json(rows);
  } catch (e) {
    console.error('List keys error:', e);
    res.status(500).json({ error: 'Failed to list keys' });
  }
});

app.post('/api/admin/keys', requireReady, adminAuth, async (req, res, next) => {
  try {
    const { name, app_identifier, channel_id, webhook_url, rate_limit_per_min } = req.body || {};

    if (!name || !channel_id) {
      return res.status(400).json({ error: 'Name and Channel ID are required' });
    }

    if (!/^[a-zA-Z0-9_-]{1,50}$/.test(channel_id)) {
      return res.status(400).json({ error: 'Invalid channel_id format' });
    }

    if (webhook_url && !/^https?:\/\//i.test(webhook_url)) {
      return res.status(400).json({ error: 'webhook_url must start with http:// or https://' });
    }

    let rl = parseInt(rate_limit_per_min, 10);
    if (!Number.isFinite(rl) || rl < 1 || rl > 10000) rl = 100;

    const newKey = generateApiKey();
    const keyHash = hashKey(newKey);
    const preview = newKey.slice(0, 12) + '...' + newKey.slice(-4);
    const webhookSecret = webhook_url ? generateWebhookSecret() : null;

    // 1. Write locally first — this is our source of truth
    try {
      local.prepare(
        `INSERT INTO api_keys (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(keyHash, preview, name, app_identifier || name, channel_id, webhook_url || null, webhookSecret, rl);
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) {
        return res.status(409).json({ error: 'Key collision — please retry' });
      }
      throw e;
    }

    // 2. Queue Turso persistence (non-blocking — local write already succeeded)
    const keyArgs = [keyHash, preview, name, app_identifier || name, channel_id, webhook_url || null, webhookSecret, rl];
    const keySql = `INSERT OR IGNORE INTO api_keys (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;

    if (tursoReady && turso) {
      // Try synchronously but with timeout; if it fails, fall back to queue
      const ok = await executeWithRetry(keySql, keyArgs, 'create key');
      if (!ok) {
        console.warn('Turso persist failed; queueing key for retry:', preview);
        tursoWriteQueue.push({ sql: keySql, args: keyArgs });
      }
    } else {
      tursoWriteQueue.push({ sql: keySql, args: keyArgs });
      console.log(`Queued key creation (Turso not ready): ${preview}`);
    }

    res.json({
      api_key: newKey,
      webhook_secret: webhookSecret,
      message: 'Store these securely. They will not be shown again.',
      name,
      channel_id,
    });
  } catch (e) {
    console.error('Create key error:', e);
    next(e);
  }
});

app.patch('/api/admin/keys/:id/revoke', requireReady, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    local.prepare('UPDATE api_keys SET is_active = 0 WHERE id = ?').run(id);
    syncToTurso('UPDATE api_keys SET is_active = 0 WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to revoke key' });
  }
});

app.patch('/api/admin/keys/:id/activate', requireReady, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    local.prepare('UPDATE api_keys SET is_active = 1 WHERE id = ?').run(id);
    syncToTurso('UPDATE api_keys SET is_active = 1 WHERE id = ?', [id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to activate key' });
  }
});

app.delete('/api/admin/keys/:id', requireReady, adminAuth, (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    const row = local.prepare('SELECT key_hash FROM api_keys WHERE id = ?').get(id);
    local.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
    if (row) {
      syncToTurso('DELETE FROM api_keys WHERE key_hash = ?', [row.key_hash]);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete key' });
  }
});

app.post('/api/admin/keys/verify', requireReady, adminAuth, (req, res) => {
  try {
    const { api_key } = req.body || {};
    if (!api_key) return res.status(400).json({ error: 'api_key required' });

    const keyHash = hashKey(api_key);
    const k = local
      .prepare('SELECT id, name, channel_id, is_active, expires_at FROM api_keys WHERE key_hash = ?')
      .get(keyHash);

    if (!k) {
      return res.json({ valid: false, reason: 'Key not found' });
    }

    if (k.expires_at && new Date(k.expires_at) < new Date()) {
      return res.json({ valid: false, reason: 'Key expired' });
    }

    res.json({
      valid: k.is_active === 1,
      name: k.name,
      channel_id: k.channel_id,
      active: k.is_active === 1,
    });
  } catch (e) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.get('/api/admin/stats', requireReady, adminAuth, (req, res) => {
  try {
    const keys = local.prepare('SELECT COUNT(*) as c, COALESCE(SUM(is_active),0) as active FROM api_keys').get();
    const txns = local.prepare('SELECT COUNT(*) as c FROM transactions').get();
    const revenue = local.prepare("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE status = 'success'").get();
    const recent = local.prepare("SELECT COUNT(*) as c FROM transactions WHERE created_at >= datetime('now', '-24 hours')").get();
    const successCount = local.prepare("SELECT COUNT(*) as c FROM transactions WHERE status = 'success'").get();
    const pendingCount = local.prepare("SELECT COUNT(*) as c FROM transactions WHERE status = 'pending'").get();
    const failedCount = local.prepare("SELECT COUNT(*) as c FROM transactions WHERE status = 'failed'").get();
    const unverifiedCallbacks = local.prepare("SELECT COUNT(*) as c FROM callback_log WHERE verified = 0").get();

    res.json({
      total_keys: keys.c,
      active_keys: keys.active || 0,
      total_transactions: txns.c,
      recent_transactions: recent.c,
      total_revenue: revenue.total,
      success_count: successCount.c,
      pending_count: pendingCount.c,
      failed_count: failedCount.c,
      unverified_callbacks: unverifiedCallbacks.c,
    });
  } catch (e) {
    console.error('Stats error:', e);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/api/admin/transactions', requireReady, adminAuth, (req, res) => {
  try {
    const { status, limit = 50, offset = 0 } = req.query;
    let sql = 'SELECT * FROM transactions';
    const args = [];

    if (status && status !== 'all') {
      sql += ' WHERE status = ?';
      args.push(status);
    }

    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    const lim = Math.min(parseInt(limit, 10) || 50, 500);
    const off = Math.max(parseInt(offset, 10) || 0, 0);
    args.push(lim, off);

    const rows = local.prepare(sql).all(...args);
    res.json(rows);
  } catch (e) {
    console.error('Transactions error:', e);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/admin/charts', requireReady, adminAuth, (req, res) => {
  try {
    const daily = local.prepare(`
      SELECT date(created_at) as day, COUNT(*) as count,
             COALESCE(SUM(CASE WHEN status='success' THEN amount ELSE 0 END), 0) as revenue
      FROM transactions
      WHERE created_at >= datetime('now', '-7 days')
      GROUP BY date(created_at) ORDER BY day ASC
    `).all();

    const byStatus = local.prepare('SELECT status, COUNT(*) as count FROM transactions GROUP BY status').all();
    const byApp = local.prepare(`
      SELECT app_identifier, COUNT(*) as count,
             COALESCE(SUM(CASE WHEN status='success' THEN amount ELSE 0 END), 0) as revenue
      FROM transactions GROUP BY app_identifier ORDER BY count DESC LIMIT 10
    `).all();
    const recentRequests = local.prepare(`
      SELECT endpoint, method, COUNT(*) as count FROM request_log
      WHERE created_at >= datetime('now', '-7 days')
      GROUP BY endpoint, method ORDER BY count DESC LIMIT 10
    `).all();

    res.json({ daily, byStatus, byApp, recentRequests });
  } catch (e) {
    console.error('Charts error:', e);
    res.status(500).json({ error: 'Failed to fetch charts' });
  }
});

// ============================================================
// PAYHERO PROXY ROUTES
// ============================================================
app.post('/api/pay/stk-push', requireReady, authenticateApiKey, async (req, res) => {
  try {
    const { phone_number, amount, external_reference, callback_url } = req.body || {};
    const channelId = req.apiKeyRecord.channel_id;

    // ===== VALIDATION =====
    if (!phone_number || !amount || !external_reference) {
      logRequest(req.apiKeyRecord, req, 400);
      return res.status(400).json({
        error: 'phone_number, amount, and external_reference are required'
      });
    }

    if (typeof external_reference !== 'string' || external_reference.length > 100) {
      logRequest(req.apiKeyRecord, req, 400);
      return res.status(400).json({ error: 'external_reference must be a string ≤ 100 chars' });
    }

    let phone = String(phone_number).replace(/\s+/g, '').replace(/-/g, '');
    if (phone.startsWith('+')) phone = phone.slice(1);
    if (phone.startsWith('0')) phone = '254' + phone.slice(1);
    if (phone.startsWith('7') || phone.startsWith('1')) phone = '254' + phone;

    if (!/^254[17]\d{8}$/.test(phone)) {
      logRequest(req.apiKeyRecord, req, 400);
      return res.status(400).json({
        error: 'Invalid phone number. Use format 254708765597 or 0708765597'
      });
    }

    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0 || numericAmount > 500000) {
      logRequest(req.apiKeyRecord, req, 400);
      return res.status(400).json({
        error: 'Amount must be between 1 and 500,000 KES'
      });
    }

    // ===== IDEMPOTENCY =====
    const existing = local.prepare(
      'SELECT * FROM transactions WHERE external_reference = ?'
    ).get(external_reference);

    if (existing) {
      logRequest(req.apiKeyRecord, req, 200);
      return res.json({
        success: true,
        external_reference,
        idempotent: true,
        message: 'Transaction already exists',
        transaction: existing,
      });
    }

    // ===== INSERT PENDING (atomic, handles race) =====
    try {
      local.prepare(
        `INSERT INTO transactions
         (external_reference, app_identifier, channel_id, phone_number, amount, status)
         VALUES (?, ?, ?, ?, ?, 'pending')`
      ).run(external_reference, req.apiKeyRecord.app_identifier, channelId, phone, numericAmount);
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) {
        const row = local.prepare('SELECT * FROM transactions WHERE external_reference = ?').get(external_reference);
        logRequest(req.apiKeyRecord, req, 200);
        return res.json({ success: true, external_reference, idempotent: true, transaction: row });
      }
      throw e;
    }

    syncToTurso(
      `INSERT OR IGNORE INTO transactions
       (external_reference, app_identifier, channel_id, phone_number, amount, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      [external_reference, req.apiKeyRecord.app_identifier, channelId, phone, numericAmount]
    );

    // ===== CALL PAYHERO (with timeout) =====
    const payheroPayload = {
      amount: numericAmount,
      phone_number: phone,
      channel_id: channelId,
      provider: 'm-pesa',
      external_reference: external_reference,
      callback_url: callback_url || `${req.protocol}://${req.get('host')}/api/payhero/callback`,
    };

    let response, data;
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 25000);
      response = await fetch(
        'https://backend.payhero.co.ke/api/v2/payments/initiate-stk-push',
        {
          method: 'POST',
          headers: {
            Authorization: getPayHeroAuthHeader(),
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payheroPayload),
          signal: controller.signal,
        }
      );
      clearTimeout(t);
      data = await response.json().catch(() => ({}));
    } catch (e) {
      console.error('PayHero fetch failed:', e.message);
      local.prepare(
        `UPDATE transactions SET status = 'failed', callback_payload = ?, updated_at = datetime('now')
         WHERE external_reference = ?`
      ).run(JSON.stringify({ error: e.message }), external_reference);
      syncToTurso(
        `UPDATE transactions SET status = 'failed', callback_payload = ?, updated_at = CURRENT_TIMESTAMP
         WHERE external_reference = ?`,
        [JSON.stringify({ error: e.message }), external_reference]
      );
      logRequest(req.apiKeyRecord, req, 502);
      return res.status(502).json({
        error: 'PayHero unreachable',
        message: e.message,
      });
    }

    // ===== HANDLE PAYHERO ERROR =====
    if (!response.ok) {
      local.prepare(
        `UPDATE transactions
         SET status = 'failed',
             callback_payload = ?,
             updated_at = datetime('now')
         WHERE external_reference = ?`
      ).run(JSON.stringify(data), external_reference);

      syncToTurso(
        `UPDATE transactions
         SET status = 'failed',
             callback_payload = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE external_reference = ?`,
        [JSON.stringify(data), external_reference]
      );

      logRequest(req.apiKeyRecord, req, response.status);

      return res.status(response.status).json({
        error: 'PayHero API error',
        message: data.error_message || data.message || 'STK Push failed',
        details: data,
      });
    }

    // ===== SUCCESS =====
    const payheroRef =
      data.reference ||
      data.response?.reference ||
      data.response?.Transaction_Reference ||
      data.checkout_request_id ||
      '';

    if (payheroRef) {
      local.prepare(
        `UPDATE transactions
         SET payhero_reference = ?, updated_at = datetime('now')
         WHERE external_reference = ?`
      ).run(payheroRef, external_reference);

      syncToTurso(
        `UPDATE transactions
         SET payhero_reference = ?, updated_at = CURRENT_TIMESTAMP
         WHERE external_reference = ?`,
        [payheroRef, external_reference]
      );
    }

    logRequest(req.apiKeyRecord, req, 200);

    res.json({
      success: true,
      external_reference,
      payhero_response: data,
    });

  } catch (error) {
    console.error('STK Push error:', error);
    if (req.apiKeyRecord) logRequest(req.apiKeyRecord, req, 500);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});

// ============================================================
// STATUS QUERY
// ============================================================
app.get('/api/pay/status/:reference', requireReady, authenticateApiKey, async (req, res) => {
  try {
    const { reference } = req.params;
    const channelId = req.apiKeyRecord.channel_id;

    const t = local.prepare(
      'SELECT * FROM transactions WHERE external_reference = ? OR payhero_reference = ? OR mpesa_receipt = ?'
    ).get(reference, reference, reference);

    if (t && t.status !== 'pending' && t.verified_with_payhero) {
      logRequest(req.apiKeyRecord, req, 200);
      return res.json({ source: 'local', transaction: t });
    }

    let response, data;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20000);
      response = await fetch(
        `https://backend.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(reference)}&channel_id=${encodeURIComponent(channelId)}`,
        { headers: { Authorization: getPayHeroAuthHeader() }, signal: controller.signal }
      );
      clearTimeout(timer);
      data = await response.json().catch(() => ({}));
    } catch (e) {
      console.error('Status fetch failed:', e.message);
      logRequest(req.apiKeyRecord, req, 502);
      return res.status(502).json({ error: 'PayHero unreachable', message: e.message });
    }

    if (!response.ok) {
      logRequest(req.apiKeyRecord, req, response.status);
      return res.status(response.status).json({
        error: 'PayHero API error',
        details: data,
      });
    }

    if (t) {
      const normalized = normalizeStatus(data.status || data.Status || data.response?.Status);
      if (normalized !== 'unknown') {
        local.prepare(
          `UPDATE transactions SET status = ?, verified_with_payhero = 1, updated_at = datetime('now') WHERE id = ?`
        ).run(normalized, t.id);
        syncToTurso(
          `UPDATE transactions SET status = ?, verified_with_payhero = 1, updated_at = CURRENT_TIMESTAMP WHERE external_reference = ?`,
          [normalized, t.external_reference]
        );
      }
    }

    logRequest(req.apiKeyRecord, req, 200);
    res.json({ source: 'payhero', transaction: data });
  } catch (error) {
    console.error('Status query error:', error);
    if (req.apiKeyRecord) logRequest(req.apiKeyRecord, req, 500);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// PAYHERO CALLBACK
// ============================================================
app.post('/api/payhero/callback', async (req, res) => {
  const sourceIp = req.ip;
  const payload = req.body || {};

  try {
    console.log('PayHero Callback received:', JSON.stringify(payload, null, 2));

    const externalRef = payload.external_reference || payload.reference || payload.response?.User_Reference;
    const mpesaRef = payload.mpesa_receipt || payload.response?.MPESA_Reference;

    let callbackLogId = null;
    try {
      const info = local.prepare(
        `INSERT INTO callback_log (external_reference, raw_payload, source_ip)
         VALUES (?, ?, ?)`
      ).run(externalRef || null, JSON.stringify(payload), sourceIp);
      callbackLogId = info.lastInsertRowid;
    } catch (e) {
      console.error('callback_log insert failed:', e.message);
    }

    syncToTurso(
      `INSERT INTO callback_log (external_reference, raw_payload, source_ip)
       VALUES (?, ?, ?)`,
      [externalRef || null, JSON.stringify(payload), sourceIp]
    );

    if (!externalRef && !mpesaRef) {
      console.warn('Callback missing reference, ignoring');
      return res.status(200).json({ status: 'received_no_reference' });
    }

    let txn = null;
    if (externalRef) {
      txn = local.prepare('SELECT * FROM transactions WHERE external_reference = ?').get(externalRef);
    }
    if (!txn && mpesaRef) {
      txn = local.prepare('SELECT * FROM transactions WHERE payhero_reference = ? OR mpesa_receipt = ?').get(mpesaRef, mpesaRef);
    }

    if (!txn) {
      console.warn('Callback for unknown transaction:', externalRef || mpesaRef);
      return res.status(200).json({ status: 'received_unknown_transaction' });
    }

    let verifiedStatus = null;
    let verifiedWithPayhero = false;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      const verifyResponse = await fetch(
        `https://backend.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(txn.external_reference)}&channel_id=${encodeURIComponent(txn.channel_id)}`,
        { headers: { Authorization: getPayHeroAuthHeader() }, signal: controller.signal }
      );
      clearTimeout(timer);

      if (verifyResponse.ok) {
        const verifyData = await verifyResponse.json();
        const rawStatus = verifyData.status || verifyData.Status || verifyData.response?.Status;
        verifiedStatus = normalizeStatus(rawStatus);
        verifiedWithPayhero = verifiedStatus !== 'unknown';
      }
    } catch (e) {
      console.error('PayHero verification failed:', e.message);
    }

    const callbackStatus = normalizeStatus(
      payload.status || payload.Status || payload.transaction_status || payload.response?.Status
    );

    let finalStatus;
    if (verifiedWithPayhero) {
      finalStatus = verifiedStatus;
    } else if (callbackStatus === 'success') {
      console.warn(`Callback claims success for ${txn.external_reference} but PayHero verification failed. Keeping pending for retry.`);
      finalStatus = 'pending';
    } else {
      finalStatus = callbackStatus;
    }

    if (txn.status === 'success' && finalStatus !== 'success') {
      console.log(`Ignoring downgrade attempt for ${txn.external_reference}`);
      return res.status(200).json({ status: 'received_ignored_downgrade' });
    }

    local.prepare(
      `UPDATE transactions
       SET status = ?, payhero_reference = COALESCE(?, payhero_reference),
           mpesa_receipt = COALESCE(?, mpesa_receipt),
           callback_payload = ?, verified_with_payhero = ?, updated_at = datetime('now')
       WHERE id = ?`
    ).run(finalStatus, mpesaRef, mpesaRef, JSON.stringify(payload), verifiedWithPayhero ? 1 : 0, txn.id);

    syncToTurso(
      `UPDATE transactions
       SET status = ?, payhero_reference = COALESCE(?, payhero_reference),
           mpesa_receipt = COALESCE(?, mpesa_receipt),
           callback_payload = ?, verified_with_payhero = ?, updated_at = CURRENT_TIMESTAMP
       WHERE external_reference = ?`,
      [finalStatus, mpesaRef, mpesaRef, JSON.stringify(payload), verifiedWithPayhero ? 1 : 0, txn.external_reference]
    );

    // FIX: SQLite doesn't support ORDER BY/LIMIT in UPDATE — use subquery
    if (callbackLogId) {
      try {
        local.prepare('UPDATE callback_log SET verified = ? WHERE id = ?')
          .run(verifiedWithPayhero ? 1 : 0, callbackLogId);
      } catch (e) {
        console.error('callback_log verify update failed:', e.message);
      }
    }

    const apiKey = local.prepare('SELECT * FROM api_keys WHERE app_identifier = ?').get(txn.app_identifier);

    if (apiKey && apiKey.webhook_url) {
      const forwardPayload = {
        event: 'payment.' + finalStatus,
        external_reference: txn.external_reference,
        payhero_reference: mpesaRef || txn.payhero_reference,
        mpesa_receipt: mpesaRef,
        amount: txn.amount,
        phone_number: txn.phone_number,
        status: finalStatus,
        verified: verifiedWithPayhero,
        timestamp: new Date().toISOString(),
      };

      const signature = signWebhookPayload(apiKey.webhook_secret, forwardPayload);

      const headers = {
        'Content-Type': 'application/json',
        'X-PayHero-Event': 'payment.' + finalStatus,
      };
      if (signature) headers['X-PayHero-Signature'] = signature;

      // Fire and forget with timeout
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      fetch(apiKey.webhook_url, {
        method: 'POST',
        headers,
        body: JSON.stringify(forwardPayload),
        signal: controller.signal,
      }).then(() => clearTimeout(timer))
        .catch((e) => {
          clearTimeout(timer);
          console.error('Webhook forward failed:', e.message);
        });
    }

    res.status(200).json({ status: 'received', verified: verifiedWithPayhero });
  } catch (error) {
    console.error('Callback processing error:', error);
    // Always return 200 so PayHero doesn't retry-storm us
    res.status(200).json({ status: 'received_with_error' });
  }
});

// ============================================================
// RETRY QUEUE for unverified callbacks (every 30s)
// ============================================================
async function retryUnverifiedCallbacks() {
  if (!appReady) return;
  try {
    const pending = local.prepare(`
      SELECT t.id, t.external_reference, t.channel_id, t.status
      FROM transactions t
      JOIN callback_log c ON c.external_reference = t.external_reference
      WHERE c.verified = 0
        AND t.verified_with_payhero = 0
        AND t.created_at >= datetime('now', '-1 day')
      LIMIT 5
    `).all();

    for (const t of pending) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10000);
        const resp = await fetch(
          `https://backend.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(t.external_reference)}&channel_id=${encodeURIComponent(t.channel_id)}`,
          { headers: { Authorization: getPayHeroAuthHeader() }, signal: controller.signal }
        );
        clearTimeout(timer);
        if (!resp.ok) continue;
        const data = await resp.json();
        const status = normalizeStatus(data.status || data.Status || data.response?.Status);
        if (status !== 'unknown') {
          local.prepare(
            `UPDATE transactions SET status = ?, verified_with_payhero = 1, updated_at = datetime('now') WHERE id = ?`
          ).run(status, t.id);
          local.prepare(
            `UPDATE callback_log SET verified = 1 WHERE id = (SELECT MAX(id) FROM callback_log WHERE external_reference = ?)`
          ).run(t.external_reference);
          syncToTurso(
            `UPDATE transactions SET status = ?, verified_with_payhero = 1, updated_at = CURRENT_TIMESTAMP WHERE external_reference = ?`,
            [status, t.external_reference]
          );
          console.log(`Retry-verified ${t.external_reference} → ${status}`);
        }
      } catch (e) {
        console.error('Retry verify failed for', t.external_reference, e.message);
      }
    }
  } catch (e) {
    console.error('retryUnverifiedCallbacks error:', e.message);
  }
}

// ============================================================
// SPA FALLBACK — Express 5 safe
// ============================================================
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) next(err);
  });
});

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message, err.stack);
  if (res.headersSent) return next(err);

  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS not allowed' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload too large' });
  }
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  const statusCode = err.statusCode || 500;
  const message = err.isOperational ? err.message : 'Internal server error';
  res.status(statusCode).json({ error: message });
});

// ============================================================
// START
// ============================================================
const server = app.listen(PORT, async () => {
  console.log(`PayHero Central API listening on port ${PORT}`);

  try {
    await hydrateFromTurso();
    appReady = true;
    console.log('Startup complete — accepting API requests');
  } catch (e) {
    console.error('Startup error:', e.message);
    // Even on failure, mark ready so local-only mode works
    appReady = true;
    console.log('Continuing in local-only mode');
  }
});

// ============================================================
// PERIODIC FLUSH TO TURSO
// ============================================================
setInterval(async () => {
  if (!turso || !tursoReady || !appReady) return;

  await flushTursoQueue();

  try {
    const keys = local.prepare('SELECT * FROM api_keys').all();
    for (const k of keys) {
      await executeWithRetry(
        `INSERT OR REPLACE INTO api_keys
         (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min, is_active, created_at, last_used_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [k.key_hash, k.key_preview, k.name, k.app_identifier, k.channel_id,
         k.webhook_url, k.webhook_secret, k.rate_limit_per_min, k.is_active,
         k.created_at, k.last_used_at, k.expires_at]
      );
    }
    const txns = local.prepare('SELECT * FROM transactions').all();
    for (const t of txns) {
      await executeWithRetry(
        `INSERT OR REPLACE INTO transactions
         (external_reference, app_identifier, payhero_reference, mpesa_receipt, channel_id,
          phone_number, amount, status, callback_payload, verified_with_payhero, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [t.external_reference, t.app_identifier, t.payhero_reference, t.mpesa_receipt,
         t.channel_id, t.phone_number, t.amount, t.status, t.callback_payload,
         t.verified_with_payhero, t.created_at, t.updated_at]
      );
    }
  } catch (e) {
    console.error('Periodic flush error:', e.message);
  }
}, 30000);

// Retry unverified callbacks every 30s
setInterval(retryUnverifiedCallbacks, 30000);

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================
async function shutdown(signal) {
  console.log(`Received ${signal}, shutting down gracefully...`);
  server.close(() => console.log('HTTP server closed'));

  try {
    await flushTursoQueue();
    console.log('Turso queue flushed');
  } catch (e) {
    console.error('Shutdown flush error:', e.message);
  }

  try {
    local.close();
    console.log('Local DB closed');
  } catch (e) {
    console.error('Local DB close error:', e.message);
  }

  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled promise rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  // Don't exit — Render will restart, but we want to log first
});
