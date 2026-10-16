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
// SECURITY: Helmet with relaxed CSP for inline handlers
// ============================================================
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'unsafe-inline'"], // Allows inline onclick handlers
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
// SECURITY: CORS (restrict to your frontend in production)
// ============================================================
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : ['https://payheroapi.onrender.com'];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, same-origin)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    if (process.env.NODE_ENV !== 'production') return callback(null, true);
    // Silently reject — do NOT throw, or browser gets confusing 500 + no headers
    console.warn('CORS blocked origin:', origin);
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-token', 'x-api-key', 'idempotency-key'],
  maxAge: 86400,
}));

app.options('*', cors());

// ============================================================
// SECURITY: Body size limits (prevent memory exhaustion DoS)
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
// LOCAL SQLITE BUFFER
// ============================================================
const DB_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const LOCAL_DB_PATH = path.join(DB_DIR, 'buffer.db');

const local = new Database(LOCAL_DB_PATH);
local.pragma('journal_mode = WAL');
local.pragma('synchronous = NORMAL');
local.pragma('foreign_keys = ON');

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
  `);
  console.log('Local DB schema ready');
}

initLocalSchema();

// ============================================================
// TURSO CLOUD
// ============================================================
let turso = null;
let tursoReady = false;

if (process.env.TURSO_DATABASE_URL && process.env.TURSO_AUTH_TOKEN) {
  try {
    turso = createClient({
      url: process.env.TURSO_DATABASE_URL,
      authToken: process.env.TURSO_AUTH_TOKEN,
    });
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

async function syncToTurso(sql, args = []) {
  if (!tursoReady) return;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await turso.execute({ sql, args });
      return;
    } catch (e) {
      if (attempt === 1) {
        console.error('Turso sync failed after retry:', e.message);
        return;
      }
      // Recreate client on first failure
      try {
        turso = createClient({
          url: process.env.TURSO_DATABASE_URL,
          authToken: process.env.TURSO_AUTH_TOKEN,
        });
      } catch (re) {
        console.error('Turso client recreation failed:', re.message);
        return;
      }
    }
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
    const remoteKeys = await turso.execute('SELECT * FROM api_keys');
    const insertKey = local.prepare(`
      INSERT OR IGNORE INTO api_keys
      (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min, is_active, created_at, last_used_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let keyCount = 0;
    for (const k of remoteKeys.rows) {
      const info = insertKey.run(
        k.key_hash, k.key_preview, k.name, k.app_identifier,
        k.channel_id, k.webhook_url || null, k.webhook_secret || null,
        k.rate_limit_per_min || 100, k.is_active, k.created_at, k.last_used_at, k.expires_at || null
      );
      if (info.changes) keyCount++;
    }

    // Pull transactions
    const remoteTxns = await turso.execute('SELECT * FROM transactions');
    const insertTxn = local.prepare(`
      INSERT OR IGNORE INTO transactions
      (external_reference, app_identifier, payhero_reference, mpesa_receipt, channel_id,
       phone_number, amount, status, callback_payload, verified_with_payhero, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let txnCount = 0;
    for (const t of remoteTxns.rows) {
      const info = insertTxn.run(
        t.external_reference, t.app_identifier, t.payhero_reference,
        t.mpesa_receipt || null, t.channel_id, t.phone_number, t.amount, t.status,
        t.callback_payload, t.verified_with_payhero || 0, t.created_at, t.updated_at
      );
      if (info.changes) txnCount++;
    }

    console.log(`Hydrated from Turso: +${keyCount} keys, +${txnCount} transactions`);
  } catch (e) {
    console.error('Hydration failed:', e.message);
    console.log('Continuing with local-only data');
  }
}

// ============================================================
// HELPERS: Secure Key Generation
// ============================================================
function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function generateApiKey() {
  // 32 bytes = 256 bits of entropy, hex-encoded for safe transport
  return 'phk_' + crypto.randomBytes(32).toString('hex');
}

function generateWebhookSecret() {
  return 'whsec_' + crypto.randomBytes(32).toString('hex');
}

function getPayHeroAuthHeader() {
  const credentials = Buffer.from(
    `${process.env.PAYHERO_API_USERNAME}:${process.env.PAYHERO_API_PASSWORD}`
  ).toString('base64');
  return `Basic ${credentials}`;
}

function signWebhookPayload(secret, payload) {
  return crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
}

function normalizeStatus(raw) {
  const v = String(raw || '').toLowerCase();
  if (v.includes('success') || v === '1' || v === 'paid' || v === 'completed') return 'success';
  if (v.includes('fail') || v.includes('cancel') || v === '0') return 'failed';
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

  // Check key expiry
  if (keyRecord.expires_at && new Date(keyRecord.expires_at) < new Date()) {
    logRequest(keyRecord, req, 403);
    return res.status(403).json({ error: 'API key expired' });
  }

  // Per-key rate limit
  const rate = checkKeyRateLimit(keyRecord);
  res.set('X-RateLimit-Limit', keyRecord.rate_limit_per_min || 100);
  res.set('X-RateLimit-Remaining', rate.remaining);

  if (!rate.allowed) {
    logRequest(keyRecord, req, 429);
    return res.status(429).json({ error: 'Rate limit exceeded for this API key' });
  }

  local.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?").run(keyRecord.id);
  syncToTurso("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?", [keyRecord.id]);

  req.apiKeyRecord = keyRecord;
  next();
}

function adminAuth(req, res, next) {
  const adminToken = req.headers['x-admin-token'] || req.query.admin_token;
  const expected = process.env.ADMIN_PASSWORD;

  if (!expected) {
    return res.status(500).json({ error: 'Admin password not configured' });
  }

  // Timing-safe comparison
  const provided = Buffer.from(String(adminToken || ''));
  const correct = Buffer.from(String(expected));

  if (provided.length !== correct.length || !crypto.timingSafeEqual(provided, correct)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    turso: tursoReady ? 'connected' : 'local-only',
    timestamp: new Date().toISOString(),
  });
});

// ============================================================
// ADMIN ROUTES
// ============================================================

// Stricter rate limit for login (prevent brute force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { password } = req.body;

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

app.get('/api/admin/keys', adminAuth, (req, res) => {
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

app.post('/api/admin/keys', adminAuth, (req, res) => {
  try {
    const { name, app_identifier, channel_id, webhook_url, rate_limit_per_min } = req.body;

    if (!name || !channel_id) {
      return res.status(400).json({ error: 'Name and Channel ID are required' });
    }

    if (!/^[a-zA-Z0-9_-]{1,50}$/.test(channel_id)) {
      return res.status(400).json({ error: 'Invalid channel_id format' });
    }

    const newKey = generateApiKey();
    const keyHash = hashKey(newKey);
    const preview = newKey.slice(0, 12) + '...' + newKey.slice(-4);
    const webhookSecret = webhook_url ? generateWebhookSecret() : null;

    local.prepare(
      `INSERT INTO api_keys (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(keyHash, preview, name, app_identifier || name, channel_id, webhook_url || null, webhookSecret, rate_limit_per_min || 100);

    syncToTurso(
      `INSERT OR IGNORE INTO api_keys (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [keyHash, preview, name, app_identifier || name, channel_id, webhook_url || null, webhookSecret, rate_limit_per_min || 100]
    );

    res.json({
      api_key: newKey,
      webhook_secret: webhookSecret,
      message: 'Store these securely. They will not be shown again.',
      name,
      channel_id,
    });
  } catch (e) {
    console.error('Create key error:', e);
    res.status(500).json({ error: 'Failed to create key' });
  }
});

app.patch('/api/admin/keys/:id/revoke', adminAuth, (req, res) => {
  try {
    local.prepare('UPDATE api_keys SET is_active = 0 WHERE id = ?').run(req.params.id);
    syncToTurso('UPDATE api_keys SET is_active = 0 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to revoke key' });
  }
});

app.patch('/api/admin/keys/:id/activate', adminAuth, (req, res) => {
  try {
    local.prepare('UPDATE api_keys SET is_active = 1 WHERE id = ?').run(req.params.id);
    syncToTurso('UPDATE api_keys SET is_active = 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to activate key' });
  }
});

app.delete('/api/admin/keys/:id', adminAuth, (req, res) => {
  try {
    const row = local.prepare('SELECT key_hash FROM api_keys WHERE id = ?').get(req.params.id);
    local.prepare('DELETE FROM api_keys WHERE id = ?').run(req.params.id);
    if (row) {
      syncToTurso('DELETE FROM api_keys WHERE key_hash = ?', [row.key_hash]);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete key' });
  }
});

app.post('/api/admin/keys/verify', adminAuth, (req, res) => {
  try {
    const { api_key } = req.body;
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

app.get('/api/admin/stats', adminAuth, (req, res) => {
  try {
    const keys = local.prepare('SELECT COUNT(*) as c, SUM(is_active) as active FROM api_keys').get();
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

app.get('/api/admin/transactions', adminAuth, (req, res) => {
  try {
    const { status, limit = 50, offset = 0 } = req.query;
    let sql = 'SELECT * FROM transactions';
    const args = [];

    if (status && status !== 'all') {
      sql += ' WHERE status = ?';
      args.push(status);
    }

    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    args.push(Math.min(parseInt(limit) || 50, 500), parseInt(offset) || 0);

    const rows = local.prepare(sql).all(...args);
    res.json(rows);
  } catch (e) {
    console.error('Transactions error:', e);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/admin/charts', adminAuth, (req, res) => {
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

app.post('/api/pay/stk-push', authenticateApiKey, async (req, res) => {
  try {
    const { phone_number, amount, external_reference, callback_url } = req.body;
    const channelId = req.apiKeyRecord.channel_id;

    // ===== VALIDATION =====
    if (!phone_number || !amount || !external_reference) {
      logRequest(req.apiKeyRecord, req, 400);
      return res.status(400).json({ 
        error: 'phone_number, amount, and external_reference are required' 
      });
    }

    // Normalize phone: accept 0707..., 254707..., +254707...
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

    if (typeof amount !== 'number' || amount <= 0 || amount > 500000) {
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

    // ===== INSERT PENDING =====
    local.prepare(
      `INSERT INTO transactions 
       (external_reference, app_identifier, channel_id, phone_number, amount, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`
    ).run(external_reference, req.apiKeyRecord.app_identifier, channelId, phone, amount);

    syncToTurso(
      `INSERT OR IGNORE INTO transactions 
       (external_reference, app_identifier, channel_id, phone_number, amount, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      [external_reference, req.apiKeyRecord.app_identifier, channelId, phone, amount]
    );

    // ===== CALL PAYHERO (CORRECT ENDPOINT + PAYLOAD) =====
    const payheroPayload = {
      amount: Number(amount),
      phone_number: phone,
      channel_id: channelId,
      provider: 'm-pesa',              // ← CRITICAL: REQUIRED
      external_reference: external_reference,
      callback_url: callback_url || `${req.protocol}://${req.get('host')}/api/payhero/callback`,
    };

    const response = await fetch(
      'https://backend.payhero.co.ke/api/v2/payments/initiate-stk-push',
      {
        method: 'POST',
        headers: {
          Authorization: getPayHeroAuthHeader(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payheroPayload),
      }
    );

    const data = await response.json();

    // ===== HANDLE PAYHERO ERROR =====
    if (!response.ok) {
      // Mark transaction as failed so it doesn't stay pending forever
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

      // Return a clear error to the client
      return res.status(response.status).json({
        error: 'PayHero API error',
        message: data.error_message || data.message || 'STK Push failed',
        details: data,
      });
    }

    // ===== SUCCESS: Store PayHero reference =====
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
    logRequest(req.apiKeyRecord, req, 500);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// ============================================================
// PAYHERO CALLBACK — SECURITY CRITICAL
// ============================================================
app.post('/api/payhero/callback', async (req, res) => {
  const sourceIp = req.ip;
  const payload = req.body;

  try {
    console.log('PayHero Callback received:', JSON.stringify(payload, null, 2));

    // Log ALL callbacks for audit
    const externalRef = payload.external_reference || payload.reference || payload.response?.User_Reference;
    const mpesaRef = payload.mpesa_receipt || payload.response?.MPESA_Reference;

    local.prepare(
      `INSERT INTO callback_log (external_reference, raw_payload, source_ip)
       VALUES (?, ?, ?)`
    ).run(externalRef || null, JSON.stringify(payload), sourceIp);
    syncToTurso(
      `INSERT INTO callback_log (external_reference, raw_payload, source_ip)
       VALUES (?, ?, ?)`,
      [externalRef || null, JSON.stringify(payload), sourceIp]
    );

    if (!externalRef && !mpesaRef) {
      console.warn('Callback missing reference, ignoring');
      return res.status(200).json({ status: 'received_no_reference' });
    }

    // Find the transaction
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

    // SECURITY: Re-query PayHero to verify the actual status
    let verifiedStatus = null;
    let verifiedWithPayhero = false;

    try {
      const verifyResponse = await fetch(
        `https://backend.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(txn.external_reference)}&channel_id=${txn.channel_id}`,
        { headers: { Authorization: getPayHeroAuthHeader() } }
      );

      if (verifyResponse.ok) {
        const verifyData = await verifyResponse.json();
        const rawStatus = verifyData.status || verifyData.Status || verifyData.response?.Status;
        verifiedStatus = normalizeStatus(rawStatus);
        verifiedWithPayhero = verifiedStatus !== 'unknown';
      }
    } catch (e) {
      console.error('PayHero verification failed:', e.message);
    }

    // If we couldn't verify with PayHero, only trust the callback if it's NOT claiming success
    const callbackStatus = normalizeStatus(
      payload.status || payload.Status || payload.transaction_status || payload.response?.Status
    );

    let finalStatus;
    if (verifiedWithPayhero) {
      finalStatus = verifiedStatus;
    } else if (callbackStatus === 'success') {
      console.warn(`Callback claims success for ${txn.external_reference} but PayHero verification failed. Keeping pending.`);
      finalStatus = 'pending';
    } else {
      finalStatus = callbackStatus;
    }

    // Don't downgrade from success
    if (txn.status === 'success' && finalStatus !== 'success') {
      console.log(`Ignoring downgrade attempt for ${txn.external_reference}`);
      return res.status(200).json({ status: 'received_ignored_downgrade' });
    }

    // Update transaction
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

    // Mark callback as verified in log
    local.prepare(
      `UPDATE callback_log SET verified = ? WHERE external_reference = ? ORDER BY id DESC LIMIT 1`
    ).run(verifiedWithPayhero ? 1 : 0, txn.external_reference);

    // Forward to app webhook (if configured)
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

      fetch(apiKey.webhook_url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-PayHero-Signature': signature,
          'X-PayHero-Event': 'payment.' + finalStatus,
        },
        body: JSON.stringify(forwardPayload),
      }).catch((e) => console.error('Webhook forward failed:', e.message));
    }

    res.status(200).json({ status: 'received', verified: verifiedWithPayhero });
  } catch (error) {
    console.error('Callback processing error:', error);
    res.status(200).json({ status: 'received_with_error' });
  }
});

// ============================================================
// SPA FALLBACK
// ============================================================
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// GLOBAL ERROR HANDLER (no stack traces leaked)
// ============================================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS not allowed' });
  }
  const statusCode = err.statusCode || 500;
  const message = err.isOperational ? err.message : 'Internal server error';
  res.status(statusCode).json({ error: message });
});

// ============================================================
// START (non-blocking for Render health checks)
// ============================================================
app.listen(PORT, () => {
  console.log(`PayHero Central API listening on port ${PORT}`);

  hydrateFromTurso()
    .then(() => console.log('Startup complete'))
    .catch((e) => console.error('Startup error:', e.message));
});

// ============================================================
// PERIODIC FLUSH to Turso (safety net)
// ============================================================
setInterval(async () => {
  if (!turso || !tursoReady) return;
  try {
    const keys = local.prepare('SELECT * FROM api_keys').all();
    for (const k of keys) {
      await turso.execute({
        sql: `INSERT OR REPLACE INTO api_keys
              (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min, is_active, created_at, last_used_at, expires_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [k.key_hash, k.key_preview, k.name, k.app_identifier, k.channel_id,
               k.webhook_url, k.webhook_secret, k.rate_limit_per_min, k.is_active,
               k.created_at, k.last_used_at, k.expires_at],
      });
    }
    const txns = local.prepare('SELECT * FROM transactions').all();
    for (const t of txns) {
      await turso.execute({
        sql: `INSERT OR REPLACE INTO transactions
              (external_reference, app_identifier, payhero_reference, mpesa_receipt, channel_id,
               phone_number, amount, status, callback_payload, verified_with_payhero, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [t.external_reference, t.app_identifier, t.payhero_reference, t.mpesa_receipt,
               t.channel_id, t.phone_number, t.amount, t.status, t.callback_payload,
               t.verified_with_payhero, t.created_at, t.updated_at],
      });
    }
  } catch (e) {
    console.error('Periodic flush error:', e.message);
  }
}, 30000);
