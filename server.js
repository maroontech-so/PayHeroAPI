require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const BRAND = 'LyCash';
const KEY_PREFIX = 'lyc_';

// ============================================================
// BASIC SECURITY
// ============================================================
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.payhero.co.ke", "https://backend.payhero.co.ke", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// ============================================================
// CORS
// ============================================================
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : ['https://lycash.onrender.com'];

const allowAll = allowedOrigins.includes('*');

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowAll) return cb(null, true);
    for (const o of allowedOrigins) {
      if (o.startsWith('*.')) {
        if (origin.toLowerCase().endsWith(o.slice(1).toLowerCase())) return cb(null, true);
      } else if (origin === o) {
        return cb(null, true);
      }
    }
    console.warn('CORS blocked:', origin);
    return cb(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-token', 'x-api-key', 'idempotency-key'],
  maxAge: 86400,
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// TURSO CLIENT
// ============================================================
if (!process.env.TURSO_DATABASE_URL || !process.env.TURSO_AUTH_TOKEN) {
  console.error('FATAL: TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are required');
  process.exit(1);
}

const turso = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function db(sql, args = []) {
  try {
    return await turso.execute({ sql, args });
  } catch (e) {
    console.error('DB error, retrying:', e.message);
    await new Promise(r => setTimeout(r, 500));
    return await turso.execute({ sql, args });
  }
}

// ============================================================
// SCHEMA
// ============================================================
async function ensureSchema() {
  await db(`
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
  await db(`
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
  await db(`
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
  await db(`
    CREATE TABLE IF NOT EXISTS callback_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_reference TEXT,
      raw_payload TEXT,
      verified INTEGER DEFAULT 0,
      source_ip TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  console.log('Schema ready');
}

// ============================================================
// IN-MEMORY KEY CACHE
// ============================================================
const keyCache = new Map();
let keyCacheLoadedAt = 0;
const KEY_CACHE_TTL_MS = 30_000;

async function refreshKeyCache() {
  try {
    const result = await db('SELECT * FROM api_keys WHERE is_active = 1');
    keyCache.clear();
    for (const row of result.rows) {
      keyCache.set(row.key_hash, row);
    }
    keyCacheLoadedAt = Date.now();
    console.log(`Key cache loaded: ${keyCache.size} keys`);
  } catch (e) {
    console.error('Key cache refresh failed:', e.message);
  }
}

async function getKeyByHash(keyHash) {
  if (Date.now() - keyCacheLoadedAt > KEY_CACHE_TTL_MS) {
    await refreshKeyCache();
  }
  if (keyCache.has(keyHash)) return keyCache.get(keyHash);
  const result = await db(
    'SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1',
    [keyHash]
  );
  if (result.rows.length === 0) return null;
  const row = result.rows[0];
  keyCache.set(keyHash, row);
  return row;
}

// ============================================================
// HELPERS
// ============================================================
function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}
function generateApiKey() {
  return KEY_PREFIX + crypto.randomBytes(32).toString('hex');
}
function generateWebhookSecret() {
  return 'whsec_' + crypto.randomBytes(32).toString('hex');
}
function getPayHeroAuthHeader() {
  const u = process.env.PAYHERO_API_USERNAME;
  const p = process.env.PAYHERO_API_PASSWORD;
  if (!u || !p) throw new Error('Upstream credentials not configured');
  return `Basic ${Buffer.from(`${u}:${p}`).toString('base64')}`;
}
function signWebhookPayload(secret, payload) {
  if (!secret) return null;
  return crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
}
function normalizeStatus(raw) {
  const v = String(raw || '').toLowerCase().trim();
  if (['success', 'successful', 'complete', 'completed', 'paid', '1'].includes(v)) return 'success';
  if (v.includes('fail') || v.includes('cancel') || v === '0' || v.includes('reject')) return 'failed';
  if (v.includes('pending') || v.includes('process') || v.includes('queue') || v === '2') return 'pending';
  return 'unknown';
}

async function logRequest(req, keyRecord, statusCode) {
  try {
    await db(
      `INSERT INTO request_log (api_key_id, app_identifier, endpoint, method, status_code)
       VALUES (?, ?, ?, ?, ?)`,
      [keyRecord?.id ?? null, keyRecord?.app_identifier ?? null, req.path, req.method, statusCode]
    );
  } catch (e) {
    console.error('logRequest failed:', e.message);
  }
}

// Extract the best reference from the upstream gateway response
function extractGatewayRef(data) {
  return (
    data.reference ||
    data.response?.reference ||
    data.response?.Transaction_Reference ||
    data.CheckoutRequestID ||
    data.checkout_request_id ||
    ''
  );
}

// ============================================================
// AUTH
// ============================================================
async function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  if (!apiKey) return res.status(401).json({ error: 'API key required' });

  try {
    const keyRecord = await getKeyByHash(hashKey(apiKey));
    if (!keyRecord) {
      logRequest(req, null, 403);
      return res.status(403).json({ error: 'Invalid or inactive API key' });
    }

    if (keyRecord.expires_at && new Date(keyRecord.expires_at) < new Date()) {
      logRequest(req, keyRecord, 403);
      return res.status(403).json({ error: 'API key expired' });
    }

    req.apiKeyRecord = keyRecord;
    next();
  } catch (e) {
    console.error('Auth error:', e.message);
    res.status(500).json({ error: 'Authentication failed' });
  }
}

function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.admin_token;
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) return res.status(500).json({ error: 'Admin password not configured' });

  const a = Buffer.from(String(token || ''));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}

// ============================================================
// HEALTH
// ============================================================
app.get('/health', async (req, res) => {
  try {
    await db('SELECT 1');
    res.json({
      service: BRAND,
      status: 'ok',
      turso: 'connected',
      cached_keys: keyCache.size,
      timestamp: new Date().toISOString(),
    });
  } catch (e) {
    res.status(500).json({ service: BRAND, status: 'error', message: e.message });
  }
});

// ============================================================
// ADMIN ROUTES
// ============================================================
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many login attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { password } = req.body || {};
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) return res.status(500).json({ error: 'Admin password not configured' });

  const a = Buffer.from(String(password || ''));
  const b = Buffer.from(String(expected));
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
    return res.json({ success: true });
  }
  res.status(403).json({ error: 'Invalid password' });
});

app.get('/api/admin/keys', adminAuth, async (req, res) => {
  try {
    const result = await db(
      `SELECT id, key_preview, name, app_identifier, channel_id, webhook_url,
              rate_limit_per_min, is_active, created_at, last_used_at, expires_at
       FROM api_keys ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (e) {
    console.error('List keys error:', e);
    res.status(500).json({ error: 'Failed to list keys' });
  }
});

app.post('/api/admin/keys', adminAuth, async (req, res) => {
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

    await db(
      `INSERT INTO api_keys (key_hash, key_preview, name, app_identifier, channel_id, webhook_url, webhook_secret, rate_limit_per_min)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [keyHash, preview, name, app_identifier || name, channel_id, webhook_url || null, webhookSecret, rl]
    );

    await refreshKeyCache();

    res.json({
      api_key: newKey,
      webhook_secret: webhookSecret,
      message: 'Store these securely. They will not be shown again.',
      name,
      channel_id,
    });
  } catch (e) {
    console.error('Create key error:', e);
    res.status(500).json({ error: 'Failed to create key: ' + e.message });
  }
});

app.patch('/api/admin/keys/:id/revoke', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    await db('UPDATE api_keys SET is_active = 0 WHERE id = ?', [id]);
    await refreshKeyCache();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to revoke key' });
  }
});

app.patch('/api/admin/keys/:id/activate', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    await db('UPDATE api_keys SET is_active = 1 WHERE id = ?', [id]);
    await refreshKeyCache();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to activate key' });
  }
});

app.delete('/api/admin/keys/:id', adminAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid id' });
    await db('DELETE FROM api_keys WHERE id = ?', [id]);
    await refreshKeyCache();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete key' });
  }
});

app.post('/api/admin/keys/verify', adminAuth, async (req, res) => {
  try {
    const { api_key } = req.body || {};
    if (!api_key) return res.status(400).json({ error: 'api_key required' });

    const result = await db(
      'SELECT id, name, channel_id, is_active, expires_at FROM api_keys WHERE key_hash = ?',
      [hashKey(api_key)]
    );
    if (result.rows.length === 0) {
      return res.json({ valid: false, reason: 'Key not found' });
    }
    const k = result.rows[0];
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

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [keys, txns, revenue, recent, success, pending, failed] = await Promise.all([
      db('SELECT COUNT(*) as c, COALESCE(SUM(is_active),0) as active FROM api_keys'),
      db('SELECT COUNT(*) as c FROM transactions'),
      db("SELECT COALESCE(SUM(amount),0) as total FROM transactions WHERE status = 'success'"),
      db("SELECT COUNT(*) as c FROM transactions WHERE created_at >= datetime('now', '-24 hours')"),
      db("SELECT COUNT(*) as c FROM transactions WHERE status = 'success'"),
      db("SELECT COUNT(*) as c FROM transactions WHERE status = 'pending'"),
      db("SELECT COUNT(*) as c FROM transactions WHERE status = 'failed'"),
    ]);

    res.json({
      total_keys: keys.rows[0].c,
      active_keys: keys.rows[0].active || 0,
      total_transactions: txns.rows[0].c,
      recent_transactions: recent.rows[0].c,
      total_revenue: revenue.rows[0].total,
      success_count: success.rows[0].c,
      pending_count: pending.rows[0].c,
      failed_count: failed.rows[0].c,
    });
  } catch (e) {
    console.error('Stats error:', e);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/api/admin/transactions', adminAuth, async (req, res) => {
  try {
    const { status, limit = 50, offset = 0 } = req.query;
    const lim = Math.min(parseInt(limit, 10) || 50, 500);
    const off = Math.max(parseInt(offset, 10) || 0, 0);

    let sql, args;
    if (status && status !== 'all') {
      sql = 'SELECT * FROM transactions WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?';
      args = [status, lim, off];
    } else {
      sql = 'SELECT * FROM transactions ORDER BY created_at DESC LIMIT ? OFFSET ?';
      args = [lim, off];
    }

    const result = await db(sql, args);
    res.json(result.rows);
  } catch (e) {
    console.error('Transactions error:', e);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/admin/charts', adminAuth, async (req, res) => {
  try {
    const [daily, byStatus, byApp, recentRequests] = await Promise.all([
      db(`SELECT date(created_at) as day, COUNT(*) as count,
                 COALESCE(SUM(CASE WHEN status='success' THEN amount ELSE 0 END), 0) as revenue
          FROM transactions
          WHERE created_at >= datetime('now', '-7 days')
          GROUP BY date(created_at) ORDER BY day ASC`),
      db('SELECT status, COUNT(*) as count FROM transactions GROUP BY status'),
      db(`SELECT app_identifier, COUNT(*) as count,
                 COALESCE(SUM(CASE WHEN status='success' THEN amount ELSE 0 END), 0) as revenue
          FROM transactions GROUP BY app_identifier ORDER BY count DESC LIMIT 10`),
      db(`SELECT endpoint, method, COUNT(*) as count FROM request_log
          WHERE created_at >= datetime('now', '-7 days')
          GROUP BY endpoint, method ORDER BY count DESC LIMIT 10`),
    ]);

    res.json({
      daily: daily.rows,
      byStatus: byStatus.rows,
      byApp: byApp.rows,
      recentRequests: recentRequests.rows,
    });
  } catch (e) {
    console.error('Charts error:', e);
    res.status(500).json({ error: 'Failed to fetch charts' });
  }
});

// ============================================================
// STK PUSH
// ============================================================
app.post('/api/pay/stk-push', authenticateApiKey, async (req, res) => {
  try {
    const { phone_number, amount, external_reference, callback_url } = req.body || {};
    const channelId = req.apiKeyRecord.channel_id;

    if (!phone_number || !amount || !external_reference) {
      await logRequest(req, req.apiKeyRecord, 400);
      return res.status(400).json({
        error: 'phone_number, amount, and external_reference are required',
      });
    }

    if (typeof external_reference !== 'string' || external_reference.length > 100) {
      await logRequest(req, req.apiKeyRecord, 400);
      return res.status(400).json({ error: 'external_reference must be a string ≤ 100 chars' });
    }

    let phone = String(phone_number).replace(/\s+/g, '').replace(/-/g, '');
    if (phone.startsWith('+')) phone = phone.slice(1);
    if (phone.startsWith('0')) phone = '254' + phone.slice(1);
    if (phone.startsWith('7') || phone.startsWith('1')) phone = '254' + phone;

    if (!/^254[17]\d{8}$/.test(phone)) {
      await logRequest(req, req.apiKeyRecord, 400);
      return res.status(400).json({ error: 'Invalid phone number format' });
    }

    const numericAmount = Number(amount);
    if (!Number.isFinite(numericAmount) || numericAmount <= 0 || numericAmount > 500000) {
      await logRequest(req, req.apiKeyRecord, 400);
      return res.status(400).json({ error: 'Amount must be between 1 and 500,000 KES' });
    }

    const existing = await db(
      'SELECT * FROM transactions WHERE external_reference = ?',
      [external_reference]
    );
    if (existing.rows.length > 0) {
      await logRequest(req, req.apiKeyRecord, 200);
      return res.json({
        success: true,
        external_reference,
        idempotent: true,
        transaction: existing.rows[0],
      });
    }

    await db(
      `INSERT INTO transactions (external_reference, app_identifier, channel_id, phone_number, amount, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      [external_reference, req.apiKeyRecord.app_identifier, channelId, phone, numericAmount]
    );

    const payload = {
      amount: numericAmount,
      phone_number: phone,
      channel_id: channelId,
      provider: 'm-pesa',
      external_reference,
      callback_url: callback_url || `${req.protocol}://${req.get('host')}/api/lycash/callback`,
    };

    let response, data;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 25000);
      response = await fetch('https://backend.payhero.co.ke/api/v2/payments', {
        method: 'POST',
        headers: {
          Authorization: getPayHeroAuthHeader(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      clearTimeout(timer);
      data = await response.json().catch(() => ({}));
    } catch (e) {
      console.error('Gateway fetch error:', e.message);
      await db(
        `UPDATE transactions SET status = 'failed', callback_payload = ?, updated_at = CURRENT_TIMESTAMP
         WHERE external_reference = ?`,
        [JSON.stringify({ error: e.message }), external_reference]
      );
      await logRequest(req, req.apiKeyRecord, 502);
      return res.status(502).json({ error: 'Gateway unreachable', message: e.message });
    }

    if (!response.ok) {
      await db(
        `UPDATE transactions SET status = 'failed', callback_payload = ?, updated_at = CURRENT_TIMESTAMP
         WHERE external_reference = ?`,
        [JSON.stringify(data), external_reference]
      );
      await logRequest(req, req.apiKeyRecord, response.status);
      return res.status(response.status).json({
        error: 'Gateway API error',
        message: data.error_message || data.message || 'STK Push failed',
        details: data,
      });
    }

    const gatewayRef = extractGatewayRef(data);
    if (gatewayRef) {
      await db(
        `UPDATE transactions SET payhero_reference = ?, updated_at = CURRENT_TIMESTAMP
         WHERE external_reference = ?`,
        [gatewayRef, external_reference]
      );
    }

    await logRequest(req, req.apiKeyRecord, 200);
    res.json({ success: true, external_reference, gateway_response: data });
  } catch (e) {
    console.error('STK push error:', e);
    if (req.apiKeyRecord) await logRequest(req, req.apiKeyRecord, 500);
    res.status(500).json({ error: 'Internal server error', message: e.message });
  }
});

// ============================================================
// STATUS QUERY
// ============================================================
app.get('/api/pay/status/:reference', authenticateApiKey, async (req, res) => {
  try {
    const { reference } = req.params;
    const channelId = req.apiKeyRecord.channel_id;

    const t = await db(
      `SELECT * FROM transactions
       WHERE external_reference = ?
          OR payhero_reference = ?
          OR mpesa_receipt = ?`,
      [reference, reference, reference]
    );

    let txn = t.rows.length > 0 ? t.rows[0] : null;

    if (txn && txn.status !== 'pending' && txn.verified_with_payhero) {
      await logRequest(req, req.apiKeyRecord, 200);
      return res.json({ source: 'local', transaction: txn });
    }

    const lookupRef = txn ? txn.external_reference : reference;

    let response, data;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 20000);
      response = await fetch(
        `https://backend.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(lookupRef)}&channel_id=${encodeURIComponent(channelId)}`,
        {
          headers: { Authorization: getPayHeroAuthHeader() },
          signal: controller.signal,
        }
      );
      clearTimeout(timer);
      data = await response.json().catch(() => ({}));
    } catch (e) {
      console.error('Gateway status fetch error:', e.message);
      if (txn) {
        await logRequest(req, req.apiKeyRecord, 200);
        return res.json({ source: 'local', transaction: txn, note: 'Gateway unreachable' });
      }
      await logRequest(req, req.apiKeyRecord, 502);
      return res.status(502).json({ error: 'Gateway unreachable', message: e.message });
    }

    if (!response.ok) {
      if (txn) {
        await logRequest(req, req.apiKeyRecord, 200);
        return res.json({ source: 'local', transaction: txn });
      }
      await logRequest(req, req.apiKeyRecord, 404);
      return res.status(404).json({
        error: 'Transaction not found',
        reference,
        message: 'No transaction with this reference exists in LyCash records.',
      });
    }

    const normalized = normalizeStatus(
      data.status || data.Status || data.response?.Status
    );

    const gatewayRef = extractGatewayRef(data) || (txn ? txn.payhero_reference : null);
    const mpesaReceipt =
      data.mpesa_receipt ||
      data.response?.MPESA_Reference ||
      (txn ? txn.mpesa_receipt : null);

    if (normalized !== 'unknown') {
      if (txn) {
        await db(
          `UPDATE transactions
           SET status = ?,
               verified_with_payhero = 1,
               payhero_reference = COALESCE(?, payhero_reference),
               mpesa_receipt = COALESCE(?, mpesa_receipt),
               updated_at = CURRENT_TIMESTAMP
           WHERE external_reference = ?`,
          [normalized, gatewayRef || null, mpesaReceipt || null, txn.external_reference]
        );
      } else {
        try {
          await db(
            `INSERT OR IGNORE INTO transactions
             (external_reference, app_identifier, channel_id, payhero_reference,
              mpesa_receipt, status, verified_with_payhero, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`,
            [reference, req.apiKeyRecord.app_identifier, channelId,
             gatewayRef || null, mpesaReceipt || null, normalized]
          );
        } catch (e) {
          console.error('Synthetic insert failed:', e.message);
        }
      }
    }

    await logRequest(req, req.apiKeyRecord, 200);
    res.json({ source: 'gateway', transaction: data });
  } catch (e) {
    console.error('Status query error:', e);
    if (req.apiKeyRecord) await logRequest(req, req.apiKeyRecord, 500);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// CALLBACK — primary handler
// ============================================================
async function handleGatewayCallback(req, res) {
  const payload = req.body || {};
  try {
    console.log('Callback:', JSON.stringify(payload));

    const response = payload.response || payload;
    const externalRef =
      response.ExternalReference ||
      response.User_Reference ||
      payload.external_reference ||
      payload.reference;
    const merchantRef = response.MerchantRequestID || '';
    const checkoutId = response.CheckoutRequestID || '';
    const mpesaRef = response.MPESA_Reference || response.MpesaReceiptNumber || response.Transaction_Reference || '';
    const channelId = response.ChannelID || response.channel_id || '';

    console.log('Extracted IDs:', { externalRef, merchantRef, checkoutId, mpesaRef, channelId });

    try {
      await db(
        `INSERT INTO callback_log (external_reference, raw_payload, source_ip)
         VALUES (?, ?, ?)`,
        [externalRef || null, JSON.stringify(payload), req.ip]
      );
    } catch (e) {
      console.error('callback_log insert failed:', e.message);
    }

    if (!externalRef && !mpesaRef && !merchantRef && !checkoutId) {
      return res.status(200).json({ status: 'received_no_reference' });
    }

    let txn = null;
    const lookups = [
      ['external_reference', externalRef],
      ['payhero_reference', merchantRef],
      ['payhero_reference', checkoutId],
      ['payhero_reference', mpesaRef],
      ['mpesa_receipt', mpesaRef],
    ].filter(([, v]) => v);

    for (const [col, val] of lookups) {
      const r = await db(`SELECT * FROM transactions WHERE ${col} = ? LIMIT 1`, [val]);
      if (r.rows.length > 0) {
        txn = r.rows[0];
        console.log(`Matched transaction by ${col}=${val}`);
        break;
      }
    }

    if (!txn) {
      console.warn('Callback for unknown transaction:', { externalRef, merchantRef, checkoutId, mpesaRef });
      return res.status(200).json({ status: 'received_unknown_transaction' });
    }

    let verified = false;
    let verifiedStatus = 'unknown';
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      const vr = await fetch(
        `https://backend.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(txn.external_reference)}&channel_id=${encodeURIComponent(txn.channel_id)}`,
        { headers: { Authorization: getPayHeroAuthHeader() }, signal: controller.signal }
      );
      clearTimeout(timer);
      if (vr.ok) {
        const vd = await vr.json();
        verifiedStatus = normalizeStatus(vd.status || vd.Status || vd.response?.Status || response.Status);
        verified = verifiedStatus !== 'unknown';
      }
    } catch (e) {
      console.error('Verify failed:', e.message);
    }

    if (!verified && mpesaRef && (response.Status || '').toLowerCase().includes('success')) {
      verifiedStatus = 'success';
      verified = true;
    }

    const callbackStatus = normalizeStatus(response.Status || payload.status);
    let finalStatus = verified ? verifiedStatus : (callbackStatus === 'success' ? 'pending' : callbackStatus);

    if (txn.status === 'success' && finalStatus !== 'success') {
      return res.status(200).json({ status: 'ignored_downgrade' });
    }

    await db(
      `UPDATE transactions
       SET status = ?,
           payhero_reference = COALESCE(?, payhero_reference),
           mpesa_receipt = COALESCE(?, mpesa_receipt),
           callback_payload = ?,
           verified_with_payhero = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE external_reference = ?`,
      [
        finalStatus,
        merchantRef || checkoutId || mpesaRef || null,
        mpesaRef || null,
        JSON.stringify(payload),
        verified ? 1 : 0,
        txn.external_reference,
      ]
    );

    if (txn.app_identifier) {
      const kr = await db('SELECT * FROM api_keys WHERE app_identifier = ?', [txn.app_identifier]);
      const apiKey = kr.rows[0];
      if (apiKey?.webhook_url) {
        const forwardPayload = {
          event: 'payment.' + finalStatus,
          external_reference: txn.external_reference,
          gateway_reference: merchantRef || txn.payhero_reference,
          mpesa_receipt: mpesaRef,
          amount: txn.amount,
          phone_number: txn.phone_number,
          status: finalStatus,
          verified,
          timestamp: new Date().toISOString(),
        };
        const headers = {
          'Content-Type': 'application/json',
          'X-LyCash-Event': 'payment.' + finalStatus,
        };
        const sig = signWebhookPayload(apiKey.webhook_secret, forwardPayload);
        if (sig) headers['X-LyCash-Signature'] = sig;

        fetch(apiKey.webhook_url, {
          method: 'POST',
          headers,
          body: JSON.stringify(forwardPayload),
        }).catch(e => console.error('Webhook forward failed:', e.message));
      }
    }

    res.status(200).json({ status: 'received', verified });
  } catch (e) {
    console.error('Callback error:', e);
    res.status(200).json({ status: 'received_with_error' });
  }
}

app.post('/api/lycash/callback', handleGatewayCallback);
app.post('/api/payhero/callback', handleGatewayCallback); // legacy alias

// ============================================================
// SPA FALLBACK
// ============================================================
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) next();
  });
});

// ============================================================
// ERROR HANDLER
// ============================================================
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  if (res.headersSent) return next(err);
  res.status(err.statusCode || 500).json({ error: 'Internal server error' });
});

// ============================================================
// STARTUP
// ============================================================
(async () => {
  try {
    await ensureSchema();
    await refreshKeyCache();

    app.listen(PORT, () => {
      console.log(`${BRAND} listening on port ${PORT}`);
    });

    setInterval(refreshKeyCache, 60_000);
  } catch (e) {
    console.error('FATAL startup error:', e);
    process.exit(1);
  }
})();
