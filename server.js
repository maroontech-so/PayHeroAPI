require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// LOCAL SQLITE BUFFER
// ============================================================
// This is the primary read/write store for the running instance.
// Writes are mirrored to Turso asynchronously for durability.
// On startup, we hydrate from Turso so redeploys don't lose data.
const DB_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const LOCAL_DB_PATH = path.join(DB_DIR, 'buffer.db');

const local = new Database(LOCAL_DB_PATH);
local.pragma('journal_mode = WAL');
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
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now')),
      last_used_at TEXT
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_reference TEXT UNIQUE,
      app_identifier TEXT,
      payhero_reference TEXT,
      channel_id TEXT,
      phone_number TEXT,
      amount REAL,
      status TEXT DEFAULT 'pending',
      callback_payload TEXT,
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

    CREATE INDEX IF NOT EXISTS idx_txn_ext_ref ON transactions(external_reference);
    CREATE INDEX IF NOT EXISTS idx_txn_payhero_ref ON transactions(payhero_reference);
    CREATE INDEX IF NOT EXISTS idx_txn_status ON transactions(status);
    CREATE INDEX IF NOT EXISTS idx_log_created ON request_log(created_at);
  `);
  console.log('Local DB schema ready');
}

initLocalSchema();

// ============================================================
// TURSO CLOUD (durability layer)
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
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_used_at DATETIME
    )
  `);
  await turso.execute(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_reference TEXT UNIQUE,
      app_identifier TEXT,
      payhero_reference TEXT,
      channel_id TEXT,
      phone_number TEXT,
      amount REAL,
      status TEXT DEFAULT 'pending',
      callback_payload TEXT,
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
}

// Sync a single write to Turso (fire and forget, non-blocking)
function syncToTurso(sql, args = []) {
  if (!turso || !tursoReady) return;
  turso.execute({ sql, args }).catch((e) => {
    console.error('Turso sync error:', e.message, '| sql:', sql.slice(0, 80));
  });
}

// Hydrate local DB from Turso on startup.
// Local is authoritative for the running instance; Turso is the backup.
// We merge: pull anything from Turso that isn't in local.
async function hydrateFromTurso() {
  if (!turso) {
    console.log('No Turso — skipping hydration');
    return;
  }

  try {
    await initTursoSchema();
    tursoReady = true;
    console.log('Turso schema ready');

    // Pull API keys from Turso that aren't in local
    const remoteKeys = await turso.execute('SELECT * FROM api_keys');
    const insertKey = local.prepare(`
      INSERT OR IGNORE INTO api_keys
      (key_hash, key_preview, name, app_identifier, channel_id, is_active, created_at, last_used_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let keyCount = 0;
    for (const k of remoteKeys.rows) {
      const info = insertKey.run(
        k.key_hash, k.key_preview, k.name, k.app_identifier,
        k.channel_id, k.is_active, k.created_at, k.last_used_at
      );
      if (info.changes) keyCount++;
    }

    // Pull transactions from Turso that aren't in local
    const remoteTxns = await turso.execute('SELECT * FROM transactions');
    const insertTxn = local.prepare(`
      INSERT OR IGNORE INTO transactions
      (external_reference, app_identifier, payhero_reference, channel_id,
       phone_number, amount, status, callback_payload, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let txnCount = 0;
    for (const t of remoteTxns.rows) {
      const info = insertTxn.run(
        t.external_reference, t.app_identifier, t.payhero_reference,
        t.channel_id, t.phone_number, t.amount, t.status,
        t.callback_payload, t.created_at, t.updated_at
      );
      if (info.changes) txnCount++;
    }

    // Optionally: push any local rows that Turso doesn't have yet
    // (In case Turso is behind — e.g., last instance wrote locally then crashed)
    const localKeys = local.prepare('SELECT * FROM api_keys').all();
    for (const k of localKeys) {
      syncToTurso(
        `INSERT OR IGNORE INTO api_keys
         (key_hash, key_preview, name, app_identifier, channel_id, is_active, created_at, last_used_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [k.key_hash, k.key_preview, k.name, k.app_identifier,
         k.channel_id, k.is_active, k.created_at, k.last_used_at]
      );
    }

    const localTxns = local.prepare('SELECT * FROM transactions').all();
    for (const t of localTxns) {
      syncToTurso(
        `INSERT OR IGNORE INTO transactions
         (external_reference, app_identifier, payhero_reference, channel_id,
          phone_number, amount, status, callback_payload, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [t.external_reference, t.app_identifier, t.payhero_reference,
         t.channel_id, t.phone_number, t.amount, t.status,
         t.callback_payload, t.created_at, t.updated_at]
      );
    }

    console.log(`Hydrated from Turso: +${keyCount} keys, +${txnCount} transactions`);
  } catch (e) {
    console.error('Hydration failed:', e.message);
    console.log('Continuing with local-only data');
  }
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// ============================================================
// HELPERS
// ============================================================
function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function generateApiKey() {
  return 'phk_' + crypto.randomBytes(32).toString('hex');
}

function getPayHeroAuthHeader() {
  const credentials = Buffer.from(
    `${process.env.PAYHERO_API_USERNAME}:${process.env.PAYHERO_API_PASSWORD}`
  ).toString('base64');
  return `Basic ${credentials}`;
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
      [
        apiKeyRecord ? apiKeyRecord.id : null,
        apiKeyRecord ? apiKeyRecord.app_identifier : null,
        req.path,
        req.method,
        statusCode,
      ]
    );
  } catch (e) {
    console.error('Log error:', e.message);
  }
}

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

  local.prepare(
    "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?"
  ).run(keyRecord.id);
  syncToTurso(
    "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?",
    [keyRecord.id]
  );

  req.apiKeyRecord = keyRecord;
  next();
}

function adminAuth(req, res, next) {
  const adminToken = req.headers['x-admin-token'] || req.query.admin_token;
  if (adminToken !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}

// ============================================================
// HEALTH CHECK (must be first — Render probes this)
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

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === process.env.ADMIN_PASSWORD) {
    return res.json({ success: true });
  }
  res.status(403).json({ error: 'Invalid password' });
});

app.get('/api/admin/keys', adminAuth, (req, res) => {
  try {
    const rows = local.prepare(
      'SELECT id, key_preview, name, app_identifier, channel_id, is_active, created_at, last_used_at FROM api_keys ORDER BY created_at DESC'
    ).all();
    res.json(rows);
  } catch (e) {
    console.error('List keys error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/keys', adminAuth, (req, res) => {
  try {
    const { name, app_identifier, channel_id } = req.body;

    if (!name || !channel_id) {
      return res.status(400).json({ error: 'Name and Channel ID are required' });
    }

    const newKey = generateApiKey();
    const keyHash = hashKey(newKey);
    const preview = newKey.slice(0, 12) + '...' + newKey.slice(-4);

    local.prepare(
      `INSERT INTO api_keys (key_hash, key_preview, name, app_identifier, channel_id)
       VALUES (?, ?, ?, ?, ?)`
    ).run(keyHash, preview, name, app_identifier || name, channel_id);

    syncToTurso(
      `INSERT OR IGNORE INTO api_keys (key_hash, key_preview, name, app_identifier, channel_id)
       VALUES (?, ?, ?, ?, ?)`,
      [keyHash, preview, name, app_identifier || name, channel_id]
    );

    res.json({
      api_key: newKey,
      message: 'Store this key securely. It will not be shown again.',
      name,
      channel_id,
    });
  } catch (e) {
    console.error('Create key error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/admin/keys/:id/revoke', adminAuth, (req, res) => {
  try {
    local.prepare('UPDATE api_keys SET is_active = 0 WHERE id = ?').run(req.params.id);
    syncToTurso('UPDATE api_keys SET is_active = 0 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/admin/keys/:id/activate', adminAuth, (req, res) => {
  try {
    local.prepare('UPDATE api_keys SET is_active = 1 WHERE id = ?').run(req.params.id);
    syncToTurso('UPDATE api_keys SET is_active = 1 WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
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
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/keys/verify', adminAuth, (req, res) => {
  try {
    const { api_key } = req.body;
    if (!api_key) return res.status(400).json({ error: 'api_key required' });

    const keyHash = hashKey(api_key);
    const k = local
      .prepare('SELECT id, name, channel_id, is_active FROM api_keys WHERE key_hash = ?')
      .get(keyHash);

    if (!k) {
      return res.json({ valid: false, reason: 'Key not found' });
    }

    res.json({
      valid: k.is_active === 1,
      name: k.name,
      channel_id: k.channel_id,
      active: k.is_active === 1,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  try {
    const keys = local.prepare(
      'SELECT COUNT(*) as c, SUM(is_active) as active FROM api_keys'
    ).get();
    const txns = local.prepare('SELECT COUNT(*) as c FROM transactions').get();
    const revenue = local.prepare(
      "SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE status = 'success'"
    ).get();
    const recent = local.prepare(
      "SELECT COUNT(*) as c FROM transactions WHERE created_at >= datetime('now', '-24 hours')"
    ).get();
    const successCount = local.prepare(
      "SELECT COUNT(*) as c FROM transactions WHERE status = 'success'"
    ).get();
    const pendingCount = local.prepare(
      "SELECT COUNT(*) as c FROM transactions WHERE status = 'pending'"
    ).get();
    const failedCount = local.prepare(
      "SELECT COUNT(*) as c FROM transactions WHERE status = 'failed'"
    ).get();

    res.json({
      total_keys: keys.c,
      active_keys: keys.active || 0,
      total_transactions: txns.c,
      recent_transactions: recent.c,
      total_revenue: revenue.total,
      success_count: successCount.c,
      pending_count: pendingCount.c,
      failed_count: failedCount.c,
    });
  } catch (e) {
    console.error('Stats error:', e);
    res.status(500).json({ error: e.message });
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
    args.push(parseInt(limit), parseInt(offset));

    const rows = local.prepare(sql).all(...args);
    res.json(rows);
  } catch (e) {
    console.error('Transactions error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/charts', adminAuth, (req, res) => {
  try {
    const daily = local.prepare(`
      SELECT date(created_at) as day,
             COUNT(*) as count,
             COALESCE(SUM(CASE WHEN status='success' THEN amount ELSE 0 END), 0) as revenue
      FROM transactions
      WHERE created_at >= datetime('now', '-7 days')
      GROUP BY date(created_at)
      ORDER BY day ASC
    `).all();

    const byStatus = local.prepare(`
      SELECT status, COUNT(*) as count FROM transactions GROUP BY status
    `).all();

    const byApp = local.prepare(`
      SELECT app_identifier, COUNT(*) as count,
             COALESCE(SUM(CASE WHEN status='success' THEN amount ELSE 0 END), 0) as revenue
      FROM transactions
      GROUP BY app_identifier
      ORDER BY count DESC
      LIMIT 10
    `).all();

    const recentRequests = local.prepare(`
      SELECT endpoint, method, COUNT(*) as count
      FROM request_log
      WHERE created_at >= datetime('now', '-7 days')
      GROUP BY endpoint, method
      ORDER BY count DESC
      LIMIT 10
    `).all();

    res.json({ daily, byStatus, byApp, recentRequests });
  } catch (e) {
    console.error('Charts error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
// PAYHERO PROXY ROUTES
// ============================================================

app.post('/api/pay/stk-push', authenticateApiKey, async (req, res) => {
  try {
    const { phone_number, amount, external_reference, callback_url } = req.body;
    const channelId = req.apiKeyRecord.channel_id;

    if (!phone_number || !amount || !external_reference) {
      logRequest(req.apiKeyRecord, req, 400);
      return res.status(400).json({
        error: 'phone_number, amount, and external_reference are required',
      });
    }

    local.prepare(
      `INSERT OR IGNORE INTO transactions
       (external_reference, app_identifier, channel_id, phone_number, amount, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`
    ).run(
      external_reference,
      req.apiKeyRecord.app_identifier,
      channelId,
      phone_number,
      amount
    );
    syncToTurso(
      `INSERT OR IGNORE INTO transactions
       (external_reference, app_identifier, channel_id, phone_number, amount, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      [external_reference, req.apiKeyRecord.app_identifier, channelId, phone_number, amount]
    );

    const payheroPayload = {
      amount,
      phone_number,
      channel_id: channelId,
      external_reference,
      callback_url:
        callback_url ||
        `${req.protocol}://${req.get('host')}/api/payhero/callback`,
    };

    const response = await fetch('https://api.payhero.co.ke/api/v2/payments', {
      method: 'POST',
      headers: {
        Authorization: getPayHeroAuthHeader(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payheroPayload),
    });

    const data = await response.json();

    if (!response.ok) {
      logRequest(req.apiKeyRecord, req, response.status);
      return res.status(response.status).json({
        error: 'PayHero API error',
        details: data,
      });
    }

    if (data.reference) {
      local.prepare(
        "UPDATE transactions SET payhero_reference = ?, updated_at = datetime('now') WHERE external_reference = ?"
      ).run(data.reference, external_reference);
      syncToTurso(
        "UPDATE transactions SET payhero_reference = ?, updated_at = datetime('now') WHERE external_reference = ?",
        [data.reference, external_reference]
      );
    }

    logRequest(req.apiKeyRecord, req, 200);
    res.json({ success: true, external_reference, payhero_response: data });
  } catch (error) {
    console.error('STK Push error:', error);
    logRequest(req.apiKeyRecord, req, 500);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/pay/status/:reference', authenticateApiKey, async (req, res) => {
  try {
    const { reference } = req.params;
    const channelId = req.apiKeyRecord.channel_id;

    const t = local.prepare(
      'SELECT * FROM transactions WHERE external_reference = ? OR payhero_reference = ?'
    ).get(reference, reference);

    if (t && t.status !== 'pending') {
      logRequest(req.apiKeyRecord, req, 200);
      return res.json({ source: 'local', transaction: t });
    }

    const response = await fetch(
      `https://api.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(reference)}&channel_id=${channelId}`,
      { headers: { Authorization: getPayHeroAuthHeader() } }
    );

    const data = await response.json();

    if (!response.ok) {
      logRequest(req.apiKeyRecord, req, response.status);
      return res.status(response.status).json({
        error: 'PayHero API error',
        details: data,
      });
    }

    logRequest(req.apiKeyRecord, req, 200);
    res.json({ source: 'payhero', transaction: data });
  } catch (error) {
    console.error('Status query error:', error);
    logRequest(req.apiKeyRecord, req, 500);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// PAYHERO CALLBACK
// ============================================================
app.post('/api/payhero/callback', (req, res) => {
  try {
    const payload = req.body;
    console.log('PayHero Callback:', JSON.stringify(payload, null, 2));

    const externalRef = payload.external_reference || payload.reference;
    const status = payload.status || payload.transaction_status;
    const payheroRef = payload.payhero_reference || payload.mpesa_receipt;

    if (externalRef) {
      local.prepare(
        `UPDATE transactions
         SET status = ?,
             payhero_reference = COALESCE(?, payhero_reference),
             callback_payload = ?,
             updated_at = datetime('now')
         WHERE external_reference = ?`
      ).run(status, payheroRef, JSON.stringify(payload), externalRef);

      syncToTurso(
        `UPDATE transactions
         SET status = ?,
             payhero_reference = COALESCE(?, payhero_reference),
             callback_payload = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE external_reference = ?`,
        [status, payheroRef, JSON.stringify(payload), externalRef]
      );
    }

    res.status(200).json({ status: 'received' });
  } catch (error) {
    console.error('Callback error:', error);
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
// START (non-blocking, for Render health checks)
// ============================================================
app.listen(PORT, () => {
  console.log(`PayHero Central API listening on port ${PORT}`);

  hydrateFromTurso()
    .then(() => console.log('Startup complete'))
    .catch((e) => console.error('Startup error:', e.message));
});
