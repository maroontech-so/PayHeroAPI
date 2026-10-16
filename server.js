require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// TURSO DATABASE SETUP
// ============================================================
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

async function initDB() {
  await db.execute(`
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

  await db.execute(`
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

  // Request log table for stats
  await db.execute(`
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

  console.log('Database initialized');
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

async function logRequest(apiKeyRecord, req, statusCode) {
  try {
    await db.execute({
      sql: 'INSERT INTO request_log (api_key_id, app_identifier, endpoint, method, status_code) VALUES (?, ?, ?, ?, ?)',
      args: [
        apiKeyRecord ? apiKeyRecord.id : null,
        apiKeyRecord ? apiKeyRecord.app_identifier : null,
        req.path,
        req.method,
        statusCode,
      ],
    });
  } catch (e) {
    console.error('Log error:', e.message);
  }
}

async function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;

  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }

  const keyHash = hashKey(apiKey);
  const result = await db.execute({
    sql: 'SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1',
    args: [keyHash],
  });

  if (result.rows.length === 0) {
    await logRequest(null, req, 403);
    return res.status(403).json({ error: 'Invalid or inactive API key' });
  }

  const keyRecord = result.rows[0];
  await db.execute({
    sql: 'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?',
    args: [keyRecord.id],
  });

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
// ADMIN ROUTES
// ============================================================

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === process.env.ADMIN_PASSWORD) {
    return res.json({ success: true });
  }
  res.status(403).json({ error: 'Invalid password' });
});

app.get('/api/admin/keys', adminAuth, async (req, res) => {
  const result = await db.execute(
    'SELECT id, key_preview, name, app_identifier, channel_id, is_active, created_at, last_used_at FROM api_keys ORDER BY created_at DESC'
  );
  res.json(result.rows);
});

app.post('/api/admin/keys', adminAuth, async (req, res) => {
  const { name, app_identifier, channel_id } = req.body;

  if (!name || !channel_id) {
    return res.status(400).json({ error: 'Name and Channel ID are required' });
  }

  const newKey = generateApiKey();
  const keyHash = hashKey(newKey);
  const preview = newKey.slice(0, 12) + '...' + newKey.slice(-4);

  await db.execute({
    sql: 'INSERT INTO api_keys (key_hash, key_preview, name, app_identifier, channel_id) VALUES (?, ?, ?, ?, ?)',
    args: [keyHash, preview, name, app_identifier || name, channel_id],
  });

  res.json({
    api_key: newKey,
    message: 'Store this key securely. It will not be shown again.',
    name,
    channel_id,
  });
});

app.patch('/api/admin/keys/:id/revoke', adminAuth, async (req, res) => {
  await db.execute({
    sql: 'UPDATE api_keys SET is_active = 0 WHERE id = ?',
    args: [req.params.id],
  });
  res.json({ success: true });
});

app.patch('/api/admin/keys/:id/activate', adminAuth, async (req, res) => {
  await db.execute({
    sql: 'UPDATE api_keys SET is_active = 1 WHERE id = ?',
    args: [req.params.id],
  });
  res.json({ success: true });
});

app.delete('/api/admin/keys/:id', adminAuth, async (req, res) => {
  await db.execute({
    sql: 'DELETE FROM api_keys WHERE id = ?',
    args: [req.params.id],
  });
  res.json({ success: true });
});

// Verify a key (used by docs terminal)
app.post('/api/admin/keys/verify', adminAuth, async (req, res) => {
  const { api_key } = req.body;
  if (!api_key) return res.status(400).json({ error: 'api_key required' });

  const keyHash = hashKey(api_key);
  const result = await db.execute({
    sql: 'SELECT id, name, channel_id, is_active FROM api_keys WHERE key_hash = ?',
    args: [keyHash],
  });

  if (result.rows.length === 0) {
    return res.json({ valid: false, reason: 'Key not found' });
  }

  const k = result.rows[0];
  res.json({
    valid: k.is_active === 1,
    name: k.name,
    channel_id: k.channel_id,
    active: k.is_active === 1,
  });
});

// Dashboard stats
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const [keys, txns, revenue, recent] = await Promise.all([
    db.execute('SELECT COUNT(*) as c, SUM(is_active) as active FROM api_keys'),
    db.execute('SELECT COUNT(*) as c FROM transactions'),
    db.execute("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE status = 'success'"),
    db.execute("SELECT COUNT(*) as c FROM transactions WHERE created_at >= datetime('now', '-24 hours')"),
  ]);

  const successCount = await db.execute("SELECT COUNT(*) as c FROM transactions WHERE status = 'success'");
  const pendingCount = await db.execute("SELECT COUNT(*) as c FROM transactions WHERE status = 'pending'");
  const failedCount = await db.execute("SELECT COUNT(*) as c FROM transactions WHERE status = 'failed'");

  res.json({
    total_keys: keys.rows[0].c,
    active_keys: keys.rows[0].active || 0,
    total_transactions: txns.rows[0].c,
    recent_transactions: recent.rows[0].c,
    total_revenue: revenue.rows[0].total,
    success_count: successCount.rows[0].c,
    pending_count: pendingCount.rows[0].c,
    failed_count: failedCount.rows[0].c,
  });
});

// Transactions list with filters
app.get('/api/admin/transactions', adminAuth, async (req, res) => {
  const { status, limit = 50, offset = 0 } = req.query;

  let sql = 'SELECT * FROM transactions';
  const args = [];

  if (status && status !== 'all') {
    sql += ' WHERE status = ?';
    args.push(status);
  }

  sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  args.push(parseInt(limit), parseInt(offset));

  const result = await db.execute({ sql, args });
  res.json(result.rows);
});

// Chart data: transactions over last 7 days
app.get('/api/admin/charts', adminAuth, async (req, res) => {
  const daily = await db.execute(`
    SELECT date(created_at) as day,
           COUNT(*) as count,
           COALESCE(SUM(CASE WHEN status='success' THEN amount ELSE 0 END), 0) as revenue
    FROM transactions
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY date(created_at)
    ORDER BY day ASC
  `);

  const byStatus = await db.execute(`
    SELECT status, COUNT(*) as count FROM transactions GROUP BY status
  `);

  const byApp = await db.execute(`
    SELECT app_identifier, COUNT(*) as count,
           COALESCE(SUM(CASE WHEN status='success' THEN amount ELSE 0 END), 0) as revenue
    FROM transactions
    GROUP BY app_identifier
    ORDER BY count DESC
    LIMIT 10
  `);

  const recentRequests = await db.execute(`
    SELECT endpoint, method, COUNT(*) as count
    FROM request_log
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY endpoint, method
    ORDER BY count DESC
    LIMIT 10
  `);

  res.json({
    daily: daily.rows,
    byStatus: byStatus.rows,
    byApp: byApp.rows,
    recentRequests: recentRequests.rows,
  });
});

// ============================================================
// PAYHERO PROXY ROUTES
// ============================================================

app.post('/api/pay/stk-push', authenticateApiKey, async (req, res) => {
  try {
    const { phone_number, amount, external_reference, callback_url } = req.body;
    const channelId = req.apiKeyRecord.channel_id;

    if (!phone_number || !amount || !external_reference) {
      await logRequest(req.apiKeyRecord, req, 400);
      return res.status(400).json({
        error: 'phone_number, amount, and external_reference are required',
      });
    }

    await db.execute({
      sql: `INSERT OR IGNORE INTO transactions
            (external_reference, app_identifier, channel_id, phone_number, amount, status)
            VALUES (?, ?, ?, ?, ?, 'pending')`,
      args: [
        external_reference,
        req.apiKeyRecord.app_identifier,
        channelId,
        phone_number,
        amount,
      ],
    });

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
      await logRequest(req.apiKeyRecord, req, response.status);
      return res.status(response.status).json({
        error: 'PayHero API error',
        details: data,
      });
    }

    if (data.reference) {
      await db.execute({
        sql: 'UPDATE transactions SET payhero_reference = ?, updated_at = CURRENT_TIMESTAMP WHERE external_reference = ?',
        args: [data.reference, external_reference],
      });
    }

    await logRequest(req.apiKeyRecord, req, 200);
    res.json({
      success: true,
      external_reference,
      payhero_response: data,
    });
  } catch (error) {
    console.error('STK Push error:', error);
    await logRequest(req.apiKeyRecord, req, 500);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/pay/status/:reference', authenticateApiKey, async (req, res) => {
  try {
    const { reference } = req.params;
    const channelId = req.apiKeyRecord.channel_id;

    const localResult = await db.execute({
      sql: 'SELECT * FROM transactions WHERE external_reference = ? OR payhero_reference = ?',
      args: [reference, reference],
    });

    if (localResult.rows.length > 0 && localResult.rows[0].status !== 'pending') {
      await logRequest(req.apiKeyRecord, req, 200);
      return res.json({
        source: 'local',
        transaction: localResult.rows[0],
      });
    }

    const response = await fetch(
      `https://api.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(reference)}&channel_id=${channelId}`,
      { headers: { Authorization: getPayHeroAuthHeader() } }
    );

    const data = await response.json();

    if (!response.ok) {
      await logRequest(req.apiKeyRecord, req, response.status);
      return res.status(response.status).json({
        error: 'PayHero API error',
        details: data,
      });
    }

    await logRequest(req.apiKeyRecord, req, 200);
    res.json({ source: 'payhero', transaction: data });
  } catch (error) {
    console.error('Status query error:', error);
    await logRequest(req.apiKeyRecord, req, 500);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// PAYHERO CALLBACK
// ============================================================
app.post('/api/payhero/callback', async (req, res) => {
  try {
    const payload = req.body;
    console.log('PayHero Callback:', JSON.stringify(payload, null, 2));

    const externalRef = payload.external_reference || payload.reference;
    const status = payload.status || payload.transaction_status;
    const payheroRef = payload.payhero_reference || payload.mpesa_receipt;

    if (externalRef) {
      await db.execute({
        sql: `UPDATE transactions
              SET status = ?,
                  payhero_reference = COALESCE(?, payhero_reference),
                  callback_payload = ?,
                  updated_at = CURRENT_TIMESTAMP
              WHERE external_reference = ?`,
        args: [status, payheroRef, JSON.stringify(payload), externalRef],
      });
    }

    res.status(200).json({ status: 'received' });
  } catch (error) {
    console.error('Callback error:', error);
    res.status(200).json({ status: 'received_with_error' });
  }
});

// ============================================================
// HEALTH
// ============================================================
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Catch-all for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================
// START
// ============================================================
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`PayHero Central API on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('DB init failed:', err);
    process.exit(1);
  });
