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

// Initialize tables
async function initDB() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_hash TEXT UNIQUE NOT NULL,
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

  console.log('Database initialized');
}

// ============================================================
// MIDDLEWARE
// ============================================================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiter: 100 requests per minute per IP (adjustable)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // limit each IP to 100 requests per windowMs
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

function verifyApiKey(key) {
  const hash = hashKey(key);
  // Timing-safe comparison to prevent timing attacks
  const keyBuffer = Buffer.from(key);
  const expectedBuffer = Buffer.from(hash);
  if (keyBuffer.length !== expectedBuffer.length) return false;
  return crypto.timingSafeEqual(keyBuffer, expectedBuffer);
}

// Get PayHero Basic Auth header
function getPayHeroAuthHeader() {
  const credentials = Buffer.from(
    `${process.env.PAYHERO_API_USERNAME}:${process.env.PAYHERO_API_PASSWORD}`
  ).toString('base64');
  return `Basic ${credentials}`;
}

// Middleware: authenticate API key
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
    return res.status(403).json({ error: 'Invalid or inactive API key' });
  }

  const keyRecord = result.rows[0];
  
  // Update last used
  await db.execute({
    sql: 'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?',
    args: [keyRecord.id],
  });

  req.apiKeyRecord = keyRecord;
  next();
}

// ============================================================
// ADMIN ROUTES (Frontend Management)
// ============================================================

// Simple admin auth using password from env
function adminAuth(req, res, next) {
  const adminToken = req.headers['x-admin-token'] || req.query.admin_token;
  if (adminToken !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
}

// List all API keys
app.get('/api/admin/keys', adminAuth, async (req, res) => {
  const result = await db.execute('SELECT id, name, app_identifier, channel_id, is_active, created_at, last_used_at FROM api_keys ORDER BY created_at DESC');
  res.json(result.rows);
});

// Create a new API key
app.post('/api/admin/keys', adminAuth, async (req, res) => {
  const { name, app_identifier, channel_id } = req.body;
  
  if (!name || !channel_id) {
    return res.status(400).json({ error: 'Name and Channel ID are required' });
  }

  const newKey = generateApiKey();
  const keyHash = hashKey(newKey);

  await db.execute({
    sql: 'INSERT INTO api_keys (key_hash, name, app_identifier, channel_id) VALUES (?, ?, ?, ?)',
    args: [keyHash, name, app_identifier || name, channel_id],
  });

  // Return the plain key ONCE - it's never shown again
  res.json({
    api_key: newKey,
    message: 'Store this key securely. It will not be shown again.',
    name,
    channel_id,
  });
});

// Revoke an API key
app.patch('/api/admin/keys/:id/revoke', adminAuth, async (req, res) => {
  await db.execute({
    sql: 'UPDATE api_keys SET is_active = 0 WHERE id = ?',
    args: [req.params.id],
  });
  res.json({ success: true });
});

// Delete an API key
app.delete('/api/admin/keys/:id', adminAuth, async (req, res) => {
  await db.execute({
    sql: 'DELETE FROM api_keys WHERE id = ?',
    args: [req.params.id],
  });
  res.json({ success: true });
});

// ============================================================
// PAYHERO PROXY ROUTES (Protected by API Key)
// ============================================================

// Initiate STK Push
app.post('/api/pay/stk-push', authenticateApiKey, async (req, res) => {
  try {
    const { phone_number, amount, external_reference, callback_url } = req.body;
    const channelId = req.apiKeyRecord.channel_id;

    if (!phone_number || !amount || !external_reference) {
      return res.status(400).json({ 
        error: 'phone_number, amount, and external_reference are required' 
      });
    }

    // Log pending transaction
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

    // Call PayHero API
    const payheroPayload = {
      amount,
      phone_number,
      channel_id: channelId,
      external_reference,
      callback_url: callback_url || `${req.protocol}://${req.get('host')}/api/payhero/callback`,
    };

    const response = await fetch('https://api.payhero.co.ke/api/v2/payments', {
      method: 'POST',
      headers: {
        'Authorization': getPayHeroAuthHeader(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payheroPayload),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: 'PayHero API error',
        details: data,
      });
    }

    // Update transaction with PayHero reference if returned
    if (data.reference) {
      await db.execute({
        sql: 'UPDATE transactions SET payhero_reference = ?, updated_at = CURRENT_TIMESTAMP WHERE external_reference = ?',
        args: [data.reference, external_reference],
      });
    }

    res.json({
      success: true,
      external_reference,
      payhero_response: data,
    });
  } catch (error) {
    console.error('STK Push error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Query transaction status
app.get('/api/pay/status/:reference', authenticateApiKey, async (req, res) => {
  try {
    const { reference } = req.params;
    const channelId = req.apiKeyRecord.channel_id;

    // First check local DB
    const localResult = await db.execute({
      sql: 'SELECT * FROM transactions WHERE external_reference = ? OR payhero_reference = ?',
      args: [reference, reference],
    });

    if (localResult.rows.length > 0 && localResult.rows[0].status !== 'pending') {
      return res.json({
        source: 'local',
        transaction: localResult.rows[0],
      });
    }

    // Query PayHero directly
    const response = await fetch(
      `https://api.payhero.co.ke/api/v2/transaction-status?reference=${encodeURIComponent(reference)}&channel_id=${channelId}`,
      {
        headers: {
          'Authorization': getPayHeroAuthHeader(),
        },
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: 'PayHero API error',
        details: data,
      });
    }

    res.json({
      source: 'payhero',
      transaction: data,
    });
  } catch (error) {
    console.error('Status query error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================
// PAYHERO CALLBACK ENDPOINT (Public - PayHero calls this)
// ============================================================
app.post('/api/payhero/callback', async (req, res) => {
  try {
    const payload = req.body;
    console.log('PayHero Callback received:', JSON.stringify(payload, null, 2));

    // Extract reference and status from PayHero callback
    // Adjust field names based on actual PayHero callback structure
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

    // Always respond with 200 to acknowledge receipt
    res.status(200).json({ status: 'received' });
  } catch (error) {
    console.error('Callback processing error:', error);
    // Still return 200 to prevent PayHero retries
    res.status(200).json({ status: 'received_with_error' });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================
// START SERVER
// ============================================================
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`PayHero Central API running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});