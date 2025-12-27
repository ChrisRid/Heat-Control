const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Standardized error response
const sendError = (res, status, message, extra = {}) => {
    res.status(status).json({ success: false, error: message, ...extra });
};

// Audit logger
const auditLog = (event, deviceId, details = {}) => {
    const timestamp = new Date().toISOString();
    console.log(JSON.stringify({ timestamp, event, deviceId, ...details }));
};

// Rate limiter (100/min max, 5/sec regen, 1min memory)
const rateLimits = new Map();
const RATE_MAX = 100, RATE_REGEN = 5, RATE_WINDOW = 60000;

setInterval(() => {
    const now = Date.now();
    for (const [key, data] of rateLimits) {
        if (now - data.lastSeen > RATE_WINDOW) rateLimits.delete(key);
    }
}, 10000);

const rateLimit = (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    let data = rateLimits.get(key);
    
    if (!data) {
        data = { tokens: RATE_MAX, lastUpdate: now, lastSeen: now };
        rateLimits.set(key, data);
    }
    
    const elapsed = (now - data.lastUpdate) / 1000;
    data.tokens = Math.min(RATE_MAX, data.tokens + elapsed * RATE_REGEN);
    data.lastUpdate = now;
    data.lastSeen = now;
    
    if (data.tokens < 1) {
        return sendError(res, 429, 'Rate limit exceeded');
    }
    
    data.tokens--;
    next();
};

app.use(rateLimit);

// HTTPS enforcement
app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] === 'https' || req.secure || req.hostname === 'localhost') {
        return next();
    }
    sendError(res, 403, 'HTTPS required');
});

// Device ID validation
const isValidDeviceId = (id) => typeof id === 'string' && /^[a-z0-9]{32}$/.test(id);

const validateDeviceId = (source = 'params') => (req, res, next) => {
    const id = source === 'params' ? req.params.id : 
               source === 'query' ? req.query.id : 
               req.body.deviceId;
    if (!isValidDeviceId(id)) {
        return sendError(res, 400, 'Invalid device ID');
    }
    req.deviceId = id;
    next();
};

// Reformat PEM key
const formatPEM = (key) => {
    const b64 = key.replace(/-----BEGIN [^-]+-----/, '')
                   .replace(/-----END [^-]+-----/, '')
                   .replace(/\s/g, '');
    return '-----BEGIN PUBLIC KEY-----\n' + b64.match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----';
};

// Utility functions
const hash = (str) => crypto.createHash('sha256').update(str).digest('hex');
const randomHex = (bytes) => crypto.randomBytes(bytes).toString('hex');

// Verify hub signature (deviceId + timestamp)
const verifyHubSignature = async (deviceId, timestamp, signature) => {
    const now = Date.now();
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts) || Math.abs(now - ts) > 300000) return false; // 5 min window
    
    try {
        const result = await pool.query(
            'SELECT auth_public_key FROM authentication WHERE device_id = $1',
            [deviceId]
        );
        if (result.rows.length === 0) return false;
        
        const formattedKey = formatPEM(result.rows[0].auth_public_key);
        const message = deviceId + timestamp;
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(message);
        return verify.verify(formattedKey, signature, 'base64');
    } catch (err) {
        auditLog('signature_verify_error', deviceId, { error: err.message });
        return false;
    }
};

// Middleware for hub authentication
const requireHubAuth = async (req, res, next) => {
    const { deviceId, timestamp, signature } = req.body.deviceId ? req.body : req.query;
    
    if (!isValidDeviceId(deviceId)) {
        return sendError(res, 400, 'Invalid device ID');
    }
    if (!timestamp || !signature) {
        return sendError(res, 401, 'Missing authentication');
    }
    
    const valid = await verifyHubSignature(deviceId, timestamp, signature);
    if (!valid) {
        auditLog('hub_auth_failed', deviceId);
        return sendError(res, 401, 'Invalid signature');
    }
    
    req.deviceId = deviceId;
    next();
};

// Check auth cookie
app.get('/api/auth/check', validateDeviceId('query'), async (req, res) => {
    const cookie = req.cookies[`auth_${req.deviceId}`];
    if (!cookie) return res.json({ authenticated: false });
    
    try {
        const { device_id, token } = JSON.parse(cookie);
        if (device_id !== req.deviceId) return res.json({ authenticated: false });
        
        const result = await pool.query(
            'SELECT auth_cookie_token_hash FROM authentication WHERE device_id = $1',
            [req.deviceId]
        );
        if (result.rows.length === 0) return res.json({ authenticated: false });
        
        res.json({ authenticated: result.rows[0].auth_cookie_token_hash === hash(token) });
    } catch (err) {
        auditLog('auth_check_error', req.deviceId, { error: err.message });
        res.json({ authenticated: false });
    }
});

// Start auth flow
app.post('/api/auth/start', async (req, res) => {
    const { deviceId } = req.body;
    if (!isValidDeviceId(deviceId)) {
        return sendError(res, 400, 'Invalid device ID');
    }
    
    const nonce = randomHex(16);
    const clientId = randomHex(16);
    const expires = Date.now() + 60000;
    
    try {
        const result = await pool.query(
            `UPDATE authentication SET auth_nonce = $1, auth_expires = $2, client_id = $3
             WHERE device_id = $4 RETURNING device_id`,
            [nonce, expires, clientId, deviceId]
        );
        if (result.rows.length === 0) {
            return sendError(res, 404, 'Device not found');
        }
        auditLog('auth_started', deviceId);
        res.json({ success: true, clientId });
    } catch (err) {
        auditLog('auth_start_error', deviceId, { error: err.message });
        sendError(res, 500, 'Database error');
    }
});

// Poll auth status
app.get('/api/auth/poll', validateDeviceId('query'), async (req, res) => {
    const { clientId } = req.query;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        const result = await client.query(
            'SELECT auth_nonce, auth_expires, client_id FROM authentication WHERE device_id = $1 FOR UPDATE',
            [req.deviceId]
        );
        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.json({ success: false, status: 'error', message: 'Device not found' });
        }
        
        const row = result.rows[0];
        if (row.client_id !== clientId) {
            await client.query('ROLLBACK');
            return res.json({ success: false, status: 'error', message: 'Invalid client' });
        }
        
        if (Date.now() > row.auth_expires) {
            await client.query('ROLLBACK');
            return res.json({ success: false, status: 'timeout', message: 'Authentication expired' });
        }
        
        if (row.auth_nonce === null) {
            const token = randomHex(32);
            await client.query(
                'UPDATE authentication SET auth_cookie_token_hash = $1, client_id = NULL WHERE device_id = $2',
                [hash(token), req.deviceId]
            );
            await client.query('COMMIT');
            
            res.cookie(`auth_${req.deviceId}`, JSON.stringify({ device_id: req.deviceId, token }), {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 365 * 24 * 60 * 60 * 1000,
                sameSite: 'strict'
            });
            auditLog('auth_completed', req.deviceId);
            return res.json({ success: true, status: 'authenticated', message: 'Success' });
        }
        
        await client.query('COMMIT');
        res.json({ success: true, status: 'pending', message: 'Waiting for hub...' });
    } catch (err) {
        await client.query('ROLLBACK');
        auditLog('auth_poll_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    } finally {
        client.release();
    }
});

// Hub: Get nonce for signing (requires hub signature)
app.get('/api/hub/nonce', requireHubAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT auth_nonce, auth_expires FROM authentication WHERE device_id = $1',
            [req.deviceId]
        );
        if (result.rows.length === 0 || !result.rows[0].auth_nonce) {
            return sendError(res, 404, 'No pending auth');
        }
        if (Date.now() > result.rows[0].auth_expires) {
            return sendError(res, 410, 'Auth expired');
        }
        res.json({ success: true, nonce: result.rows[0].auth_nonce });
    } catch (err) {
        auditLog('nonce_fetch_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

// Hub: Submit signed auth
app.post('/api/hub/auth', async (req, res) => {
    const { deviceId, signature } = req.body;
    
    if (!isValidDeviceId(deviceId)) {
        return sendError(res, 400, 'Invalid device ID');
    }
    
    try {
        const result = await pool.query(
            'SELECT auth_public_key, auth_nonce, auth_expires FROM authentication WHERE device_id = $1',
            [deviceId]
        );
        if (result.rows.length === 0) {
            auditLog('auth_device_not_found', deviceId);
            return sendError(res, 404, 'Device not found');
        }
        
        const { auth_public_key, auth_nonce, auth_expires } = result.rows[0];
        
        if (!auth_nonce || Date.now() > auth_expires) {
            auditLog('auth_expired', deviceId);
            return sendError(res, 410, 'Auth expired');
        }
        
        const formattedKey = formatPEM(auth_public_key);
        const message = auth_nonce + deviceId;
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(message);
        
        let valid = false;
        try {
            valid = verify.verify(formattedKey, signature, 'base64');
        } catch {
            valid = false;
        }
        
        if (!valid) {
            auditLog('auth_invalid_signature', deviceId);
            return sendError(res, 401, 'Invalid signature');
        }
        
        await pool.query(
            'UPDATE authentication SET auth_nonce = NULL WHERE device_id = $1',
            [deviceId]
        );
        
        auditLog('hub_auth_success', deviceId);
        res.json({ success: true });
    } catch (err) {
        auditLog('hub_auth_error', deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

// Middleware to verify auth cookie for device endpoints
const requireAuth = async (req, res, next) => {
    const deviceId = req.params.id;
    if (!isValidDeviceId(deviceId)) {
        return sendError(res, 400, 'Invalid device ID');
    }
    
    const cookie = req.cookies[`auth_${deviceId}`];
    if (!cookie) {
        return sendError(res, 401, 'Not authenticated', { needsAuth: true });
    }
    
    try {
        const { device_id, token } = JSON.parse(cookie);
        if (device_id !== deviceId) {
            return sendError(res, 401, 'Invalid auth', { needsAuth: true });
        }
        
        const result = await pool.query(
            'SELECT auth_cookie_token_hash FROM authentication WHERE device_id = $1',
            [deviceId]
        );
        if (result.rows.length === 0 || result.rows[0].auth_cookie_token_hash !== hash(token)) {
            return sendError(res, 401, 'Invalid token', { needsAuth: true });
        }
        
        req.deviceId = deviceId;
        next();
    } catch (err) {
        auditLog('auth_middleware_error', deviceId, { error: err.message });
        sendError(res, 401, 'Auth error', { needsAuth: true });
    }
};

// Get device state (client auth via cookie)
app.get('/api/device/:id', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT current_temp, set_temp, mode, boost, program FROM devices WHERE device_id = $1',
            [req.deviceId]
        );
        if (result.rows.length === 0) {
            return sendError(res, 404, 'Device not found');
        }
        res.json({ success: true, ...result.rows[0] });
    } catch (err) {
        auditLog('device_get_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

// Update device state (client auth via cookie)
app.patch('/api/device/:id', requireAuth, async (req, res) => {
    const { set_temp, mode, boost, program } = req.body;
    const updates = [];
    const values = [];
    let idx = 1;
    
    if (set_temp !== undefined) { updates.push(`set_temp = $${idx++}`); values.push(set_temp); }
    if (mode !== undefined) { updates.push(`mode = $${idx++}`); values.push(mode); }
    if (boost !== undefined) { updates.push(`boost = $${idx++}`); values.push(boost); }
    if (program !== undefined) { updates.push(`program = $${idx++}`); values.push(program); }
    
    if (updates.length === 0) return res.json({ success: true });
    
    values.push(req.deviceId);
    
    try {
        await pool.query(
            `UPDATE devices SET ${updates.join(', ')} WHERE device_id = $${idx}`,
            values
        );
        res.json({ success: true });
    } catch (err) {
        auditLog('device_update_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

// Hub: Get settings (requires hub signature)
app.get('/api/hub/state', requireHubAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT set_temp, mode, boost, program FROM devices WHERE device_id = $1',
            [req.deviceId]
        );
        if (result.rows.length === 0) {
            return sendError(res, 404, 'Device not found');
        }
        res.json({ success: true, ...result.rows[0] });
    } catch (err) {
        auditLog('hub_state_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

// Hub: Report temperature (requires hub signature)
app.post('/api/hub/temp', requireHubAuth, async (req, res) => {
    const { temp } = req.body;
    try {
        await pool.query(
            'UPDATE devices SET current_temp = $1 WHERE device_id = $2',
            [temp, req.deviceId]
        );
        res.json({ success: true });
    } catch (err) {
        auditLog('hub_temp_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
