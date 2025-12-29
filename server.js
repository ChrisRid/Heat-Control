const cluster = require('cluster');
const os = require('os');

// =============================================================================
// Clustering - Use all available CPU cores
// =============================================================================

const numCPUs = parseInt(process.env.NUM_CLUSTER_WORKERS, 10) || os.cpus().length;

if (cluster.isPrimary) {
    console.log(`[Primary ${process.pid}] Starting ${numCPUs} workers (set NUM_CLUSTER_WORKERS to override)`);
    
    let activeWorkers = 0;
    
    const logWorkerCount = (event, workerId) => {
        console.log(`[Primary] Worker ${workerId} ${event}. Active workers: ${activeWorkers}/${numCPUs}`);
    };
    
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
    
    cluster.on('online', (worker) => {
        activeWorkers++;
        logWorkerCount('online', worker.process.pid);
    });
    
    cluster.on('exit', (worker, code, signal) => {
        activeWorkers--;
        logWorkerCount(`exited (${signal || code})`, worker.process.pid);
        console.log(`[Primary] Starting replacement worker...`);
        cluster.fork();
    });
    
} else {
    startServer();
}

function startServer() {

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const app = express();

app.use(express.json({ limit: '1kb' }));
app.use(cookieParser());

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'");
    next();
});

const pool = new Pool({ 
    connectionString: process.env.DATABASE_URL,
    max: parseInt(process.env.DB_CONNECTIONS_PER_WORKER, 10) || 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000
});

// =============================================================================
// Constants
// =============================================================================

const TEMP_MIN = 10, TEMP_MAX = 30;
const VALID_MODES = [0, 1];
const VALID_BOOSTS = [0, 1, 2, 3];
const PROGRAM_PATTERN = /^[A-U]{168}$/;
const TIMESTAMP_WINDOW_MS = 120000;

// Cookie expiry: 6 months (refreshed on each use for rolling expiry)
const COOKIE_MAX_AGE_MS = 180 * 24 * 60 * 60 * 1000;

// Session cleanup: remove sessions unused for 6 months
const SESSION_EXPIRY_MS = 180 * 24 * 60 * 60 * 1000;

// Server readiness flag
let serverReady = false;

// Track last session cleanup time (run hourly, not every 30 seconds)
let lastSessionCleanup = 0;
const SESSION_CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // 1 hour

// =============================================================================
// Utility Functions
// =============================================================================

const sendError = (res, status, message, extra = {}) => {
    res.status(status).json({ success: false, error: message, ...extra });
};

const auditLog = (event, deviceId, details = {}) => {
    const timestamp = new Date().toISOString();
    console.log(JSON.stringify({ timestamp, event, deviceId, ...details }));
};

const hash = (str) => crypto.createHash('sha256').update(str).digest('hex');
const randomHex = (bytes) => crypto.randomBytes(bytes).toString('hex');

// =============================================================================
// Rate Limiting
// =============================================================================

const rateLimits = new Map();
const RATE_MAX = 100, RATE_REGEN = 5, RATE_WINDOW = 60000;

const authBlocks = new Map();
const AUTH_BLOCK_DURATION = 10000;

// Cleanup every 30 seconds (rate limits + auth blocks)
// Session cleanup runs hourly within this interval
setInterval(async () => {
    const now = Date.now();
    
    // Clean up rate limits
    for (const [key, data] of rateLimits) {
        if (now - data.lastSeen > RATE_WINDOW) rateLimits.delete(key);
    }
    
    // Clean up auth blocks
    for (const [key, blockUntil] of authBlocks) {
        if (now > blockUntil) authBlocks.delete(key);
    }
    
    // Clean up expired sessions (hourly)
    if (now - lastSessionCleanup > SESSION_CLEANUP_INTERVAL_MS) {
        lastSessionCleanup = now;
        try {
            const cutoff = now - SESSION_EXPIRY_MS;
            const result = await pool.query(
                'DELETE FROM sessions WHERE last_used_at < $1',
                [cutoff]
            );
            if (result.rowCount > 0) {
                auditLog('session_cleanup', null, { removed: result.rowCount });
            }
        } catch (err) {
            console.error('[Session cleanup error]', err.message);
        }
    }
}, 30000);

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

// =============================================================================
// Validation
// =============================================================================

const isValidDeviceId = (id) => typeof id === 'string' && /^[a-z0-9]{32}$/.test(id);

const getDeviceId = (req, source) => {
    switch (source) {
        case 'params': return req.params.id;
        case 'query': return req.query.id || req.query.deviceId;
        case 'body': return req.body.deviceId;
        case 'auto': return req.body.deviceId || req.query.deviceId || req.params.id;
        default: return null;
    }
};

const validateDeviceId = (source = 'params') => (req, res, next) => {
    const id = getDeviceId(req, source);
    if (!isValidDeviceId(id)) {
        return sendError(res, 400, 'Invalid device ID');
    }
    req.deviceId = id;
    next();
};

const validateSetTemp = (temp) => {
    const t = parseInt(temp, 10);
    return !isNaN(t) && t >= TEMP_MIN && t <= TEMP_MAX ? t : null;
};

const validateMode = (mode) => {
    const m = parseInt(mode, 10);
    return VALID_MODES.includes(m) ? m : null;
};

const validateBoost = (boost) => {
    const b = parseInt(boost, 10);
    return VALID_BOOSTS.includes(b) ? b : null;
};

const validateProgram = (program) => {
    return typeof program === 'string' && PROGRAM_PATTERN.test(program) ? program : null;
};

const validateTemp = (temp) => {
    const t = parseInt(temp, 10);
    return !isNaN(t) && t >= -40 && t <= 60 ? t : null;
};

// =============================================================================
// Crypto Helpers
// =============================================================================

const formatPEM = (key) => {
    const b64 = key.replace(/-----BEGIN [^-]+-----/, '')
                   .replace(/-----END [^-]+-----/, '')
                   .replace(/\s/g, '');
    return '-----BEGIN PUBLIC KEY-----\n' + b64.match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----';
};

const isBlocked = (ip) => {
    const blockUntil = authBlocks.get(ip);
    return blockUntil && Date.now() < blockUntil;
};

const blockIp = (ip) => {
    authBlocks.set(ip, Date.now() + AUTH_BLOCK_DURATION);
};

const verifyHubSignature = async (deviceId, timestamp, signature) => {
    const now = Date.now();
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts) || Math.abs(now - ts) > TIMESTAMP_WINDOW_MS) return false;
    
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

// =============================================================================
// Hub Authentication Middleware
// =============================================================================

const requireHubAuth = async (req, res, next) => {
    const deviceId = getDeviceId(req, 'auto');
    const timestamp = req.body.timestamp || req.query.timestamp;
    const signature = req.body.signature || req.query.signature;
    
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

// =============================================================================
// Startup Cleanup
// =============================================================================

const clearStaleAuthStates = async () => {
    try {
        const result = await pool.query(
            'UPDATE authentication SET auth_nonce = NULL, client_id = NULL WHERE client_id IS NOT NULL'
        );
        const cleared = result.rowCount || 0;
        if (cleared > 0) {
            auditLog('startup_cleanup', null, { cleared_auth_states: cleared });
        }
        console.log(`[Worker ${process.pid}] Startup cleanup complete (cleared ${cleared} stale auth states)`);
        serverReady = true;
    } catch (err) {
        console.error(`[Worker ${process.pid}] Startup cleanup failed:`, err.message);
        setTimeout(clearStaleAuthStates, 1000);
    }
};

const requireServerReady = (req, res, next) => {
    if (!serverReady) {
        return sendError(res, 425, 'Server starting up, please retry shortly');
    }
    next();
};

// =============================================================================
// Cookie Helper
// =============================================================================

const setSessionCookie = (res, deviceId, token) => {
    res.cookie(`auth_${deviceId}`, JSON.stringify({ device_id: deviceId, token }), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: COOKIE_MAX_AGE_MS,
        sameSite: 'strict'
    });
};

// =============================================================================
// Session Authentication Middleware
// =============================================================================

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
        
        const tokenHash = hash(token);
        const result = await pool.query(
            'SELECT id FROM sessions WHERE device_id = $1 AND token_hash = $2',
            [deviceId, tokenHash]
        );
        
        if (result.rows.length === 0) {
            return sendError(res, 401, 'Invalid token', { needsAuth: true });
        }
        
        // Update last_used_at and refresh cookie (rolling 6-month expiry)
        const now = Date.now();
        await pool.query(
            'UPDATE sessions SET last_used_at = $1 WHERE id = $2',
            [now, result.rows[0].id]
        );
        setSessionCookie(res, deviceId, token);
        
        req.deviceId = deviceId;
        req.sessionId = result.rows[0].id;
        req.tokenHash = tokenHash;
        next();
    } catch (err) {
        auditLog('auth_middleware_error', deviceId, { error: err.message });
        sendError(res, 401, 'Auth error', { needsAuth: true });
    }
};

// =============================================================================
// Auth Endpoints
// =============================================================================

app.get('/api/auth/check', validateDeviceId('query'), async (req, res) => {
    const cookie = req.cookies[`auth_${req.deviceId}`];
    if (!cookie) return res.json({ success: true, authenticated: false });
    
    try {
        const { device_id, token } = JSON.parse(cookie);
        if (device_id !== req.deviceId) return res.json({ success: true, authenticated: false });
        
        const tokenHash = hash(token);
        const result = await pool.query(
            'SELECT id FROM sessions WHERE device_id = $1 AND token_hash = $2',
            [req.deviceId, tokenHash]
        );
        
        if (result.rows.length === 0) {
            return res.json({ success: true, authenticated: false });
        }
        
        // Update last_used_at and refresh cookie (rolling 6-month expiry)
        const now = Date.now();
        await pool.query(
            'UPDATE sessions SET last_used_at = $1 WHERE id = $2',
            [now, result.rows[0].id]
        );
        setSessionCookie(res, req.deviceId, token);
        
        res.json({ success: true, authenticated: true });
    } catch (err) {
        auditLog('auth_check_error', req.deviceId, { error: err.message });
        res.json({ success: true, authenticated: false });
    }
});

app.post('/api/auth/start', requireServerReady, async (req, res) => {
    if (isBlocked(req.ip)) {
        return sendError(res, 429, 'Too many attempts');
    }
    
    const { deviceId } = req.body;
    if (!isValidDeviceId(deviceId)) {
        return sendError(res, 400, 'Invalid device ID');
    }
    
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');
        
        const checkResult = await client.query(
            'SELECT client_id, auth_expires FROM authentication WHERE device_id = $1 FOR UPDATE',
            [deviceId]
        );
        
        if (checkResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return sendError(res, 404, 'Device not found');
        }
        
        const row = checkResult.rows[0];
        
        if (row.client_id && row.auth_expires && Date.now() < row.auth_expires) {
            await client.query('ROLLBACK');
            auditLog('auth_conflict', deviceId);
            return sendError(res, 409, 'Authentication already in progress');
        }
        
        const nonce = randomHex(16);
        const clientId = randomHex(16);
        const expires = Date.now() + 60000;
        
        await client.query(
            `UPDATE authentication SET auth_nonce = $1, auth_expires = $2, client_id = $3
             WHERE device_id = $4`,
            [nonce, expires, clientId, deviceId]
        );
        
        await client.query('COMMIT');
        
        auditLog('auth_started', deviceId);
        res.json({ success: true, clientId });
    } catch (err) {
        await client.query('ROLLBACK');
        auditLog('auth_start_error', deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    } finally {
        client.release();
    }
});

app.get('/api/auth/poll', requireServerReady, validateDeviceId('query'), async (req, res) => {
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
            return sendError(res, 404, 'Device not found', { status: 'error' });
        }
        
        const row = result.rows[0];
        if (row.client_id !== clientId) {
            await client.query('ROLLBACK');
            return sendError(res, 400, 'Invalid client', { status: 'error' });
        }
        
        if (Date.now() > row.auth_expires) {
            await client.query(
                'UPDATE authentication SET auth_nonce = NULL, client_id = NULL WHERE device_id = $1',
                [req.deviceId]
            );
            await client.query('COMMIT');
            return res.json({ success: false, status: 'timeout', error: 'Authentication expired' });
        }
        
        if (row.auth_nonce === null) {
            // Auth successful - create new session
            const token = randomHex(32);
            const tokenHash = hash(token);
            const now = Date.now();
            
            await client.query(
                'INSERT INTO sessions (device_id, token_hash, created_at, last_used_at) VALUES ($1, $2, $3, $3)',
                [req.deviceId, tokenHash, now]
            );
            
            await client.query(
                'UPDATE authentication SET client_id = NULL WHERE device_id = $1',
                [req.deviceId]
            );
            
            await client.query('COMMIT');
            
            setSessionCookie(res, req.deviceId, token);
            auditLog('auth_completed', req.deviceId);
            return res.json({ success: true, status: 'authenticated' });
        }
        
        await client.query('COMMIT');
        res.json({ success: true, status: 'pending' });
    } catch (err) {
        await client.query('ROLLBACK');
        auditLog('auth_poll_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    } finally {
        client.release();
    }
});

// =============================================================================
// Hub Endpoints
// =============================================================================

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

app.post('/api/hub/auth', validateDeviceId('body'), async (req, res) => {
    const { signature } = req.body;
    
    if (isBlocked(req.ip)) {
        return sendError(res, 429, 'Too many attempts');
    }
    
    try {
        const result = await pool.query(
            'SELECT auth_public_key, auth_nonce, auth_expires FROM authentication WHERE device_id = $1',
            [req.deviceId]
        );
        if (result.rows.length === 0) {
            auditLog('auth_device_not_found', req.deviceId);
            return sendError(res, 404, 'Device not found');
        }
        
        const { auth_public_key, auth_nonce, auth_expires } = result.rows[0];
        
        if (!auth_nonce || Date.now() > auth_expires) {
            auditLog('auth_expired', req.deviceId);
            return sendError(res, 410, 'Auth expired');
        }
        
        const formattedKey = formatPEM(auth_public_key);
        const message = auth_nonce + req.deviceId;
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(message);
        
        let valid = false;
        try {
            valid = verify.verify(formattedKey, signature, 'base64');
        } catch {
            valid = false;
        }
        
        if (!valid) {
            auditLog('auth_invalid_signature', req.deviceId);
            blockIp(req.ip);
            return sendError(res, 401, 'Invalid signature');
        }
        
        await pool.query(
            'UPDATE authentication SET auth_nonce = NULL WHERE device_id = $1',
            [req.deviceId]
        );
        
        auditLog('hub_auth_success', req.deviceId);
        res.json({ success: true });
    } catch (err) {
        auditLog('hub_auth_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

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

app.post('/api/hub/temp', requireHubAuth, async (req, res) => {
    const { temp } = req.body;
    const validated = validateTemp(temp);
    if (validated === null) {
        return sendError(res, 400, 'Invalid temperature');
    }
    
    try {
        await pool.query(
            'UPDATE devices SET current_temp = $1 WHERE device_id = $2',
            [validated, req.deviceId]
        );
        res.json({ success: true });
    } catch (err) {
        auditLog('hub_temp_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

// =============================================================================
// Device Endpoints
// =============================================================================

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

app.patch('/api/device/:id', requireAuth, async (req, res) => {
    const { set_temp, mode, boost, program } = req.body;
    const updates = [];
    const values = [];
    let idx = 1;
    
    if (set_temp !== undefined) {
        const validated = validateSetTemp(set_temp);
        if (validated === null) return sendError(res, 400, 'Invalid set_temp (must be 10-30)');
        updates.push(`set_temp = $${idx++}`);
        values.push(validated);
    }
    if (mode !== undefined) {
        const validated = validateMode(mode);
        if (validated === null) return sendError(res, 400, 'Invalid mode (must be 0 or 1)');
        updates.push(`mode = $${idx++}`);
        values.push(validated);
    }
    if (boost !== undefined) {
        const validated = validateBoost(boost);
        if (validated === null) return sendError(res, 400, 'Invalid boost (must be 0-3)');
        updates.push(`boost = $${idx++}`);
        values.push(validated);
    }
    if (program !== undefined) {
        const validated = validateProgram(program);
        if (validated === null) return sendError(res, 400, 'Invalid program format');
        updates.push(`program = $${idx++}`);
        values.push(validated);
    }
    
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

// =============================================================================
// Session Management Endpoints
// =============================================================================

// Get session count for a device (requires auth)
app.get('/api/device/:id/sessions', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT COUNT(*) as count FROM sessions WHERE device_id = $1',
            [req.deviceId]
        );
        res.json({ success: true, count: parseInt(result.rows[0].count, 10) });
    } catch (err) {
        auditLog('session_count_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

// Revoke all sessions for a device (requires auth)
app.delete('/api/device/:id/sessions', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM sessions WHERE device_id = $1',
            [req.deviceId]
        );
        
        auditLog('sessions_revoked', req.deviceId, { count: result.rowCount });
        
        // Clear the cookie for this user
        res.clearCookie(`auth_${req.deviceId}`);
        
        res.json({ success: true, revoked: result.rowCount });
    } catch (err) {
        auditLog('session_revoke_error', req.deviceId, { error: err.message });
        sendError(res, 500, 'Server error');
    }
});

// =============================================================================
// Static Files & Health Check
// =============================================================================

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req, res) => {
    res.json({ success: true, ready: serverReady });
});

// =============================================================================
// Start Server
// =============================================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[Worker ${process.pid}] Server running on port ${PORT}`);
    clearStaleAuthStates();
});

} // end startServer()
