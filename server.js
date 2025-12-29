const cluster = require('cluster');
const os = require('os');

// =============================================================================
// Clustering - Use all available CPU cores
// =============================================================================

// Use NUM_CLUSTER_WORKERS env var, fallback to CPU count
// Note: os.cpus().length returns HOST CPUs in containers, not allocated vCPUs
const numCPUs = parseInt(process.env.NUM_CLUSTER_WORKERS, 10) || os.cpus().length;

if (cluster.isPrimary) {
    console.log(`[Primary ${process.pid}] Starting ${numCPUs} workers (set NUM_CLUSTER_WORKERS to override)`);
    
    let activeWorkers = 0;
    
    const logWorkerCount = (event, workerId) => {
        console.log(`[Primary] Worker ${workerId} ${event}. Active workers: ${activeWorkers}/${numCPUs}`);
    };
    
    // Fork workers for each CPU
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
        
        // Restart dead workers
        console.log(`[Primary] Starting replacement worker...`);
        cluster.fork();
    });
    
} else {
    // Worker process - run the Express server
    startServer();
}

function startServer() {

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const app = express();

// #6 - Request body size limit (1kb is plenty for this API)
app.use(express.json({ limit: '1kb' }));
app.use(cookieParser());

// #7 - Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'");
    next();
});

// PostgreSQL pool - configurable per worker
// Total connections = DB_CONNECTIONS_PER_WORKER × WEB_CONCURRENCY (e.g., 3 × 8 = 24)
// Check your Railway Postgres tier's connection limit
const pool = new Pool({ 
    connectionString: process.env.DATABASE_URL,
    max: parseInt(process.env.DB_CONNECTIONS_PER_WORKER, 10) || 5,
    idleTimeoutMillis: 30000,  // Close idle connections after 30s
    connectionTimeoutMillis: 5000  // Fail fast if can't connect in 5s
});

// #5 - Validation constants
const TEMP_MIN = 10, TEMP_MAX = 30;
const VALID_MODES = [0, 1];
const VALID_BOOSTS = [0, 1, 2, 3];
const PROGRAM_LENGTH = 168;
const PROGRAM_PATTERN = /^[A-U]{168}$/; // A=10°C to U=30°C

// #8 - Timestamp window (2 minutes)
const TIMESTAMP_WINDOW_MS = 120000;

// Server readiness flag - prevents auth requests until startup cleanup completes
let serverReady = false;

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

// #13 - Brute force protection (10 second block after failed auth)
const authBlocks = new Map();
const AUTH_BLOCK_DURATION = 10000;

// #25 - Cleanup every 30 seconds
setInterval(() => {
    const now = Date.now();
    for (const [key, data] of rateLimits) {
        if (now - data.lastSeen > RATE_WINDOW) rateLimits.delete(key);
    }
    for (const [key, blockUntil] of authBlocks) {
        if (now > blockUntil) authBlocks.delete(key);
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

// #22 - Single device ID validation function
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

// #5 - Input validators
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
    return !isNaN(t) && t >= -40 && t <= 60 ? t : null; // Reasonable sensor range
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

// #13 - Check if IP is blocked
const isBlocked = (ip) => {
    const blockUntil = authBlocks.get(ip);
    return blockUntil && Date.now() < blockUntil;
};

const blockIp = (ip) => {
    authBlocks.set(ip, Date.now() + AUTH_BLOCK_DURATION);
};

// #8 - Verify hub signature with 2 minute window
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

// #22 - Unified hub authentication middleware
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

// Startup cleanup - clear any stale auth states from previous server instance
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
        // Retry after a short delay
        setTimeout(clearStaleAuthStates, 1000);
    }
};

// Middleware to check server readiness for auth endpoints
const requireServerReady = (req, res, next) => {
    if (!serverReady) {
        return sendError(res, 425, 'Server starting up, please retry shortly');
    }
    next();
};

// #23 - Standardized auth check response
app.get('/api/auth/check', validateDeviceId('query'), async (req, res) => {
    const cookie = req.cookies[`auth_${req.deviceId}`];
    if (!cookie) return res.json({ success: true, authenticated: false });
    
    try {
        const { device_id, token } = JSON.parse(cookie);
        if (device_id !== req.deviceId) return res.json({ success: true, authenticated: false });
        
        const result = await pool.query(
            'SELECT auth_cookie_token_hash FROM authentication WHERE device_id = $1',
            [req.deviceId]
        );
        if (result.rows.length === 0) return res.json({ success: true, authenticated: false });
        
        const authenticated = result.rows[0].auth_cookie_token_hash === hash(token);
        res.json({ success: true, authenticated });
    } catch (err) {
        auditLog('auth_check_error', req.deviceId, { error: err.message });
        res.json({ success: true, authenticated: false });
    }
});

// #13 - Start auth flow with brute force protection and conflict detection
app.post('/api/auth/start', requireServerReady, async (req, res) => {
    // Check for brute force block
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
        
        // Check if device exists and if there's an active auth in progress
        const checkResult = await client.query(
            'SELECT client_id, auth_expires FROM authentication WHERE device_id = $1 FOR UPDATE',
            [deviceId]
        );
        
        if (checkResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return sendError(res, 404, 'Device not found');
        }
        
        const row = checkResult.rows[0];
        
        // If there's an active (non-expired) auth in progress, reject
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

// #23 - Poll auth status with standardized responses
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
            // Clear auth state so a new auth can start
            await client.query(
                'UPDATE authentication SET auth_nonce = NULL, client_id = NULL WHERE device_id = $1',
                [req.deviceId]
            );
            await client.query('COMMIT');
            return res.json({ success: false, status: 'timeout', error: 'Authentication expired' });
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

// #13 - Hub: Submit signed auth with brute force protection
app.post('/api/hub/auth', validateDeviceId('body'), async (req, res) => {
    const { signature } = req.body;
    
    // Check for brute force block
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
            blockIp(req.ip); // #13 - Block IP on failed auth
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

// #5 - Update device state with input validation
app.patch('/api/device/:id', requireAuth, async (req, res) => {
    const { set_temp, mode, boost, program } = req.body;
    const updates = [];
    const values = [];
    let idx = 1;
    
    // Validate each field if provided
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

// #5 - Hub: Report temperature with validation
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

app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint (useful for load balancers)
app.get('/api/health', (req, res) => {
    res.json({ success: true, ready: serverReady });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[Worker ${process.pid}] Server running on port ${PORT}`);
    // Run startup cleanup after server is listening
    clearStaleAuthStates();
});

} // end startServer()
