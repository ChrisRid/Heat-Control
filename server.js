/**
 * Thermostat Control Backend API
 * Single-file REST API for thermostat device management
 * 
 * AUTHENTICATION: Uses ECDSA asymmetric key authentication
 * - Devices hold private keys (never transmitted)
 * - Server stores public keys
 * - Challenge-response with nonce prevents replay attacks
 * 
 * SCALABILITY NOTES:
 * - Auth state is stored in database (not memory) for multi-instance support
 * - Rate limiting uses database for shared state across instances
 * - Per-device isolation ensures no cross-device interference
 */

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');

const app = express();

// ============================================================================
// CONFIGURATION
// ============================================================================

const PORT = process.env.PORT || 3000;
const DB_URL = process.env.DATABASE_URL;
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex');
const NODE_ENV = process.env.NODE_ENV || 'development';

// Auth timeout in milliseconds (60 seconds)
const AUTH_TIMEOUT_MS = 60000;

// Timestamp validity window in seconds (±60 seconds)
const TIMESTAMP_WINDOW_SECONDS = 60;

// Max pending auth requests per device (prevents queue flooding)
const MAX_PENDING_AUTH_PER_DEVICE = 10;

// Rate limit windows
const RATE_LIMIT_GENERAL_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_GENERAL_MAX = 100;
const RATE_LIMIT_AUTH_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_AUTH_MAX = 10;

// Program encoding: A=10°C, B=11°C, ... U=30°C (21 letters for temps 10-30)
const TEMP_MIN = 10;
const TEMP_MAX = 30;
const TEMP_OFFSET = 'A'.charCodeAt(0) - TEMP_MIN;

// ============================================================================
// DATABASE CONNECTION
// ============================================================================

const pool = new Pool({
    connectionString: DB_URL,
    ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20, // Maximum connections in pool
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// Test database connection and ensure tables exist
async function initDatabase() {
    try {
        await pool.query('SELECT NOW()');
        console.log('✓ Database connected');
        
        // Create auth_requests table if it doesn't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS auth_requests (
                id SERIAL PRIMARY KEY,
                device_id TEXT NOT NULL,
                client_id TEXT UNIQUE NOT NULL,
                nonce TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL,
                verified BOOLEAN DEFAULT FALSE
            )
        `);
        
        // Create indexes for efficient lookups
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_auth_requests_device_id 
            ON auth_requests(device_id)
        `);
        
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_auth_requests_client_id 
            ON auth_requests(client_id)
        `);
        
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_auth_requests_nonce 
            ON auth_requests(nonce)
        `);
        
        // Create rate_limits table for distributed rate limiting
        await pool.query(`
            CREATE TABLE IF NOT EXISTS rate_limits (
                id SERIAL PRIMARY KEY,
                key TEXT NOT NULL,
                window_start TIMESTAMP NOT NULL,
                count INTEGER DEFAULT 1,
                UNIQUE(key, window_start)
            )
        `);
        
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_rate_limits_key 
            ON rate_limits(key)
        `);
        
        console.log('✓ Database tables initialized');
    } catch (err) {
        console.error('✗ Database initialization failed:', err.message);
    }
}

initDatabase();

// Cleanup expired auth requests periodically
async function cleanupExpiredAuthRequests() {
    try {
        await pool.query('DELETE FROM auth_requests WHERE expires_at < NOW()');
        // Also cleanup old rate limit entries (older than 5 minutes)
        await pool.query(`DELETE FROM rate_limits WHERE window_start < NOW() - INTERVAL '5 minutes'`);
    } catch (err) {
        console.error('Cleanup error:', err.message);
    }
}

setInterval(cleanupExpiredAuthRequests, 30000); // Run every 30 seconds

// ============================================================================
// DISTRIBUTED RATE LIMITING
// ============================================================================

/**
 * Database-backed rate limiter for multi-instance deployment
 */
async function checkRateLimit(key, windowMs, maxRequests) {
    const windowStart = new Date(Math.floor(Date.now() / windowMs) * windowMs);
    
    try {
        // Upsert: increment counter or insert new record
        const result = await pool.query(`
            INSERT INTO rate_limits (key, window_start, count)
            VALUES ($1, $2, 1)
            ON CONFLICT (key, window_start) 
            DO UPDATE SET count = rate_limits.count + 1
            RETURNING count
        `, [key, windowStart]);
        
        const count = result.rows[0].count;
        return {
            allowed: count <= maxRequests,
            current: count,
            limit: maxRequests,
            remaining: Math.max(0, maxRequests - count)
        };
    } catch (err) {
        console.error('Rate limit check error:', err.message);
        // Fail open - allow request if rate limiting fails
        return { allowed: true, current: 0, limit: maxRequests, remaining: maxRequests };
    }
}

/**
 * Rate limit middleware factory
 */
function createRateLimiter(windowMs, maxRequests, keyPrefix = 'general') {
    return async (req, res, next) => {
        // Use IP + optional prefix as key
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const key = `${keyPrefix}:${ip}`;
        
        const result = await checkRateLimit(key, windowMs, maxRequests);
        
        // Set standard rate limit headers
        res.set('X-RateLimit-Limit', result.limit);
        res.set('X-RateLimit-Remaining', result.remaining);
        
        if (!result.allowed) {
            return res.status(429).json({ 
                error: 'Too many requests, please try again later',
                retryAfter: Math.ceil(windowMs / 1000)
            });
        }
        
        next();
    };
}

// ============================================================================
// MIDDLEWARE
// ============================================================================

// CORS configuration
app.use(cors({
    origin: true,
    credentials: true
}));

// Parse JSON bodies
app.use(express.json());

// Parse cookies
app.use(cookieParser(COOKIE_SECRET));

// Trust proxy for rate limiting behind reverse proxy
app.set('trust proxy', 1);

// Create rate limiters
const generalLimiter = createRateLimiter(
    RATE_LIMIT_GENERAL_WINDOW_MS, 
    RATE_LIMIT_GENERAL_MAX, 
    'general'
);

const authLimiter = createRateLimiter(
    RATE_LIMIT_AUTH_WINDOW_MS, 
    RATE_LIMIT_AUTH_MAX, 
    'auth'
);

// Apply general rate limiting to all routes
app.use(generalLimiter);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Hash a value using SHA256
 */
function sha256(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Generate a secure random token (256 bits)
 */
function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate a cryptographically secure nonce (256 bits)
 */
function generateNonce() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * Constant-time comparison to prevent timing attacks
 */
function secureCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Validate device_id format (32 alphanumeric characters)
 */
function isValidDeviceId(deviceId) {
    return typeof deviceId === 'string' && /^[a-z0-9]{32}$/.test(deviceId);
}

/**
 * Validate nonce format (64 hex characters)
 */
function isValidNonce(nonce) {
    return typeof nonce === 'string' && /^[a-f0-9]{64}$/.test(nonce);
}

/**
 * Check if timestamp is within acceptable window
 * @param {number} timestamp - Unix timestamp in seconds
 * @param {number} windowSeconds - Acceptable drift in seconds
 * @returns {boolean}
 */
function isTimestampValid(timestamp, windowSeconds = TIMESTAMP_WINDOW_SECONDS) {
    const now = Math.floor(Date.now() / 1000);
    return Math.abs(now - timestamp) <= windowSeconds;
}

/**
 * Verify an ECDSA signature
 * @param {string} message - The signed message
 * @param {string} signature - Base64-encoded signature
 * @param {string} publicKeyPem - PEM-encoded public key
 * @returns {boolean} - Whether signature is valid
 */
function verifySignature(message, signature, publicKeyPem) {
    try {
        const verify = crypto.createVerify('SHA256');
        verify.update(message);
        verify.end();
        
        return verify.verify(publicKeyPem, signature, 'base64');
    } catch (err) {
        console.error('Signature verification error:', err.message);
        return false;
    }
}

/**
 * Encode temperature array to program string
 * Each temp (10-30) becomes a letter (A-U)
 */
function encodeProgram(programData) {
    // programData is an array of 7 days, each with 24 temperature values
    let encoded = '';
    for (const day of programData) {
        for (const temp of day) {
            const clampedTemp = Math.max(TEMP_MIN, Math.min(TEMP_MAX, Math.round(temp)));
            encoded += String.fromCharCode(clampedTemp + TEMP_OFFSET);
        }
    }
    return encoded;
}

/**
 * Decode program string to temperature array
 */
function decodeProgram(encoded) {
    if (!encoded || encoded.length !== 168) {
        // Return default program if invalid
        return getDefaultProgram();
    }
    
    const program = [];
    for (let day = 0; day < 7; day++) {
        const dayTemps = [];
        for (let hour = 0; hour < 24; hour++) {
            const char = encoded[day * 24 + hour];
            const temp = char.charCodeAt(0) - TEMP_OFFSET;
            dayTemps.push(Math.max(TEMP_MIN, Math.min(TEMP_MAX, temp)));
        }
        program.push(dayTemps);
    }
    return program;
}

/**
 * Get default program (all hours at 18°C)
 */
function getDefaultProgram() {
    return Array(7).fill(null).map(() => Array(24).fill(18));
}

/**
 * Convert legacy point-based schedule to hourly program format
 */
function convertPointsToHourly(points) {
    // points is array of {hour, temp} objects
    const hourly = Array(24).fill(TEMP_MIN);
    
    if (!points || points.length === 0) {
        return hourly.fill(18);
    }
    
    // Sort points by hour
    const sorted = [...points].sort((a, b) => a.hour - b.hour);
    
    // Fill each hour with the applicable temperature
    let currentTemp = sorted[0].temp;
    for (let hour = 0; hour < 24; hour++) {
        // Find if there's a point at or before this hour
        for (const point of sorted) {
            if (point.hour <= hour) {
                currentTemp = point.temp;
            }
        }
        hourly[hour] = currentTemp;
    }
    
    return hourly;
}

/**
 * Convert hourly program format to point-based schedule for frontend
 */
function convertHourlyToPoints(hourly) {
    const points = [];
    let prevTemp = null;
    
    for (let hour = 0; hour < 24; hour++) {
        if (hourly[hour] !== prevTemp) {
            points.push({ hour, temp: hourly[hour] });
            prevTemp = hourly[hour];
        }
    }
    
    return points;
}

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

/**
 * Middleware to verify browser authentication (cookie-based)
 */
async function requireAuth(req, res, next) {
    const deviceId = req.params.deviceId || req.query.id;
    
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    // Use device-specific cookie name to support multiple devices
    const cookieName = `auth_${deviceId}`;
    const authToken = req.cookies?.[cookieName];
    
    if (!authToken) {
        return res.status(401).json({ error: 'Authentication required', needsAuth: true });
    }
    
    try {
        const authTokenHash = sha256(authToken);
        
        const result = await pool.query(
            'SELECT device_id FROM "Devices" WHERE device_id = $1 AND auth_token_hash = $2',
            [deviceId, authTokenHash]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid authentication', needsAuth: true });
        }
        
        req.deviceId = deviceId;
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).json({ error: 'Authentication check failed' });
    }
}

// ============================================================================
// API ROUTES
// ============================================================================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ----------------------------------------------------------------------------
// DEVICE PROVISIONING
// ----------------------------------------------------------------------------

/**
 * Register a device's public key
 * Called during device setup/provisioning
 * 
 * Security: This endpoint requires the device secret (legacy auth)
 * to prevent unauthorized key registration
 * 
 * POST /api/device/provision
 * Body: { deviceId, deviceSecret, publicKey }
 */
app.post('/api/device/provision', authLimiter, async (req, res) => {
    const { deviceId, deviceSecret, publicKey } = req.body;
    
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    if (!deviceSecret || typeof deviceSecret !== 'string') {
        return res.status(400).json({ error: 'Device secret required' });
    }
    
    if (!publicKey || typeof publicKey !== 'string') {
        return res.status(400).json({ error: 'Public key required' });
    }
    
    // Validate public key format (should be PEM)
    if (!publicKey.includes('-----BEGIN PUBLIC KEY-----')) {
        return res.status(400).json({ error: 'Invalid public key format (expected PEM)' });
    }
    
    try {
        // Verify device secret
        const secretHash = sha256(deviceSecret);
        
        const result = await pool.query(
            'SELECT device_id, public_key FROM "Devices" WHERE device_id = $1 AND device_secret_hash = $2',
            [deviceId, secretHash]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid device credentials' });
        }
        
        // Check if already provisioned
        if (result.rows[0].public_key) {
            return res.status(400).json({ 
                error: 'Device already provisioned',
                hint: 'To re-provision, use /api/device/reprovision endpoint'
            });
        }
        
        // Validate the public key is actually valid ECDSA
        try {
            crypto.createPublicKey(publicKey);
        } catch (keyErr) {
            return res.status(400).json({ error: 'Invalid public key: ' + keyErr.message });
        }
        
        // Store the public key
        await pool.query(
            'UPDATE "Devices" SET public_key = $1 WHERE device_id = $2',
            [publicKey, deviceId]
        );
        
        console.log(`✓ Device ${deviceId} provisioned with public key`);
        res.json({ success: true, message: 'Device provisioned successfully' });
        
    } catch (err) {
        console.error('Provisioning error:', err);
        res.status(500).json({ error: 'Provisioning failed' });
    }
});

/**
 * Re-provision a device (replaces existing key)
 * 
 * POST /api/device/reprovision
 * Body: { deviceId, deviceSecret, publicKey }
 */
app.post('/api/device/reprovision', authLimiter, async (req, res) => {
    const { deviceId, deviceSecret, publicKey } = req.body;
    
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    if (!deviceSecret || typeof deviceSecret !== 'string') {
        return res.status(400).json({ error: 'Device secret required' });
    }
    
    if (!publicKey || typeof publicKey !== 'string') {
        return res.status(400).json({ error: 'Public key required' });
    }
    
    // Validate public key format
    if (!publicKey.includes('-----BEGIN PUBLIC KEY-----')) {
        return res.status(400).json({ error: 'Invalid public key format (expected PEM)' });
    }
    
    try {
        // Verify device secret
        const secretHash = sha256(deviceSecret);
        
        const result = await pool.query(
            'SELECT device_id FROM "Devices" WHERE device_id = $1 AND device_secret_hash = $2',
            [deviceId, secretHash]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid device credentials' });
        }
        
        // Validate the public key
        try {
            crypto.createPublicKey(publicKey);
        } catch (keyErr) {
            return res.status(400).json({ error: 'Invalid public key: ' + keyErr.message });
        }
        
        // Replace the public key and clear any pending auth state
        await pool.query(
            'UPDATE "Devices" SET public_key = $1, pending_nonce = NULL, auth_token_hash = NULL WHERE device_id = $2',
            [publicKey, deviceId]
        );
        
        // Clear any pending auth requests
        await pool.query(
            'DELETE FROM auth_requests WHERE device_id = $1',
            [deviceId]
        );
        
        console.log(`✓ Device ${deviceId} re-provisioned with new public key`);
        res.json({ success: true, message: 'Device re-provisioned successfully' });
        
    } catch (err) {
        console.error('Re-provisioning error:', err);
        res.status(500).json({ error: 'Re-provisioning failed' });
    }
});

// ----------------------------------------------------------------------------
// AUTHENTICATION ENDPOINTS
// ----------------------------------------------------------------------------

/**
 * Check if user is already authenticated for a device
 * GET /api/auth/check?id=<device_id>
 */
app.get('/api/auth/check', authLimiter, async (req, res) => {
    const deviceId = req.query.id;
    
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    // Use device-specific cookie name
    const cookieName = `auth_${deviceId}`;
    const authToken = req.cookies?.[cookieName];
    
    // Check if device exists
    try {
        const deviceResult = await pool.query(
            'SELECT device_id, public_key FROM "Devices" WHERE device_id = $1',
            [deviceId]
        );
        
        if (deviceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }
        
        // Check if device is provisioned
        const isProvisioned = !!deviceResult.rows[0].public_key;
        
        if (!authToken) {
            return res.json({ authenticated: false, provisioned: isProvisioned });
        }
        
        const authTokenHash = sha256(authToken);
        
        const result = await pool.query(
            'SELECT device_id FROM "Devices" WHERE device_id = $1 AND auth_token_hash = $2',
            [deviceId, authTokenHash]
        );
        
        res.json({ 
            authenticated: result.rows.length > 0,
            provisioned: isProvisioned
        });
    } catch (err) {
        console.error('Auth check error:', err);
        res.status(500).json({ error: 'Authentication check failed' });
    }
});

/**
 * Start authentication process (user waiting for button press)
 * Generates a nonce challenge for the device to sign
 * 
 * POST /api/auth/start
 * Body: { deviceId: string }
 */
app.post('/api/auth/start', authLimiter, async (req, res) => {
    const { deviceId } = req.body;
    
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    // Check if device exists AND has a public key registered
    try {
        const deviceResult = await pool.query(
            'SELECT device_id, public_key FROM "Devices" WHERE device_id = $1',
            [deviceId]
        );
        
        if (deviceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }
        
        if (!deviceResult.rows[0].public_key) {
            return res.status(400).json({ 
                error: 'Device not yet provisioned',
                hint: 'The device needs to register its public key first'
            });
        }
    } catch (err) {
        console.error('Device check error:', err);
        return res.status(500).json({ error: 'Database error' });
    }
    
    // Check how many pending requests exist for this device (prevent queue flooding)
    try {
        const countResult = await pool.query(
            'SELECT COUNT(*) as count FROM auth_requests WHERE device_id = $1 AND expires_at > NOW()',
            [deviceId]
        );
        
        if (parseInt(countResult.rows[0].count) >= MAX_PENDING_AUTH_PER_DEVICE) {
            return res.status(429).json({ 
                error: 'Too many pending authentication requests for this device. Please wait.',
                retryAfter: 60
            });
        }
    } catch (err) {
        console.error('Count check error:', err);
    }
    
    // Generate unique identifiers
    const clientId = generateToken();
    const nonce = generateNonce();
    const expiresAt = new Date(Date.now() + AUTH_TIMEOUT_MS);
    
    // Store auth request in database
    try {
        await pool.query(
            'INSERT INTO auth_requests (device_id, client_id, nonce, expires_at) VALUES ($1, $2, $3, $4)',
            [deviceId, clientId, nonce, expiresAt]
        );
        
        // Store nonce on device record so hub can retrieve it during polling
        await pool.query(
            'UPDATE "Devices" SET pending_nonce = $1 WHERE device_id = $2',
            [nonce, deviceId]
        );
    } catch (err) {
        console.error('Failed to create auth request:', err);
        return res.status(500).json({ error: 'Failed to start authentication' });
    }
    
    res.json({
        success: true,
        clientId,
        expiresAt: expiresAt.toISOString(),
        message: 'Press the auth button on the hub within 60 seconds'
    });
});

/**
 * Poll for authentication status
 * GET /api/auth/poll?id=<device_id>&clientId=<client_id>
 */
app.get('/api/auth/poll', authLimiter, async (req, res) => {
    const { id: deviceId, clientId } = req.query;
    
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    if (!clientId) {
        return res.status(400).json({ error: 'Client ID required' });
    }
    
    try {
        // Get this client's auth request
        const clientResult = await pool.query(
            'SELECT id, nonce, created_at, expires_at, verified FROM auth_requests WHERE client_id = $1 AND device_id = $2',
            [clientId, deviceId]
        );
        
        if (clientResult.rows.length === 0) {
            return res.json({ status: 'expired', message: 'Authentication session expired or invalid' });
        }
        
        const clientRequest = clientResult.rows[0];
        
        // Check if expired
        if (new Date(clientRequest.expires_at) < new Date()) {
            // Clean up expired request
            await pool.query('DELETE FROM auth_requests WHERE id = $1', [clientRequest.id]);
            return res.json({ status: 'timeout', message: 'Authentication timed out' });
        }
        
        // Check if this client's request has been verified
        if (clientRequest.verified) {
            // This client is verified - issue auth token
            const authToken = generateToken();
            const authTokenHash = sha256(authToken);
            
            // Update device with new auth token and clear pending nonce
            await pool.query(
                'UPDATE "Devices" SET auth_token_hash = $1, pending_nonce = NULL WHERE device_id = $2',
                [authTokenHash, deviceId]
            );
            
            // Delete this auth request
            await pool.query('DELETE FROM auth_requests WHERE id = $1', [clientRequest.id]);
            
            // Set device-specific cookie (10 years expiry)
            const cookieName = `auth_${deviceId}`;
            res.cookie(cookieName, authToken, {
                httpOnly: true,
                secure: NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 10 * 365 * 24 * 60 * 60 * 1000 // 10 years
            });
            
            return res.json({ status: 'authenticated', message: 'Successfully authenticated' });
        }
        
        // Still waiting - calculate position in queue
        const positionResult = await pool.query(`
            SELECT COUNT(*) as position FROM auth_requests 
            WHERE device_id = $1 AND expires_at > NOW() AND created_at < $2
        `, [deviceId, clientRequest.created_at]);
        
        const position = parseInt(positionResult.rows[0].position) + 1;
        const timeRemaining = Math.max(0, new Date(clientRequest.expires_at) - new Date());
        
        res.json({
            status: 'waiting',
            position,
            timeRemaining: Math.ceil(timeRemaining / 1000),
            message: position === 1 ? 'Press the auth button on the hub' : `Waiting (position ${position} in queue)`
        });
    } catch (err) {
        console.error('Auth poll error:', err);
        res.status(500).json({ error: 'Failed to check authentication status' });
    }
});

/**
 * Hub verifies user authentication with signed challenge
 * Uses ECDSA signature verification
 * 
 * POST /api/auth/verify
 * Body: { deviceId, nonce, timestamp, signature }
 */
app.post('/api/auth/verify', authLimiter, async (req, res) => {
    const { deviceId, nonce, timestamp, signature } = req.body;
    
    // Validate deviceId
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    // Validate nonce format
    if (!nonce || !isValidNonce(nonce)) {
        return res.status(400).json({ error: 'Invalid nonce format' });
    }
    
    // Validate timestamp
    if (timestamp === undefined || typeof timestamp !== 'number') {
        return res.status(400).json({ error: 'Invalid timestamp' });
    }
    
    // Validate signature
    if (!signature || typeof signature !== 'string') {
        return res.status(400).json({ error: 'Invalid signature' });
    }
    
    // Check timestamp is within acceptable window (±60 seconds)
    if (!isTimestampValid(timestamp)) {
        return res.status(401).json({ 
            error: 'Timestamp out of range',
            serverTime: Math.floor(Date.now() / 1000),
            receivedTime: timestamp
        });
    }
    
    try {
        // Get device's public key and pending nonce
        const deviceResult = await pool.query(
            'SELECT public_key, pending_nonce FROM "Devices" WHERE device_id = $1',
            [deviceId]
        );
        
        if (deviceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }
        
        const device = deviceResult.rows[0];
        
        if (!device.public_key) {
            return res.status(400).json({ error: 'Device not provisioned' });
        }
        
        // Verify nonce matches what we're expecting
        if (!device.pending_nonce) {
            return res.status(400).json({ error: 'No pending authentication request' });
        }
        
        if (!secureCompare(device.pending_nonce, nonce)) {
            return res.status(401).json({ error: 'Invalid nonce' });
        }
        
        // Reconstruct the message that was signed
        const message = `${deviceId}:${nonce}:${timestamp}`;
        
        // Verify the ECDSA signature
        if (!verifySignature(message, signature, device.public_key)) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
        
        // Signature valid! Find the pending auth request with this nonce
        const pendingResult = await pool.query(
            'SELECT id FROM auth_requests WHERE device_id = $1 AND nonce = $2 AND expires_at > NOW() AND verified = FALSE ORDER BY created_at ASC LIMIT 1',
            [deviceId, nonce]
        );
        
        if (pendingResult.rows.length === 0) {
            // This could happen if the request expired between nonce check and here
            return res.status(400).json({ error: 'No matching pending authentication request' });
        }
        
        // Mark the FIRST auth request with this nonce as verified
        // (There should only be one, since nonce is unique per /auth/start call)
        await pool.query(
            'UPDATE auth_requests SET verified = TRUE WHERE id = $1',
            [pendingResult.rows[0].id]
        );
        
        // Clear the pending nonce (prevents replay with same nonce)
        await pool.query(
            'UPDATE "Devices" SET pending_nonce = NULL WHERE device_id = $1',
            [deviceId]
        );
        
        console.log(`✓ Device ${deviceId} verified authentication via ECDSA signature`);
        res.json({ success: true, message: 'Device verified, user will be authenticated' });
        
    } catch (err) {
        console.error('Verification error:', err);
        res.status(500).json({ error: 'Verification failed' });
    }
});

/**
 * Logout (clear auth token for a specific device)
 * POST /api/auth/logout
 * Body: { deviceId: string }
 */
app.post('/api/auth/logout', (req, res) => {
    const { deviceId } = req.body;
    
    if (deviceId && isValidDeviceId(deviceId)) {
        // Clear device-specific cookie
        const cookieName = `auth_${deviceId}`;
        res.clearCookie(cookieName);
        res.json({ success: true, message: 'Logged out from device' });
    } else {
        // If no deviceId provided, return error
        res.status(400).json({ error: 'Device ID required for logout' });
    }
});

// ----------------------------------------------------------------------------
// DEVICE STATE ENDPOINTS (require authentication)
// ----------------------------------------------------------------------------

/**
 * Get device state
 * GET /api/device/:deviceId
 */
app.get('/api/device/:deviceId', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT current_temp, set_temp, boost, mode, program FROM "Devices" WHERE device_id = $1',
            [req.deviceId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }
        
        const device = result.rows[0];
        const program = decodeProgram(device.program);
        
        // Convert program to point-based format for frontend compatibility
        const schedulePoints = program.map(dayHourly => convertHourlyToPoints(dayHourly));
        
        res.json({
            currentTemp: device.current_temp,
            setTemp: device.set_temp,
            boost: device.boost,
            mode: device.mode ? 'program' : 'manual',
            program: schedulePoints
        });
    } catch (err) {
        console.error('Get device state error:', err);
        res.status(500).json({ error: 'Failed to get device state' });
    }
});

/**
 * Update device settings
 * PATCH /api/device/:deviceId
 * Body: { setTemp?, boost?, mode?, program? }
 */
app.patch('/api/device/:deviceId', requireAuth, async (req, res) => {
    const { setTemp, boost, mode, program } = req.body;
    
    const updates = [];
    const values = [];
    let paramIndex = 1;
    
    // Validate and add setTemp
    if (setTemp !== undefined) {
        const temp = parseInt(setTemp, 10);
        if (isNaN(temp) || temp < 10 || temp > 30) {
            return res.status(400).json({ error: 'Invalid setTemp (must be 10-30)' });
        }
        updates.push(`set_temp = $${paramIndex++}`);
        values.push(temp);
    }
    
    // Validate and add boost
    if (boost !== undefined) {
        const boostVal = parseInt(boost, 10);
        if (isNaN(boostVal) || boostVal < 0 || boostVal > 3) {
            return res.status(400).json({ error: 'Invalid boost (must be 0-3)' });
        }
        updates.push(`boost = $${paramIndex++}`);
        values.push(boostVal);
    }
    
    // Validate and add mode
    if (mode !== undefined) {
        const modeVal = mode === 'program' || mode === true || mode === 1;
        updates.push(`mode = $${paramIndex++}`);
        values.push(modeVal);
    }
    
    // Validate and add program
    if (program !== undefined) {
        if (!Array.isArray(program) || program.length !== 7) {
            return res.status(400).json({ error: 'Invalid program (must be array of 7 days)' });
        }
        
        // Convert point-based schedule to hourly format
        const hourlyProgram = program.map(dayPoints => {
            if (Array.isArray(dayPoints) && dayPoints.length > 0 && typeof dayPoints[0] === 'object') {
                return convertPointsToHourly(dayPoints);
            } else if (Array.isArray(dayPoints) && dayPoints.length === 24) {
                return dayPoints;
            }
            return Array(24).fill(18);
        });
        
        const encoded = encodeProgram(hourlyProgram);
        updates.push(`program = $${paramIndex++}`);
        values.push(encoded);
    }
    
    if (updates.length === 0) {
        return res.status(400).json({ error: 'No valid updates provided' });
    }
    
    values.push(req.deviceId);
    
    try {
        await pool.query(
            `UPDATE "Devices" SET ${updates.join(', ')} WHERE device_id = $${paramIndex}`,
            values
        );
        
        res.json({ success: true, message: 'Device updated' });
    } catch (err) {
        console.error('Update device error:', err);
        res.status(500).json({ error: 'Failed to update device' });
    }
});

/**
 * Update only the set temperature (convenience endpoint)
 * PUT /api/device/:deviceId/temp
 * Body: { temp: number }
 */
app.put('/api/device/:deviceId/temp', requireAuth, async (req, res) => {
    const { temp } = req.body;
    const tempVal = parseInt(temp, 10);
    
    if (isNaN(tempVal) || tempVal < 10 || tempVal > 30) {
        return res.status(400).json({ error: 'Invalid temperature (must be 10-30)' });
    }
    
    try {
        await pool.query(
            'UPDATE "Devices" SET set_temp = $1 WHERE device_id = $2',
            [tempVal, req.deviceId]
        );
        
        res.json({ success: true, setTemp: tempVal });
    } catch (err) {
        console.error('Update temp error:', err);
        res.status(500).json({ error: 'Failed to update temperature' });
    }
});

/**
 * Update only the boost setting (convenience endpoint)
 * PUT /api/device/:deviceId/boost
 * Body: { boost: number }
 */
app.put('/api/device/:deviceId/boost', requireAuth, async (req, res) => {
    const { boost } = req.body;
    const boostVal = parseInt(boost, 10);
    
    if (isNaN(boostVal) || boostVal < 0 || boostVal > 3) {
        return res.status(400).json({ error: 'Invalid boost (must be 0-3)' });
    }
    
    try {
        await pool.query(
            'UPDATE "Devices" SET boost = $1 WHERE device_id = $2',
            [boostVal, req.deviceId]
        );
        
        res.json({ success: true, boost: boostVal });
    } catch (err) {
        console.error('Update boost error:', err);
        res.status(500).json({ error: 'Failed to update boost' });
    }
});

/**
 * Update only the mode (convenience endpoint)
 * PUT /api/device/:deviceId/mode
 * Body: { mode: 'manual' | 'program' }
 */
app.put('/api/device/:deviceId/mode', requireAuth, async (req, res) => {
    const { mode } = req.body;
    
    if (mode !== 'manual' && mode !== 'program') {
        return res.status(400).json({ error: 'Invalid mode (must be "manual" or "program")' });
    }
    
    const modeVal = mode === 'program';
    
    try {
        await pool.query(
            'UPDATE "Devices" SET mode = $1 WHERE device_id = $2',
            [modeVal, req.deviceId]
        );
        
        res.json({ success: true, mode });
    } catch (err) {
        console.error('Update mode error:', err);
        res.status(500).json({ error: 'Failed to update mode' });
    }
});

/**
 * Update only the program schedule (convenience endpoint)
 * PUT /api/device/:deviceId/program
 * Body: { program: array }
 */
app.put('/api/device/:deviceId/program', requireAuth, async (req, res) => {
    const { program } = req.body;
    
    if (!Array.isArray(program) || program.length !== 7) {
        return res.status(400).json({ error: 'Invalid program (must be array of 7 days)' });
    }
    
    // Convert point-based schedule to hourly format
    const hourlyProgram = program.map(dayPoints => {
        if (Array.isArray(dayPoints) && dayPoints.length > 0 && typeof dayPoints[0] === 'object') {
            return convertPointsToHourly(dayPoints);
        } else if (Array.isArray(dayPoints) && dayPoints.length === 24) {
            return dayPoints;
        }
        return Array(24).fill(18);
    });
    
    const encoded = encodeProgram(hourlyProgram);
    
    try {
        await pool.query(
            'UPDATE "Devices" SET program = $1 WHERE device_id = $2',
            [encoded, req.deviceId]
        );
        
        res.json({ success: true, message: 'Program updated' });
    } catch (err) {
        console.error('Update program error:', err);
        res.status(500).json({ error: 'Failed to update program' });
    }
});

// ----------------------------------------------------------------------------
// DEVICE POLLING ENDPOINT (for the physical device/hub)
// ----------------------------------------------------------------------------

/**
 * Device polls for current settings
 * Returns pending nonce if there's an auth request waiting
 * 
 * GET /api/hub/:deviceId/poll
 * Query: secret=<device_secret>
 */
app.get('/api/hub/:deviceId/poll', async (req, res) => {
    const { deviceId } = req.params;
    const { secret } = req.query;
    
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    if (!secret) {
        return res.status(401).json({ error: 'Device secret required' });
    }
    
    try {
        const secretHash = sha256(secret);
        
        const result = await pool.query(
            'SELECT set_temp, boost, mode, program, pending_nonce FROM "Devices" WHERE device_id = $1 AND device_secret_hash = $2',
            [deviceId, secretHash]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid device credentials' });
        }
        
        const device = result.rows[0];
        
        res.json({
            setTemp: device.set_temp,
            boost: device.boost,
            mode: device.mode ? 'program' : 'manual',
            program: device.program || '',
            pendingNonce: device.pending_nonce || null
        });
    } catch (err) {
        console.error('Hub poll error:', err);
        res.status(500).json({ error: 'Poll failed' });
    }
});

/**
 * Device reports current temperature
 * POST /api/hub/:deviceId/report
 * Body: { secret: string, currentTemp: number }
 */
app.post('/api/hub/:deviceId/report', async (req, res) => {
    const { deviceId } = req.params;
    const { secret, currentTemp } = req.body;
    
    if (!deviceId || !isValidDeviceId(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    if (!secret) {
        return res.status(401).json({ error: 'Device secret required' });
    }
    
    const tempVal = parseFloat(currentTemp);
    if (isNaN(tempVal)) {
        return res.status(400).json({ error: 'Invalid temperature' });
    }
    
    try {
        const secretHash = sha256(secret);
        
        const result = await pool.query(
            'UPDATE "Devices" SET current_temp = $1 WHERE device_id = $2 AND device_secret_hash = $3 RETURNING device_id',
            [Math.round(tempVal), deviceId, secretHash]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid device credentials' });
        }
        
        res.json({ success: true });
    } catch (err) {
        console.error('Hub report error:', err);
        res.status(500).json({ error: 'Report failed' });
    }
});

// ----------------------------------------------------------------------------
// SERVE STATIC FILES (for production)
// ----------------------------------------------------------------------------

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Catch-all route to serve the frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
    console.log(`🌡️  Thermostat API running on port ${PORT}`);
    console.log(`   Environment: ${NODE_ENV}`);
    console.log(`   Auth: ECDSA asymmetric key authentication`);
});

module.exports = app;
