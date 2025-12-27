const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Reformat PEM key (fix spacing/newlines)
function formatPEM(key) {
    // Remove all whitespace and headers
    let b64 = key.replace(/-----BEGIN [^-]+-----/, '')
                 .replace(/-----END [^-]+-----/, '')
                 .replace(/\s/g, '');
    // Re-add headers with proper newlines
    return '-----BEGIN PUBLIC KEY-----\n' + 
           b64.match(/.{1,64}/g).join('\n') + 
           '\n-----END PUBLIC KEY-----';
}

// Utility functions
const hash = (str) => crypto.createHash('sha256').update(str).digest('hex');
const randomHex = (bytes) => crypto.randomBytes(bytes).toString('hex');

// Check auth cookie
app.get('/api/auth/check', async (req, res) => {
    const { id } = req.query;
    const cookie = req.cookies[`auth_${id}`];
    if (!cookie) return res.json({ authenticated: false });
    
    try {
        const { device_id, token } = JSON.parse(cookie);
        if (device_id !== id) return res.json({ authenticated: false });
        
        const result = await pool.query(
            'SELECT auth_cookie_token_hash FROM authentication WHERE device_id = $1',
            [id]
        );
        if (result.rows.length === 0) return res.json({ authenticated: false });
        
        const valid = result.rows[0].auth_cookie_token_hash === hash(token);
        res.json({ authenticated: valid });
    } catch {
        res.json({ authenticated: false });
    }
});

// Start auth flow
app.post('/api/auth/start', async (req, res) => {
    const { deviceId } = req.body;
    if (!deviceId || !/^[a-z0-9]{32}$/.test(deviceId)) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    
    const nonce = randomHex(16);
    const clientId = randomHex(16);
    const expires = Date.now() + 60000;
    
    try {
        await pool.query(
            `UPDATE authentication SET auth_nonce = $1, auth_expires = $2, client_id = $3
             WHERE device_id = $4`,
            [nonce, expires, clientId, deviceId]
        );
        res.json({ clientId });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

// Poll auth status
app.get('/api/auth/poll', async (req, res) => {
    const { id, clientId } = req.query;
    
    try {
        const result = await pool.query(
            'SELECT auth_nonce, auth_expires, client_id FROM authentication WHERE device_id = $1',
            [id]
        );
        if (result.rows.length === 0) {
            return res.json({ status: 'error', message: 'Device not found' });
        }
        
        const row = result.rows[0];
        if (row.client_id !== clientId) {
            return res.json({ status: 'error', message: 'Invalid client' });
        }
        
        if (Date.now() > row.auth_expires) {
            return res.json({ status: 'timeout', message: 'Authentication expired' });
        }
        
        // Hub confirmed if nonce is cleared but still within auth window
        if (row.auth_nonce === null) {
            // Generate cookie token for this client
            const token = randomHex(32);
            await pool.query(
                'UPDATE authentication SET auth_cookie_token_hash = $1, client_id = NULL WHERE device_id = $2',
                [hash(token), id]
            );
            
            res.cookie(`auth_${id}`, JSON.stringify({ device_id: id, token }), {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 365 * 24 * 60 * 60 * 1000,
                sameSite: 'strict'
            });
            return res.json({ status: 'authenticated', message: 'Success' });
        }
        
        res.json({ status: 'pending', message: 'Waiting for hub...' });
    } catch (err) {
        console.error('auth/poll error:', err.message);
        res.status(500).json({ status: 'error', message: 'Server error' });
    }
});

// Hub: Get nonce for signing
app.get('/api/hub/nonce', async (req, res) => {
    const { id } = req.query;
    
    try {
        const result = await pool.query(
            'SELECT auth_nonce, auth_expires FROM authentication WHERE device_id = $1',
            [id]
        );
        if (result.rows.length === 0 || !result.rows[0].auth_nonce) {
            return res.status(404).json({ error: 'No pending auth' });
        }
        if (Date.now() > result.rows[0].auth_expires) {
            return res.status(410).json({ error: 'Auth expired' });
        }
        res.json({ nonce: result.rows[0].auth_nonce });
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Hub: Submit signed auth
app.post('/api/hub/auth', async (req, res) => {
    const { deviceId, signature } = req.body;
    
    console.log('=== AUTH DEBUG ===');
    console.log('deviceId:', deviceId);
    console.log('signature length:', signature?.length);
    
    try {
        const result = await pool.query(
            'SELECT auth_public_key, auth_nonce, auth_expires FROM authentication WHERE device_id = $1',
            [deviceId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }
        
        const { auth_public_key, auth_nonce, auth_expires } = result.rows[0];
        const formattedKey = formatPEM(auth_public_key);
        console.log('nonce:', auth_nonce);
        console.log('formatted key:\n', formattedKey.substring(0, 100) + '...');
        
        if (!auth_nonce || Date.now() > auth_expires) {
            return res.status(410).json({ error: 'Auth expired' });
        }
        
        // Verify signature: hub signed (nonce + deviceId) with private key
        const message = auth_nonce + deviceId;
        console.log('message to verify:', message);
        
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(message);
        
        let valid = false;
        let verifyError = null;
        try {
            valid = verify.verify(formattedKey, signature, 'base64');
        } catch (err) {
            verifyError = err.message;
            valid = false;
        }
        
        console.log('valid:', valid);
        if (verifyError) console.log('verify error:', verifyError);
        console.log('=== END DEBUG ===');
        
        if (!valid) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
        
        // Mark auth as complete by clearing nonce
        await pool.query(
            'UPDATE authentication SET auth_nonce = NULL WHERE device_id = $1',
            [deviceId]
        );
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Middleware to verify auth for device endpoints
const requireAuth = async (req, res, next) => {
    const deviceId = req.params.id;
    const cookie = req.cookies[`auth_${deviceId}`];
    
    if (!cookie) {
        return res.status(401).json({ error: 'Not authenticated', needsAuth: true });
    }
    
    try {
        const { device_id, token } = JSON.parse(cookie);
        if (device_id !== deviceId) {
            return res.status(401).json({ error: 'Invalid auth', needsAuth: true });
        }
        
        const result = await pool.query(
            'SELECT auth_cookie_token_hash FROM authentication WHERE device_id = $1',
            [deviceId]
        );
        if (result.rows.length === 0 || result.rows[0].auth_cookie_token_hash !== hash(token)) {
            return res.status(401).json({ error: 'Invalid token', needsAuth: true });
        }
        
        next();
    } catch {
        res.status(401).json({ error: 'Auth error', needsAuth: true });
    }
};

// Get device state
app.get('/api/device/:id', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT current_temp, set_temp, mode, boost, program FROM devices WHERE device_id = $1',
            [req.params.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }
        res.json(result.rows[0]);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update device state
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
    
    values.push(req.params.id);
    
    try {
        await pool.query(
            `UPDATE devices SET ${updates.join(', ')} WHERE device_id = $${idx}`,
            values
        );
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Hub: Get settings
app.get('/api/hub/state', async (req, res) => {
    const { id } = req.query;
    try {
        const result = await pool.query(
            'SELECT set_temp, mode, boost, program FROM devices WHERE device_id = $1',
            [id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Device not found' });
        }
        res.json(result.rows[0]);
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

// Hub: Report temperature
app.post('/api/hub/temp', async (req, res) => {
    const { deviceId, temp } = req.body;
    try {
        await pool.query(
            'UPDATE devices SET current_temp = $1 WHERE device_id = $2',
            [temp, deviceId]
        );
        res.json({ success: true });
    } catch {
        res.status(500).json({ error: 'Server error' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
