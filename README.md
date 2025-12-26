# Thermostat Control System

A REST API backend and web frontend for controlling smart thermostats.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Web Browser   │────▶│   REST API      │────▶│   PostgreSQL    │
│   (Frontend)    │◀────│   (Backend)     │◀────│   (Railway)     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                               │
                        ┌──────▼──────┐
                        │ Thermostat  │
                        │    Hub      │
                        └─────────────┘
```

## Features

- **Secure Authentication**: QR code + physical button authentication
- **Real-time Control**: Set target temperature, boost mode, manual/program modes
- **Weekly Scheduling**: Visual timeline editor for 7-day heating programs
- **Rate Limiting**: Protection against abuse (100/min general, 10/min auth)
- **Mobile-First Design**: Responsive UI with touch support

## Files

```
backend/
├── server.js          # Single-file REST API (all endpoints)
├── package.json       # Node.js dependencies
├── .env.example       # Environment variables template
└── public/
    └── index.html     # Single-file frontend (HTML/CSS/JS)
```

## Setup

### 1. Environment Variables

Set these in Railway (or create a `.env` file locally):

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host:port/db` |
| `COOKIE_SECRET` | Secret for signing cookies | Random 64-char hex string |
| `NODE_ENV` | Environment mode | `production` or `development` |
| `PORT` | Server port (optional) | `3000` |

### 2. Database Schema

The `Devices` table should have:

```sql
CREATE TABLE "Devices" (
    index SERIAL PRIMARY KEY,
    device_id TEXT UNIQUE NOT NULL,
    device_secret_hash TEXT NOT NULL,
    auth_token_hash TEXT,
    current_temp INTEGER DEFAULT 20,
    set_temp INTEGER DEFAULT 21,
    boost INTEGER DEFAULT 0,
    mode BOOLEAN DEFAULT false,
    program TEXT,
    pair TEXT
);
```

### 3. Adding a Device

When flashing a new device:

1. Generate a unique 32-character device ID: `openssl rand -hex 16`
2. Generate a unique 32-character device secret: `openssl rand -hex 16`
3. Hash the secret: `echo -n "your_secret" | sha256sum`
4. Insert into database:

```sql
INSERT INTO "Devices" (device_id, device_secret_hash, set_temp, mode)
VALUES ('your_device_id', 'hashed_secret', 21, false);
```

### 4. Deploy to Railway

```bash
# From the backend directory
railway up
```

Or connect your Git repository for automatic deployments.

## API Reference

### Authentication Endpoints

| Method | Endpoint | Rate Limit | Description |
|--------|----------|------------|-------------|
| GET | `/api/auth/check?id={deviceId}` | 10/min | Check if user is authenticated |
| POST | `/api/auth/start` | 10/min | Start authentication flow |
| GET | `/api/auth/poll?id={deviceId}&clientId={clientId}` | 10/min | Poll for auth status |
| POST | `/api/auth/verify` | 10/min | Hub verifies user (sends secret) |
| POST | `/api/auth/logout` | 10/min | Clear auth cookie (requires deviceId in body) |

### Device Endpoints (Require Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/device/{deviceId}` | Get device state |
| PATCH | `/api/device/{deviceId}` | Update multiple settings |
| PUT | `/api/device/{deviceId}/temp` | Update target temperature |
| PUT | `/api/device/{deviceId}/boost` | Update boost setting |
| PUT | `/api/device/{deviceId}/mode` | Update mode |
| PUT | `/api/device/{deviceId}/program` | Update schedule |

### Hub Endpoints (Device Secret Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/hub/{deviceId}/poll?secret={secret}` | Get current settings |
| POST | `/api/hub/{deviceId}/report` | Report current temperature |

## Authentication Flow

```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  User    │         │  Server  │         │   Hub    │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │                    │                    │
     │ 1. Scan QR Code    │                    │
     │ (contains device_id)                    │
     │                    │                    │
     │ 2. GET /auth/check │                    │
     │───────────────────▶│                    │
     │                    │                    │
     │ 3. Not authenticated                    │
     │◀───────────────────│                    │
     │                    │                    │
     │ 4. POST /auth/start│                    │
     │───────────────────▶│                    │
     │                    │                    │
     │ 5. Returns clientId│                    │
     │◀───────────────────│                    │
     │                    │                    │
     │ 6. User presses    │                    │
     │    button on hub   │                    │
     │                    │                    │
     │                    │ 7. POST /auth/verify│
     │                    │◀───────────────────│
     │                    │ (sends device_secret)
     │                    │                    │
     │ 8. GET /auth/poll  │                    │
     │───────────────────▶│                    │
     │                    │                    │
     │ 9. Authenticated!  │                    │
     │ (Sets auth cookie) │                    │
     │◀───────────────────│                    │
     │                    │                    │
```

## Program Data Format

The schedule is stored as a 168-character string (7 days × 24 hours):

- Each character represents one hour's target temperature
- `A` = 10°C, `B` = 11°C, ... `U` = 30°C
- Characters 0-23: Monday, 24-47: Tuesday, etc.

Example: `IIIIIIIKKKKKKKKIIIIIII` would be:
- Hours 0-6: 18°C (I = 18)
- Hours 7-14: 20°C (K = 20)
- Hours 15-23: 18°C (I = 18)

## Security Considerations

1. **No secrets in code**: All sensitive values are environment variables
2. **SQL injection prevention**: All queries use parameterized statements
3. **Timing-safe comparison**: Auth tokens compared using constant-time algorithm
4. **FIFO authentication**: Only the user waiting longest gets authenticated
5. **Rate limiting**: Database-backed, works across multiple instances
6. **Secure cookies**: HttpOnly, Secure (in production), SameSite=Strict
7. **SHA256 hashing**: Secrets never stored in plaintext
8. **Queue flooding prevention**: Max 10 pending auth requests per device

## Scalability Design

This system is designed to handle many users across many devices:

### Multi-Instance Support
- **Auth state in database**: The `auth_requests` table stores pending authentications, so multiple server instances share the same state
- **Rate limiting in database**: The `rate_limits` table provides distributed rate limiting that works across all instances
- **No in-memory state**: Server restarts don't lose authentication sessions

### Per-Device Isolation
- Each device has its own authentication queue
- Users authenticating Device A cannot interfere with Device B
- Rate limits are per-IP, not per-device

### Database Tables Created Automatically
```sql
-- Pending authentication requests
CREATE TABLE auth_requests (
    id SERIAL PRIMARY KEY,
    device_id TEXT NOT NULL,
    client_id TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN DEFAULT FALSE
);

-- Distributed rate limiting
CREATE TABLE rate_limits (
    id SERIAL PRIMARY KEY,
    key TEXT NOT NULL,
    window_start TIMESTAMP NOT NULL,
    count INTEGER DEFAULT 1,
    UNIQUE(key, window_start)
);
```

### Automatic Cleanup
- Expired auth requests are cleaned up every 30 seconds
- Old rate limit entries are pruned automatically

### Connection Pooling
- Uses pg connection pool with max 20 connections
- Idle connections released after 30 seconds

## Hub Integration

The physical hub should:

1. **On button press**: POST to `/api/auth/verify` with `deviceId` and `deviceSecret`
2. **Periodically poll**: GET `/api/hub/{deviceId}/poll?secret={secret}` for settings
3. **Report temperature**: POST to `/api/hub/{deviceId}/report` with current reading

Example hub code (pseudocode):

```c
// When auth button pressed
void onAuthButtonPress() {
    httpPost("/api/auth/verify", {
        "deviceId": DEVICE_ID,
        "deviceSecret": DEVICE_SECRET
    });
}

// Every 30 seconds
void pollSettings() {
    response = httpGet("/api/hub/" + DEVICE_ID + "/poll?secret=" + DEVICE_SECRET);
    targetTemp = response.setTemp;
    boostHours = response.boost;
    programMode = response.mode == "program";
    // ... apply settings
}

// Every 60 seconds
void reportTemperature() {
    httpPost("/api/hub/" + DEVICE_ID + "/report", {
        "secret": DEVICE_SECRET,
        "currentTemp": readTemperatureSensor()
    });
}
```

## Local Development

```bash
# Install dependencies
npm install

# Create .env file from example
cp .env.example .env
# Edit .env with your values

# Start server
npm start
```

Visit `http://localhost:3000/?id=your_device_id` to test.

## Potential Issues & Troubleshooting

### Authentication Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Authentication timed out" | User didn't press hub button within 60s | Start auth again and press button quickly |
| "Too many pending authentication requests" | >10 users trying to auth same device | Wait 60s for queue to clear |
| "Invalid device credentials" | Wrong device_secret on hub | Check hub firmware has correct secret |
| Cookie not saving | Browser blocking cookies | Enable cookies for the site |

### Connection Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Connection Lost" shown in UI | Server unreachable or DB down | Check Railway status |
| Rate limit errors (429) | Too many requests from IP | Wait 60 seconds |
| Database connection errors | Connection pool exhausted | Increase `max` in pool config |

### Multi-Device Scenarios

| Scenario | Behavior |
|----------|----------|
| User has Device A cookie, scans Device B QR | Auth check fails, user must authenticate Device B |
| Two users auth same device simultaneously | First in queue (FIFO) gets authenticated |
| User opens multiple tabs for same device | Each tab gets separate clientId, only one authenticates |
| Server restarts during auth | Auth continues - state is in database |

### Cookie Behavior

- Cookies are **per-device**: named `auth_<deviceId>` so multiple devices work simultaneously
- User can authenticate Device A and Device B without conflicts
- Cookies **never expire** (10 year max-age)
- Cookies are **HttpOnly**: JavaScript cannot read them (security feature)
- In development, cookies work on HTTP; in production, requires HTTPS
- Re-authenticating a device invalidates the previous session for that device

## License

MIT
