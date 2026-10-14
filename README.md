# RailPay Backend API

> **Non-Custodial USDC Payment Gateway on the Arc Network**  
> Pure REST & JSON backend powering buyer checkout pages, merchant dashboards, on-chain watchers, automated settlement sweeps, and transactional emails.

---

## 1. System Overview & Architecture

RailPay is split into three decoupled components:
1. **Backend Daemon (`cmd/arcpay`)**: This repository. Houses the HTTP JSON APIs, PostgreSQL persistence, double-entry ledger, blockchain event watcher, automated sweep settler, and transactional email outbox worker.
2. **Remote Signer Daemon (`cmd/signer`)**: Runs in an isolated security environment (e.g., VPS / hardware enclave). Holds the derivation seed and signs Ethereum transactions without ever exposing private keys to the gateway.
3. **Frontend Application**: Buyer checkout UI (`/pay/:id`) and merchant portal dashboard (`/dashboard`) that consume this backend over REST.

```
                    +---------------------------+
                    |   Frontend Application    |
                    | (Checkout & Merchant UI)  |
                    +-------------+-------------+
                                  |
                                  | HTTP / JSON (CORS + Cookies)
                                  v
+---------------------------------------------------------------+
|                      RailPay Gateway Backend                  |
|                                                               |
|  - Public Checkout API (/pay/:id)                             |
|  - Merchant Dashboard REST API (/api/*)                       |
|  - Payment Intent Engine (/v1/payment_intents)                |
|  - Transactional Outbox (Resend SMTP Notifications)           |
|  - Blockchain Watcher & Settler (Arc Testnet 5042002)         |
|  - Cryptographic Double-Entry Ledger                          |
+---------------+-------------------------------+---------------+
                |                               |
                v                               v
    +-----------------------+       +-----------------------+
    | PostgreSQL Database   |       | Remote Signer Daemon  |
    | (State & Outboxes)    |       | (Isolated Seed / VPS) |
    +-----------------------+       +-----------------------+
```

---

## 2. API Base URLs & Network Parameters

### Base URLs for Frontend Integration
| Environment | Base URL | Status |
| :--- | :--- | :--- |
| **Live VPS (Production/Staging)** | `http://144.202.25.12:8080` | ✅ Active & Running |
| **Local Development** | `http://localhost:8080` | Local Go daemon |

#### Frontend `.env.local` Configuration:
```env
NEXT_PUBLIC_API_URL=http://144.202.25.12:8080
```

---

### On-Chain Parameters (Testnet vs Mainnet)
| Parameter | Arc Testnet | Arc Mainnet | Description |
| :--- | :--- | :--- | :--- |
| **Chain ID** | `5042002` | `5042` | EVM Chain Identifier |
| **RPC Endpoint** | `https://rpc.testnet.arc.network` | `https://rpc.mainnet.arc.io` | Arc JSON-RPC Node |
| **Block Explorer** | `https://testnet.arcscan.io` | `https://explorer.arc.io` | Transaction & Address Explorer |
| **USDC Emitter** | `0xfffffffffffffffffffffffffffffffffffffffe` | `0xfffffffffffffffffffffffffffffffffffffffe` | Native USDC System Contract on Arc |
| **Decimals** | `6` (display) / `18` (native) | `6` (display) / `18` (native) | 1.000000 USDC = 1,000,000 units |

---

## 3. Frontend Authentication & Security

The backend supports two distinct authentication schemes:

### A. Session Cookie (Merchant Dashboard Frontend)
Used by browser sessions on the merchant portal:
* **Cookie Name**: `railpay_session` (`HttpOnly`, `SameSite=Lax`, `Secure` in production).
* **CORS Support**: Whitelisted in `.env` under `ALLOWED_ORIGINS` (e.g. `http://localhost:3000`). Frontend requests must pass `credentials: "include"`.
* **CSRF Protection**: State-changing dashboard requests (`POST /api/*`, `PUT`, `PATCH`, `DELETE`) require the `X-CSRF-Token` header. The active token is returned in `POST /auth/login`, `POST /auth/signup`, and `GET /api/me`.

### B. Bearer API Key (Merchant Server-to-Server API)
Used by merchants' servers to generate payment intents:
* Header: `Authorization: Bearer sk_live_...`
* Keys are created and revoked in the dashboard under `/api/keys` (an initial key is automatically created upon signup).

---

## 4. API Reference for Frontend Integration

### 4.1 Root & Health Check
#### `GET /`
Returns service status.
```json
{
  "service": "RailPay API",
  "version": "v1",
  "status": "online",
  "network": "arc"
}
```

#### `GET /healthz`
Health check endpoint. Returns HTTP `200 OK` with text `ok`.

---

### 4.2 Authentication Endpoints (Signup, Login & Logout)

#### `POST /auth/signup` (Alias: `/api/auth/signup`)
Registers a new merchant with email and password. Generates a merchant account, user profile, initial live API key, and creates an active session.
* **Headers**: `Content-Type: application/json`
* **Request Body**:
```json
{
  "email": "merchant@example.com",
  "password": "YourSecurePassword123!",
  "name": "Acme Global"
}
```
* **Validation**:
  * `email`: Must be a valid email address.
  * `password`: Minimum 8 characters, maximum 72 characters.
  * `name`: Optional (defaults to username prefix of email).
* **Response** (`201 Created`):
```json
{
  "ok": true,
  "token": "ses_43ab98d...",
  "csrf_token": "a1b2c3d4e5...",
  "user": {
    "id": "usr_7812...",
    "email": "merchant@example.com",
    "name": "Acme Global",
    "provider": "password"
  },
  "merchant": {
    "id": "mch_9021...",
    "name": "Acme Global",
    "email": "merchant@example.com",
    "fee_bps": 50,
    "settlement_address": "",
    "webhook_url": "",
    "webhook_secret": "••••••••",
    "created_at": "2026-10-13T18:30:00Z"
  }
}
```
* **Cookies**: Automatically sets `railpay_session` cookie on the response.
* **Errors**:
  * `409 Conflict`: `{"error":{"message":"an account with this email already exists"}}`
  * `400 Bad Request`: `{"error":{"message":"password must be at least 8 characters"}}`

#### `POST /auth/login` (Aliases: `/auth/signin`, `/api/auth/login`)
Authenticates an existing merchant with email and password.
* **Headers**: `Content-Type: application/json`
* **Request Body**:
```json
{
  "email": "merchant@example.com",
  "password": "YourSecurePassword123!"
}
```
* **Response** (`200 OK`):
```json
{
  "ok": true,
  "token": "ses_43ab98d...",
  "csrf_token": "a1b2c3d4e5...",
  "user": {
    "id": "usr_7812...",
    "email": "merchant@example.com",
    "name": "Acme Global",
    "provider": "password"
  },
  "merchant": {
    "id": "mch_9021...",
    "name": "Acme Global",
    "email": "merchant@example.com",
    "fee_bps": 50,
    "settlement_address": "0x...",
    "webhook_url": "",
    "webhook_secret": "••••••••",
    "created_at": "2026-10-13T18:30:00Z"
  }
}
```
* **Cookies**: Automatically sets `railpay_session` cookie on the response.
* **Errors**:
  * `401 Unauthorized`: `{"error":{"message":"invalid email or password"}}`

#### `POST /auth/logout` (Alias: `/api/auth/logout`)
Destroys the active session and clears the `railpay_session` cookie.
* **Response** (`200 OK`):
```json
{ "ok": true }
```

#### Frontend Integration Examples (Next.js / React)

##### Signup Example:
```typescript
async function handleSignup(email: string, password: string, name: string) {
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // Stores railpay_session cookie in browser
    body: JSON.stringify({ email, password, name }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Signup failed');
  return data; // { ok, token, csrf_token, user, merchant }
}
```

##### Login Example:
```typescript
async function handleLogin(email: string, password: string) {
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include', // Stores railpay_session cookie in browser
    body: JSON.stringify({ email, password }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error?.message || 'Login failed');
  return data; // { ok, token, csrf_token, user, merchant }
}
```

##### Logout Example:
```typescript
async function handleLogout() {
  await fetch(`${process.env.NEXT_PUBLIC_API_URL}/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  });
  window.location.href = '/login';
}
```

---

### 4.5 Merchant Dashboard REST APIs
All routes require valid `railpay_session` cookie (`credentials: "include"`). Mutations require `X-CSRF-Token` header.

#### `GET /api/me`
Fetches current logged-in user profile, merchant configuration, and active CSRF token.
* **Response** (`200 OK`):
```json
{
  "csrf_token": "...",
  "merchant": {
    "id": "mch_12a00f5307648e063ad4def1",
    "name": "Acme Store",
    "email": "merchant@example.com",
    "fee_bps": 50,
    "settlement_address": "0xce768c895e4be936db7dea5f53ad3b60ad3c3456",
    "webhook_url": "https://example.com/webhooks/railpay",
    "webhook_secret": "••••••••",
    "email_opt_out": false,
    "created_at": "2026-10-11T20:00:00Z"
  },
  "user": {
    "id": "usr_...",
    "email": "user@example.com",
    "name": "Jane Doe",
    "provider": "google"
  }
}
```

#### `GET /api/stats`
Returns aggregated volume and settlement metrics.
* **Response** (`200 OK`):
```json
{
  "volume": "150.000000",
  "pending_payout": "0.000000",
  "settled": "148.500000",
  "raw": {
    "volume_micro": 150000000,
    "pending_payout_micro": 0,
    "settled_micro": 148500000
  }
}
```

#### `GET /api/intents`
Lists merchant payment intents.
* **Query Parameters**:
  * `limit`: Number of items (default 20, max 100)
  * `status`: Filter by `pending`, `paid`, `expired`
  * `cursor`: Pagination cursor

#### `GET /api/intents/{id}`
Returns details of a specific payment intent, including confirmed on-chain transactions and block numbers.

#### `GET /api/payouts`
Lists all completed settlement sweep jobs sent to the merchant's destination wallet.
* **Response Array Items**:
```json
{
  "id": "swp_d01b17bdab45484607213c93",
  "intent_id": "pi_bfd4eeecd6820765958e4217",
  "status": "confirmed",
  "destination": "0xce768c895e4be936db7dea5f53ad3b60ad3c3456",
  "amount": "2.138620",
  "tx_hash": "0xf24aa6c7e235788f79ad82acdcd3e3fef3bd00c43d973064e2284a6d6f32ce87",
  "created_at": "2026-10-13T01:37:44Z"
}
```

#### `GET /api/settlement`
Fetches current settlement destination address and any pending updates under security cooldown.

#### `PUT /api/settlement`
Updates the automatic sweep destination wallet address on the Arc network.
* **Headers**: `X-CSRF-Token: <token>`
* **Body**: `{"address": "0xce768c895e4be936db7dea5f53ad3b60ad3c3456"}`

#### `GET /api/keys`
Lists all generated API keys with metadata (`id`, `name`, `prefix`, `created_at`, `last_used_at`).

#### `POST /api/keys`
Generates a new API key.
* **Headers**: `X-CSRF-Token: <token>`
* **Body**: `{"name": "Production Server"}`
* **Response** (`201 Created`):
```json
{
  "id": "key_...",
  "name": "Production Server",
  "key": "sk_live_cbNGjMDfxYemRhI_Si5_UF-XmcK0sP-3Df0fFSWeloo"
}
```
> **Warning**: The `key` plaintext is **only returned once** at creation.

#### `DELETE /api/keys/{id}`
Revokes an API key.
* **Headers**: `X-CSRF-Token: <token>`

#### `PATCH /api/merchant`
Updates merchant settings.
* **Headers**: `X-CSRF-Token: <token>`
* **Body**:
```json
{
  "name": "Acme Corp",
  "webhook_url": "https://example.com/api/webhooks",
  "email_opt_out": false
}
```

#### `POST /api/merchant/webhook_secret/rotate`
Rotates the merchant webhook signing secret.
* **Headers**: `X-CSRF-Token: <token>`
* **Response**: `{"webhook_secret": "whsec_..."}`

#### `GET /api/webhooks/deliveries`
Audits outgoing webhook delivery logs and retry statuses.

---

## 5. Webhook Integration Guide

When on-chain events occur, RailPay dispatches POST requests to the merchant's `webhook_url`.

### Headers
```http
POST /api/webhooks HTTP/1.1
Host: your-server.com
Content-Type: application/json
User-Agent: railpay-webhooks/1
Railpay-Event-Id: evt_912ec803b2ce49e4a541068d
Railpay-Signature: t=1760319400,v1=6d4986b5155f6e632b73ec437c03ec845f9d2d48c8b...
```

### Signature Verification (Node.js Example)
```javascript
import crypto from 'crypto';

export function verifyWebhook(payload, signatureHeader, secret) {
  const parts = Object.fromEntries(signatureHeader.split(',').map(kv => kv.split('=')));
  const timestamp = parts.t;
  const signature = parts.v1;

  // Protect against replay attacks (e.g., 5-minute tolerance)
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp, 10)) > 300) {
    throw new Error('Timestamp out of tolerance');
  }

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${payload}`)
    .digest('hex');

  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
```

### Supported Event Types
| Event | Trigger |
| :--- | :--- |
| `payment_intent.succeeded` | Full USDC amount detected and confirmed on Arc Testnet |
| `payment_intent.partially_paid` | Deposit detected, but less than required intent amount |
| `payment_intent.expired` | Intent timed out after 30 minutes without deposit |
| `payment_intent.late_payment` | Deposit arrived after expiration window |
| `payout.sent` | Settler daemon successfully swept funds to merchant's settlement wallet |

---

## 6. Frontend Quickstart Guide

### Suggested App Structure (Next.js / React)
```
frontend/
├── app/
│   ├── pay/
│   │   └── [id]/page.tsx      # Buyer Checkout (calls GET /pay/:id and polls /pay/:id/status)
│   ├── login/
│   │   └── page.tsx           # Merchant Sign-in (calls GET /login, links to /auth/:provider/start)
│   ├── dashboard/
│   │   ├── page.tsx           # Overview (calls /api/me & /api/stats)
│   │   ├── payments/page.tsx  # Payments table (calls /api/intents)
│   │   ├── payouts/page.tsx   # Payouts list (calls /api/payouts)
│   │   ├── keys/page.tsx      # API Keys manager (calls /api/keys)
│   │   └── settings/page.tsx  # Settlement & Webhooks (/api/settlement & PATCH /api/merchant)
```

### Fetch Utility Example
```typescript
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://144.202.25.12:8080";

export async function fetchWithAuth(endpoint: string, options: RequestInit = {}) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    credentials: "include", // Sends railpay_session cookie
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  if (res.status === 401) {
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }

  return res.json();
}
```

---

## 7. Running the Backend Locally

```bash
# 1. Start PostgreSQL (Docker)
docker run -d --name arcpay-postgres -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=arcpay postgres:16-alpine

# 2. Run backend daemon
go run ./cmd/arcpay

# 3. Run all tests
go test ./...
```

---

## 8. VPS Deployment Guide (`144.202.25.12`)

The production/staging gateway runs as a systemd service (`railpay.service`) on the VPS.

### Deployment Steps

#### Step 1: Cross-Compile on Mac for Linux AMD64
Because macOS is Darwin (ARM64/Apple Silicon), you **must cross-compile** for the Linux x86_64 VPS architecture:
```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o railpay-server-linux ./cmd/arcpay
```

#### Step 2: Upload Binary to VPS (Temporary Path)
Transfer the compiled executable to `/tmp` first to avoid Linux file-locking (`Text file busy`) while the service is currently running:
```bash
scp railpay-server-linux root@144.202.25.12:/tmp/railpay-server-new
```

#### Step 3: Replace Binary & Restart Service
Atomically replace the running executable and restart `railpay.service`:
```bash
ssh root@144.202.25.12 "mv /tmp/railpay-server-new /opt/railpay/railpay-server && chmod +x /opt/railpay/railpay-server && systemctl restart railpay"
```

#### Step 4: Verify Service Status & Logs
```bash
# Check service status
ssh root@144.202.25.12 "systemctl status railpay"

# View real-time service logs
ssh root@144.202.25.12 "journalctl -u railpay -f"

# Test root endpoint
curl -i http://144.202.25.12:8080/
```

---

### VPS Service & File Layout Reference
* **Binary Path**: `/opt/railpay/railpay-server`
* **Configuration**: `/opt/railpay/.env`
* **PostgreSQL Container**: `railpay-postgres` (Docker on port `127.0.0.1:5432`)
* **Signer Service**: `arcpay-signer` (listening on `127.0.0.1:8081`)
* **Systemd Service**: `/etc/systemd/system/railpay.service`

---

## 9. Switching to Arc Mainnet Checklist

When you are ready to switch from Arc Testnet to Arc Mainnet, follow this 4-step checklist:

### 1. Update Signer Daemon (`/opt/arcpay-signer/.env` on VPS)
The Signer uses `CHAIN_ID` to sign transactions and enforces production risk controls:
```env
# 1. Mainnet Chain ID
CHAIN_ID=5042

# 2. Production Security Controls
ARCPAY_ENV=prod
DESTINATION_COOLDOWN=24h
REQUIRE_APPROVAL=true

# 3. Daily & Transaction Caps
MAX_VALUE_USDC=10000
DAILY_CAP_USDC=50000
GLOBAL_DAILY_CAP_USDC=250000
MAX_FEE_GWEI=1000
```
Restart the signer daemon:
```bash
systemctl restart arcpay-signer
```

### 2. Update Gateway Daemon (`/opt/railpay/.env` on VPS)
The Gateway auto-detects `CHAIN_ID=5042` from the RPC node on startup:
```env
# 1. Mainnet RPC Endpoint
ARC_RPC_URL=https://rpc.mainnet.arc.io

# 2. Mainnet Explorer
EXPLORER_URL=https://explorer.arc.io

# 3. Production Environment & Start Block
ARCPAY_ENV=prod
START_BLOCK=25842300  # Set to current Arc mainnet block height to prevent scanning historical blocks
```
Restart the gateway service:
```bash
systemctl restart railpay
```

### 3. Reset PostgreSQL Watcher Cursor
If migrating an existing database that previously watched testnet blocks, reset the watcher cursor so it starts watching from your new `START_BLOCK` on mainnet:
```bash
docker exec -i railpay-postgres psql -U railpay -d railpay -c "DELETE FROM system_cursors WHERE id = 'watcher';"
```

### 4. Update Frontend Configuration (`.env.local`)
In your frontend Next.js app:
* Update any Web3 wallet chains (e.g. wagmi/RainbowKit) to `chainId: 5042`.
* Point block explorer links to `https://explorer.arc.io`.


