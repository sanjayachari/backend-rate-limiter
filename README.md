# Secure Backend — Node.js

No database. Logs everything and echoes the payload back. Security-first design.

## Quick Start

```bash
npm install
cp .env.example .env
npm start
# or for hot reload:
npm run dev
```

Server starts at `http://localhost:3000`

---

## Endpoints

| Method | Path | Rate Limit | Description |
|--------|------|------------|-------------|
| GET | /health | Global (60/min) | Health check |
| POST | /api/create-record | Strict (10/min) | Create — validates + echoes payload |
| PUT | /api/update-record/:id | Strict (10/min) | Update — echoes payload |
| DELETE | /api/delete-record/:id | Strict (10/min) | Delete — logs record ID |
| GET | /api/records | Global (60/min) | Get records (returns empty array) |
| POST | /api/auth/send-otp | Very strict (5/15min) | OTP endpoint — brute force protected |
| ALL | /api/echo | Strict (10/min) | Echoes everything: method, headers, body, query |

---

## Security Layers (in order they execute)

### 1. Request ID
Every request gets a `X-Request-ID` header. Use it to trace logs.

### 2. Helmet (HTTP Security Headers)
- `Content-Security-Policy` — restricts script sources
- `Strict-Transport-Security` — forces HTTPS (1 year)
- `X-Frame-Options: DENY` — blocks clickjacking
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing
- Removes `X-Powered-By: Express`

### 3. CORS
Only origins listed in `ALLOWED_ORIGINS` (.env) are allowed. Others get `403`.

### 4. Body Size Limit (10kb)
Payloads over 10kb are rejected with `413 Payload Too Large`. Prevents memory exhaustion attacks.

### 5. HPP — HTTP Parameter Pollution
Prevents attacks like `?role=admin&role=user` by keeping only the last value.

### 6. NoSQL Injection Sanitize
Strips `$` and `.` from input keys. Blocks `{ "$gt": "" }` style attacks.

### 7. Global Rate Limiter
60 requests per minute per IP across all routes.

### 8. Velocity Check
Max 15 requests in any 5-second window per IP. Catches rapid-fire loops even if they stay under the per-minute limit.

### 9. Write Rate Limiter (on write routes)
10 requests per minute per IP on POST/PUT/DELETE endpoints.

### 10. Very Strict Limiter (on sensitive routes)
5 attempts per 15 minutes on `/api/auth/send-otp`. Blocks OTP bombing.

### 11. Suspicious Payload Detector
Blocks requests containing:
- `<script>` tags / XSS patterns
- SQL keywords (`UNION SELECT`, `DROP TABLE`)
- Path traversal (`../`, `/etc/passwd`)
- Code execution patterns (`eval(`, `exec(`)
- Template injection (`${...}`)

### 12. Input Validation (on /api/create-record)
- `name` — required, max 100 chars, HTML-escaped
- `email` — valid email format, normalized
- `message` — optional, max 500 chars, HTML-escaped

---

## Logs

| File | Contents |
|------|----------|
| `logs/app.log` | All requests and events (JSON) |
| `logs/blocked.log` | Blocked/warned requests only |
| Console | Pretty-printed, colourised |

---

## What Each Attack Looks Like

### Spammer looping POST requests
→ First 10 pass, #11+ gets `429` from `writeLimiter`. Handler never runs.

### Rapid fire loop (even with rotating requests)
→ `velocityCheck` blocks after 15 req / 5 seconds regardless of endpoint.

### XSS in payload
```json
{ "name": "<script>alert(1)</script>" }
```
→ `detectSuspiciousPayload` returns `400 SUSPICIOUS_PAYLOAD` before validation runs.

### SQL Injection
```json
{ "name": "'; DROP TABLE users; --" }
```
→ `detectSuspiciousPayload` blocks it. Also HTML-escaped by validator if it slips through.

### Huge payload body
→ express.json `limit: "10kb"` returns `413` immediately.

### Invalid JSON body
→ Express returns `400 INVALID_JSON` from error handler.

### Wrong origin (CORS)
→ `403 CORS: Origin not allowed`.
