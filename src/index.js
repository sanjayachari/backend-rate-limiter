const express = require("express");
const morgan = require("morgan");
const logger = require("./logger");
const {
  globalLimiter,
  writeLimiter,
  strictLimiter,
  helmetMiddleware,
  corsMiddleware,
  hppMiddleware,
  sanitizeMiddleware,
  detectSuspiciousPayload,
  requestId,
  velocityCheck,
  handleValidation,
  createRecordValidation,
} = require("./security");

const app = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// GLOBAL MIDDLEWARE STACK
// Order matters — security first, parsing after
// ─────────────────────────────────────────────

// 1. Attach request ID (tracing)
app.use(requestId);

// 2. Security headers (helmet)
app.use(helmetMiddleware);

// 3. CORS
app.use(corsMiddleware);

// 4. HTTP access logs via morgan → winston
app.use(
  morgan("combined", {
    stream: {
      write: (msg) => logger.info(msg.trim(), { type: "access" }),
    },
  })
);

// 5. Body parsing — 10kb limit to prevent large payload attacks
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// 6. HTTP Parameter Pollution prevention
app.use(hppMiddleware);

// 7. NoSQL injection sanitize
app.use(sanitizeMiddleware);

// 8. Global rate limiter
app.use(globalLimiter);

// 9. Velocity check (rapid fire detection)
app.use(velocityCheck);

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

// Health check — no rate limit
app.get("/health", (req, res) => {
  logger.info("Health check", { ip: req.ip, requestId: req.id });
  res.json({
    status: "ok",
    requestId: req.id,
    timestamp: new Date().toISOString(),
  });
});

// ── CREATE RECORD ──────────────────────────────
// writeLimiter:          max 10 / min per IP
// detectSuspiciousPayload: blocks XSS, SQLi, traversal
// createRecordValidation:  validates + sanitizes fields
// handleValidation:        returns 422 if invalid
app.post(
  "/api/create-record",
  writeLimiter,
  detectSuspiciousPayload,
  createRecordValidation,
  handleValidation,
  (req, res) => {
    const payload = req.body;

    logger.info("Record created", {
      requestId: req.id,
      ip: req.ip,
      payload,
      userAgent: req.get("user-agent"),
    });

    res.status(201).json({
      success: true,
      message: "Record received and logged (no DB — echo mode)",
      requestId: req.id,
      receivedPayload: payload,
      timestamp: new Date().toISOString(),
    });
  }
);

// ── UPDATE RECORD ──────────────────────────────
app.put(
  "/api/update-record/:id",
  writeLimiter,
  detectSuspiciousPayload,
  (req, res) => {
    const { id } = req.params;
    const payload = req.body;

    logger.info("Record update request", {
      requestId: req.id,
      ip: req.ip,
      recordId: id,
      payload,
    });

    res.json({
      success: true,
      message: "Update received and logged",
      requestId: req.id,
      recordId: id,
      receivedPayload: payload,
      timestamp: new Date().toISOString(),
    });
  }
);

// ── DELETE RECORD ──────────────────────────────
app.delete(
  "/api/delete-record/:id",
  writeLimiter,
  (req, res) => {
    const { id } = req.params;

    logger.info("Record delete request", {
      requestId: req.id,
      ip: req.ip,
      recordId: id,
    });

    res.json({
      success: true,
      message: "Delete received and logged",
      requestId: req.id,
      recordId: id,
      timestamp: new Date().toISOString(),
    });
  }
);

// ── GET RECORDS ────────────────────────────────
app.get("/api/records", (req, res) => {
  const { page = 1, limit = 10, search } = req.query;

  logger.info("Get records request", {
    requestId: req.id,
    ip: req.ip,
    query: req.query,
  });

  res.json({
    success: true,
    message: "GET request received and logged",
    requestId: req.id,
    query: { page, limit, search },
    data: [],   // No DB — returns empty array
    timestamp: new Date().toISOString(),
  });
});

// ── SENSITIVE ENDPOINT DEMO ────────────────────
// Simulates OTP / login — very strict rate limit
app.post(
  "/api/auth/send-otp",
  strictLimiter,    // 5 attempts per 15 min
  detectSuspiciousPayload,
  (req, res) => {
    const { phone, email } = req.body;

    logger.info("OTP request", {
      requestId: req.id,
      ip: req.ip,
      phone: phone ? "provided" : "not provided",
      email: email ? "provided" : "not provided",
    });

    res.json({
      success: true,
      message: "OTP request received (echo mode — not sent)",
      requestId: req.id,
      timestamp: new Date().toISOString(),
    });
  }
);

// ── ECHO ANY PAYLOAD ───────────────────────────
// Wildcard — logs and echoes whatever comes in
app.all(
  "/api/echo",
  writeLimiter,
  detectSuspiciousPayload,
  (req, res) => {
    const echo = {
      method: req.method,
      path: req.path,
      headers: req.headers,
      query: req.query,
      body: req.body,
      ip: req.ip,
      requestId: req.id,
      timestamp: new Date().toISOString(),
    };

    logger.info("Echo endpoint hit", echo);
    res.json({ success: true, echo });
  }
);

// ─────────────────────────────────────────────
// ERROR HANDLERS
// ─────────────────────────────────────────────

// 404
app.use((req, res) => {
  logger.warn("404 Not Found", {
    ip: req.ip,
    method: req.method,
    path: req.path,
    requestId: req.id,
  });
  res.status(404).json({ error: "Route not found", code: "NOT_FOUND" });
});

// Global error handler
app.use((err, req, res, next) => {
  // CORS error
  if (err.message === "Not allowed by CORS") {
    return res.status(403).json({ error: "CORS: Origin not allowed", code: "CORS_ERROR" });
  }

  // Payload too large
  if (err.type === "entity.too.large") {
    logger.warn("Payload too large", { ip: req.ip, path: req.path });
    return res.status(413).json({ error: "Payload too large (max 10kb)", code: "PAYLOAD_TOO_LARGE" });
  }

  // Invalid JSON
  if (err.type === "entity.parse.failed") {
    logger.warn("Invalid JSON body", { ip: req.ip, path: req.path });
    return res.status(400).json({ error: "Invalid JSON body", code: "INVALID_JSON" });
  }

  logger.error("Unhandled error", {
    error: err.message,
    stack: err.stack,
    requestId: req.id,
    ip: req.ip,
  });

  res.status(500).json({ error: "Internal server error", code: "SERVER_ERROR" });
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  logger.info(`Secure backend started`, { port: PORT, env: process.env.NODE_ENV || "development" });
  console.log(`\n  🛡  Secure backend running on http://localhost:${PORT}`);
  console.log(`  📋  Logs → ./logs/app.log  |  ./logs/blocked.log\n`);
});

module.exports = app;
