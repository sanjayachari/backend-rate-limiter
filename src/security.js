const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const hpp = require("hpp");
const mongoSanitize = require("express-mongo-sanitize");
const { body, validationResult } = require("express-validator");
const logger = require("./logger");

// ─────────────────────────────────────────────
// 1. RATE LIMITERS
//    Different windows for different endpoints
// ─────────────────────────────────────────────

// General limiter — all routes
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 60,                   // 60 req / min per IP
  standardHeaders: true,     // Return RateLimit-* headers
  legacyHeaders: false,
  message: { error: "Too many requests. Slow down.", code: "RATE_LIMIT_GLOBAL" },
  handler: (req, res, next, options) => {
    logger.warn("Global rate limit hit", {
      ip: req.ip,
      path: req.path,
      method: req.method,
      userAgent: req.get("user-agent"),
    });
    res.status(429).json(options.message);
  },
});

// Strict limiter — write endpoints (create/update/delete)
const writeLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 10,                   // only 10 writes / min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Write limit exceeded. Max 10 creates per minute.", code: "RATE_LIMIT_WRITE" },
  handler: (req, res, next, options) => {
    logger.warn("Write rate limit hit — possible spam", {
      ip: req.ip,
      path: req.path,
      method: req.method,
      body: req.body,
      userAgent: req.get("user-agent"),
    });
    res.status(429).json(options.message);
  },
});

// Very strict limiter — sensitive endpoints (auth/otp)
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                    // only 5 attempts per 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again in 15 minutes.", code: "RATE_LIMIT_STRICT" },
  handler: (req, res, next, options) => {
    logger.warn("Strict rate limit hit — brute force attempt?", {
      ip: req.ip,
      path: req.path,
      method: req.method,
      userAgent: req.get("user-agent"),
    });
    res.status(429).json(options.message);
  },
});

// ─────────────────────────────────────────────
// 2. HELMET — HTTP security headers
//    Blocks: clickjacking, MIME sniffing,
//    XSS via headers, info leaks
// ─────────────────────────────────────────────
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  referrerPolicy: { policy: "no-referrer" },
  hsts: {
    maxAge: 31536000,        // 1 year
    includeSubDomains: true,
    preload: true,
  },
  frameguard: { action: "deny" },
  noSniff: true,
  xssFilter: true,
  hidePoweredBy: true,       // Remove X-Powered-By: Express
});

// ─────────────────────────────────────────────
// 3. CORS — only allowed origins
// ─────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "http://localhost:3000")
  .split(",")
  .map((o) => o.trim());

const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (curl, Postman in dev)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn("CORS blocked request", { origin });
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Request-ID"],
  credentials: true,
  maxAge: 86400,             // Cache preflight for 24h
});

// ─────────────────────────────────────────────
// 4. PAYLOAD SIZE LIMIT
//    Prevents large body attacks / DoS
// ─────────────────────────────────────────────
// Applied in index.js: express.json({ limit: "10kb" })

// ─────────────────────────────────────────────
// 5. HPP — HTTP Parameter Pollution prevention
//    e.g. ?role=admin&role=user tricks
// ─────────────────────────────────────────────
const hppMiddleware = hpp();

// ─────────────────────────────────────────────
// 6. MONGO / NoSQL INJECTION SANITIZE
//    Strips $ and . from input keys
//    Safe to use even without MongoDB
// ─────────────────────────────────────────────
const sanitizeMiddleware = mongoSanitize({
  onSanitize: ({ req, key }) => {
    logger.warn("NoSQL injection attempt sanitized", {
      ip: req.ip,
      key,
      path: req.path,
    });
  },
});

// ─────────────────────────────────────────────
// 7. SUSPICIOUS PATTERN DETECTOR
//    Blocks common script injection & traversal
// ─────────────────────────────────────────────
const suspiciousPatterns = [
  /<script[\s\S]*?>/i,           // XSS script tags
  /javascript:/i,                // JS protocol
  /on\w+\s*=/i,                  // Event handlers like onerror=
  /union\s+select/i,             // SQL injection
  /drop\s+table/i,               // SQL drop
  /\.\.\//,                      // Path traversal ../
  /\/etc\/passwd/i,              // Linux file read
  /exec\s*\(/i,                  // Code execution
  /eval\s*\(/i,                  // Eval injection
  /\$\{.*\}/,                    // Template literal injection
];

const detectSuspiciousPayload = (req, res, next) => {
  const bodyStr = JSON.stringify(req.body || {});
  const queryStr = JSON.stringify(req.query || {});
  const combined = bodyStr + queryStr;

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(combined)) {
      logger.warn("Suspicious payload detected", {
        ip: req.ip,
        path: req.path,
        method: req.method,
        pattern: pattern.toString(),
        body: req.body,
        query: req.query,
        userAgent: req.get("user-agent"),
      });
      return res.status(400).json({
        error: "Invalid payload detected.",
        code: "SUSPICIOUS_PAYLOAD",
      });
    }
  }
  next();
};

// ─────────────────────────────────────────────
// 8. REQUEST ID MIDDLEWARE
//    Attach unique ID to every request for tracing
// ─────────────────────────────────────────────
const { v4: uuidv4 } = require("uuid");

const requestId = (req, res, next) => {
  req.id = req.headers["x-request-id"] || uuidv4();
  res.setHeader("X-Request-ID", req.id);
  next();
};

// ─────────────────────────────────────────────
// 9. REQUEST VELOCITY CHECK (per user-agent + IP)
//    Catches bots rotating IPs slightly
// ─────────────────────────────────────────────
const velocityMap = new Map();
const VELOCITY_WINDOW = 5000;  // 5 seconds
const VELOCITY_MAX    = 15;    // max 15 hits in 5s from same IP

const velocityCheck = (req, res, next) => {
  const key = req.ip;
  const now = Date.now();

  if (!velocityMap.has(key)) {
    velocityMap.set(key, { count: 1, windowStart: now });
    return next();
  }

  const entry = velocityMap.get(key);

  if (now - entry.windowStart > VELOCITY_WINDOW) {
    // New window
    entry.count = 1;
    entry.windowStart = now;
    return next();
  }

  entry.count++;
  if (entry.count > VELOCITY_MAX) {
    logger.warn("Velocity check triggered — rapid fire requests", {
      ip: req.ip,
      count: entry.count,
      windowMs: now - entry.windowStart,
      path: req.path,
    });
    return res.status(429).json({
      error: "Requests too fast. Slow down.",
      code: "VELOCITY_EXCEEDED",
    });
  }

  next();
};

// Clean up velocity map every 60s to prevent memory leak
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of velocityMap.entries()) {
    if (now - val.windowStart > VELOCITY_WINDOW * 10) {
      velocityMap.delete(key);
    }
  }
}, 60000);

// ─────────────────────────────────────────────
// VALIDATION HELPERS (reusable in routes)
// ─────────────────────────────────────────────
const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn("Validation failed", {
      ip: req.ip,
      path: req.path,
      errors: errors.array(),
      body: req.body,
    });
    return res.status(422).json({
      error: "Validation failed",
      details: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }
  next();
};

// Common validation rules for the /create-record route
const createRecordValidation = [
  body("name")
    .trim()
    .notEmpty().withMessage("name is required")
    .isLength({ max: 100 }).withMessage("name max 100 chars")
    .escape(),
  body("email")
    .optional()
    .isEmail().withMessage("Invalid email format")
    .normalizeEmail(),
  body("message")
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage("message max 500 chars")
    .escape(),
];

module.exports = {
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
};
