const winston = require("winston");
const path = require("path");

const { combine, timestamp, printf, colorize, json } = winston.format;

// Console format — human readable
const consoleFormat = printf(({ level, message, timestamp, ...meta }) => {
  const extra = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : "";
  return `[${timestamp}] ${level}: ${message} ${extra}`;
});

const logger = winston.createLogger({
  level: "info",
  transports: [
    // Pretty console output
    new winston.transports.Console({
      format: combine(
        colorize(),
        timestamp({ format: "HH:mm:ss" }),
        consoleFormat
      ),
    }),
    // JSON file — all logs
    new winston.transports.File({
      filename: path.join(__dirname, "../logs/app.log"),
      format: combine(timestamp(), json()),
      maxsize: 5 * 1024 * 1024, // 5MB
      maxFiles: 3,
    }),
    // Separate file for blocked / suspicious requests
    new winston.transports.File({
      filename: path.join(__dirname, "../logs/blocked.log"),
      level: "warn",
      format: combine(timestamp(), json()),
    }),
  ],
});

module.exports = logger;
