/**
 * logger.js — Structured Logging System for SentinelAI
 *
 * Levels: ERROR, WARN, INFO, DEBUG
 * Outputs: Console (always) + File (rotated daily)
 * Format: JSON structured logs for SIEM integration
 */
const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'logs');
const LOG_LEVELS = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3 };
const CURRENT_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL || 'INFO'];

// Ensure log directory exists
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

function getLogFileName() {
  const date = new Date().toISOString().slice(0, 10);
  return path.join(LOG_DIR, `sentinelai-${date}.log`);
}

function formatLog(level, module, message, meta = {}) {
  return JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    module,
    message,
    ...meta,
    pid: process.pid,
  });
}

function writeToFile(logLine) {
  try {
    fs.appendFileSync(getLogFileName(), logLine + '\n', 'utf8');
  } catch {
    // Silent fail — don't crash app for logging failures
  }
}

function log(level, module, message, meta = {}) {
  if (LOG_LEVELS[level] > CURRENT_LEVEL) return;

  const logLine = formatLog(level, module, message, meta);

  // Console output with color
  const colors = { ERROR: '\x1b[31m', WARN: '\x1b[33m', INFO: '\x1b[36m', DEBUG: '\x1b[90m' };
  const reset = '\x1b[0m';
  const color = colors[level] || '';
  console.log(`${color}[${level}]${reset} [${module}] ${message}`, Object.keys(meta).length > 0 ? meta : '');

  // File output (always structured JSON)
  writeToFile(logLine);
}

/** Clean up log files older than N days */
function cleanOldLogs(retentionDays = 30) {
  try {
    const files = fs.readdirSync(LOG_DIR);
    const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
    for (const file of files) {
      if (!file.startsWith('sentinelai-') || !file.endsWith('.log')) continue;
      const filePath = path.join(LOG_DIR, file);
      const stat = fs.statSync(filePath);
      if (stat.mtimeMs < cutoff) {
        fs.unlinkSync(filePath);
        log('INFO', 'logger', `Cleaned old log file: ${file}`);
      }
    }
  } catch {
    // Silent
  }
}

// Clean old logs on startup
cleanOldLogs();

module.exports = {
  error: (module, message, meta) => log('ERROR', module, message, meta),
  warn:  (module, message, meta) => log('WARN', module, message, meta),
  info:  (module, message, meta) => log('INFO', module, message, meta),
  debug: (module, message, meta) => log('DEBUG', module, message, meta),
  cleanOldLogs,
};
