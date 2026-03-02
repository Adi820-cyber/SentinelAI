const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const logger = require('./core/logger');
const { requireAuth, requireRole, AUTH_ENABLED } = require('./middleware/auth');
const { sanitizeBody } = require('./middleware/inputValidator');

const analyzeRoute = require('./routes/analyze');
const historyRoute = require('./routes/history');
const statsRoute = require('./routes/stats');
const threatIntelRoute = require('./routes/threatIntel');
const authRoute = require('./routes/auth');
const alertsRoute = require('./routes/alerts');

const app = express();
const PORT = process.env.PORT || 5000;

// ── Request logging middleware ──
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'debug';
    logger[level]('http', `${req.method} ${req.path} ${res.statusCode}`, {
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs: duration,
      ip: req.ip,
      userAgent: req.headers['user-agent']?.slice(0, 100),
    });
  });
  next();
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// CORS — restrict origins in production
const corsOptions = process.env.NODE_ENV === 'production' && process.env.FRONTEND_URL
  ? { origin: process.env.FRONTEND_URL.split(',').map(s => s.trim()), credentials: true }
  : {};
app.use(cors(corsOptions));
app.use(express.json({ limit: '100kb' }));
app.use(sanitizeBody);

// Rate limiters
const analyzeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many analysis requests, please slow down.' },
});
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests.' },
});
app.use('/api/analyze', analyzeLimiter);
app.use('/api/history', generalLimiter);
app.use('/api/stats', generalLimiter);

// Health check (no auth required)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    authEnabled: AUTH_ENABLED,
  });
});

// Auth routes (no auth required for login/status)
app.use('/api', authRoute);

// Protected routes
app.use('/api', analyzeRoute);
app.use('/api', historyRoute);
app.use('/api', statsRoute);
app.use('/api', threatIntelRoute);
app.use('/api', alertsRoute);

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, _next) => {
  logger.error('server', 'Unhandled error', { error: err.message, stack: err.stack });
  const safeMessage = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;
  res.status(500).json({ error: safeMessage });
});

app.listen(PORT, () => {
  logger.info('server', `SentinelAI v2.0 running on http://localhost:${PORT}`, {
    authEnabled: AUTH_ENABLED,
    nodeEnv: process.env.NODE_ENV || 'development',
  });
});
