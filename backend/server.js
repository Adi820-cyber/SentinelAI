const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const analyzeRoute = require('./routes/analyze');
const historyRoute = require('./routes/history');
const statsRoute = require('./routes/stats');
const threatIntelRoute = require('./routes/threatIntel');

const app = express();
const PORT = process.env.PORT || 5000;

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

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Routes
app.use('/api', analyzeRoute);
app.use('/api', historyRoute);
app.use('/api', statsRoute);
app.use('/api', threatIntelRoute);

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`SentinelAI backend running on http://localhost:${PORT}`);
});
