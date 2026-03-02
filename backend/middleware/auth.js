/**
 * auth.js — Authentication & Role-Based Access Control for SentinelAI
 *
 * Supports two auth modes:
 *   1. API Key authentication (for programmatic access)
 *   2. Session-based authentication (for dashboard users)
 *
 * Roles:
 *   - admin    — Full access: manage users, configure settings, view all data
 *   - analyst  — Read access to analysis, history, stats, threat intel
 *   - viewer   — Read-only access to dashboard and stats
 *
 * Configuration:
 *   AUTH_ENABLED       — "true" to enable authentication (default: disabled for dev)
 *   AUTH_API_KEYS      — Comma-separated API keys in format "key:role" (e.g., "sk-abc123:admin,sk-def456:analyst")
 *   AUTH_ADMIN_USER    — Dashboard admin username (default: admin)
 *   AUTH_ADMIN_PASS    — Dashboard admin password (required when AUTH_ENABLED=true)
 *   AUTH_SESSION_SECRET — Secret for session tokens
 */
const crypto = require('crypto');
const logger = require('../core/logger');

const AUTH_ENABLED = process.env.AUTH_ENABLED === 'true';
const SESSION_SECRET = process.env.AUTH_SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

// ── Parse API keys from env ──
const API_KEYS = new Map();
if (process.env.AUTH_API_KEYS) {
  process.env.AUTH_API_KEYS.split(',').forEach(entry => {
    const [key, role] = entry.trim().split(':');
    if (key && role) API_KEYS.set(key, role);
  });
}

// ── Parse dashboard users ──
const USERS = new Map();
if (process.env.AUTH_ADMIN_USER && process.env.AUTH_ADMIN_PASS) {
  USERS.set(process.env.AUTH_ADMIN_USER, {
    password: process.env.AUTH_ADMIN_PASS,
    role: 'admin',
  });
}
// Support additional users: AUTH_USERS="user1:pass1:analyst,user2:pass2:viewer"
if (process.env.AUTH_USERS) {
  process.env.AUTH_USERS.split(',').forEach(entry => {
    const [username, password, role] = entry.trim().split(':');
    if (username && password && role) {
      USERS.set(username, { password, role });
    }
  });
}

// ── Active sessions (in-memory) ──
const sessions = new Map();

// ── Role permissions ──
const PERMISSIONS = {
  admin: ['analyze', 'history', 'stats', 'threat-intel', 'alerts', 'settings', 'users'],
  analyst: ['analyze', 'history', 'stats', 'threat-intel', 'alerts'],
  viewer: ['history', 'stats', 'threat-intel'],
};

/**
 * Generate a secure session token.
 */
function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

/**
 * Authenticate a user and create session.
 * Returns { token, role, expiresAt } or null.
 */
function login(username, password) {
  const user = USERS.get(username);
  if (!user) return null;

  // Constant-time comparison to prevent timing attacks
  const expected = Buffer.from(user.password, 'utf8');
  const received = Buffer.from(password, 'utf8');
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
    return null;
  }

  const token = generateToken();
  const expiresAt = new Date(Date.now() + SESSION_DURATION_MS).toISOString();

  sessions.set(token, {
    username,
    role: user.role,
    expiresAt: Date.now() + SESSION_DURATION_MS,
    createdAt: new Date().toISOString(),
  });

  logger.info('auth', `User logged in: ${username} (${user.role})`);
  return { token, role: user.role, username, expiresAt };
}

/**
 * Invalidate a session.
 */
function logout(token) {
  const session = sessions.get(token);
  if (session) {
    logger.info('auth', `User logged out: ${session.username}`);
    sessions.delete(token);
    return true;
  }
  return false;
}

/**
 * Validate a session token.
 * Returns session data or null.
 */
function validateSession(token) {
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return session;
}

/**
 * Express middleware: Require authentication.
 * Checks for API key in x-api-key header or session token in Authorization header.
 * Attaches req.user = { username, role } on success.
 *
 * When AUTH_ENABLED is false, all requests pass through as admin.
 */
function requireAuth(req, res, next) {
  if (!AUTH_ENABLED) {
    req.user = { username: 'anonymous', role: 'admin' };
    return next();
  }

  // Check API key first
  const apiKey = req.headers['x-api-key'];
  if (apiKey && API_KEYS.has(apiKey)) {
    req.user = { username: 'api-key', role: API_KEYS.get(apiKey) };
    return next();
  }

  // Check session token
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const session = validateSession(token);
    if (session) {
      req.user = { username: session.username, role: session.role };
      return next();
    }
  }

  logger.warn('auth', 'Unauthorized access attempt', {
    ip: req.ip,
    path: req.path,
    method: req.method,
  });

  return res.status(401).json({ error: 'Authentication required. Provide x-api-key header or Bearer token.' });
}

/**
 * Express middleware factory: Require specific permission.
 * Use after requireAuth: app.get('/api/alerts', requireAuth, requireRole('alerts'), handler)
 */
function requireRole(permission) {
  return (req, res, next) => {
    if (!AUTH_ENABLED) return next();

    const userPerms = PERMISSIONS[req.user?.role] || [];
    if (!userPerms.includes(permission)) {
      logger.warn('auth', 'Insufficient permissions', {
        user: req.user?.username,
        role: req.user?.role,
        required: permission,
      });
      return res.status(403).json({
        error: 'Insufficient permissions.',
        required: permission,
        yourRole: req.user?.role,
      });
    }
    next();
  };
}

/**
 * Periodically clean expired sessions. Runs every 15 minutes.
 */
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [token, session] of sessions) {
    if (now > session.expiresAt) {
      sessions.delete(token);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    logger.debug('auth', `Cleaned ${cleaned} expired sessions`);
  }
}, 15 * 60 * 1000);

module.exports = {
  requireAuth,
  requireRole,
  login,
  logout,
  AUTH_ENABLED,
  PERMISSIONS,
};
