/**
 * auth.js route — Authentication endpoints for SentinelAI
 */
const express = require('express');
const router = express.Router();
const { login, logout, requireAuth, AUTH_ENABLED, PERMISSIONS } = require('../middleware/auth');
const logger = require('../core/logger');

/**
 * POST /api/auth/login
 * Body: { username, password }
 * Returns: { token, role, username, expiresAt }
 */
router.post('/auth/login', (req, res) => {
  if (!AUTH_ENABLED) {
    return res.json({
      token: 'dev-mode-no-auth-required',
      role: 'admin',
      username: 'anonymous',
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      message: 'Authentication is disabled. All requests have admin access.',
    });
  }

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const result = login(username, password);
  if (!result) {
    logger.warn('auth-route', 'Failed login attempt', { username, ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  res.json(result);
});

/**
 * POST /api/auth/logout
 * Headers: Authorization: Bearer <token>
 */
router.post('/auth/logout', (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    logout(token);
  }
  res.json({ message: 'Logged out.' });
});

/**
 * GET /api/auth/me
 * Returns current user info (requires auth)
 */
router.get('/auth/me', requireAuth, (req, res) => {
  res.json({
    username: req.user.username,
    role: req.user.role,
    permissions: PERMISSIONS[req.user.role] || [],
    authEnabled: AUTH_ENABLED,
  });
});

/**
 * GET /api/auth/status
 * Returns auth system status (no auth required)
 */
router.get('/auth/status', (req, res) => {
  res.json({
    authEnabled: AUTH_ENABLED,
    roles: Object.keys(PERMISSIONS),
    message: AUTH_ENABLED
      ? 'Authentication is active. Use POST /api/auth/login to get a token.'
      : 'Authentication is disabled. All endpoints are open.',
  });
});

module.exports = router;
