/**
 * alerts.js route — Alert Management Endpoints for SentinelAI
 */
const express = require('express');
const router = express.Router();
const { requireAuth, requireRole } = require('../middleware/auth');
const { getAlertHistory, getAlertStats } = require('../core/alertManager');

/**
 * GET /api/alerts
 * Returns recent alert history.
 * Query: ?limit=50
 */
router.get('/alerts', requireAuth, requireRole('alerts'), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const alerts = getAlertHistory(limit);
  res.json({
    alerts,
    count: alerts.length,
    limit,
  });
});

/**
 * GET /api/alerts/stats
 * Returns alert statistics.
 */
router.get('/alerts/stats', requireAuth, requireRole('alerts'), (req, res) => {
  res.json(getAlertStats());
});

/**
 * GET /api/alerts/config
 * Returns current alerting configuration (non-sensitive).
 */
router.get('/alerts/config', requireAuth, requireRole('settings'), (req, res) => {
  res.json({
    webhookConfigured: !!process.env.ALERT_WEBHOOK_URL,
    emailEnabled: process.env.ALERT_EMAIL_ENABLED === 'true',
    siemEnabled: process.env.ALERT_SIEM_ENABLED === 'true',
    minSeverity: process.env.ALERT_MIN_SEVERITY || 'High',
    channels: [
      { name: 'Console/Log', status: 'active', description: 'Always active — logs to console and file' },
      { name: 'Webhook', status: process.env.ALERT_WEBHOOK_URL ? 'configured' : 'not configured', description: 'Slack, Discord, or Teams webhook' },
      { name: 'Email', status: process.env.ALERT_EMAIL_ENABLED === 'true' ? 'configured' : 'not configured', description: 'SMTP email notifications' },
      { name: 'SIEM', status: process.env.ALERT_SIEM_ENABLED === 'true' ? 'configured' : 'not configured', description: 'CEF + JSON SIEM export' },
    ],
  });
});

module.exports = router;
