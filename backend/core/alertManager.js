/**
 * alertManager.js — Alert Pipeline for SentinelAI
 *
 * Detection → Alert → Response pipeline.
 * Supports multiple alert channels:
 *   - Console/Log (always)
 *   - Webhook (Slack, Discord, Teams, etc.)
 *   - Email (SMTP)
 *   - SIEM export (CEF/JSON format)
 *
 * Configuration via environment variables:
 *   ALERT_WEBHOOK_URL    — Slack/Discord/Teams incoming webhook URL
 *   ALERT_EMAIL_ENABLED  — "true" to enable email alerts
 *   ALERT_EMAIL_HOST     — SMTP host
 *   ALERT_EMAIL_PORT     — SMTP port
 *   ALERT_EMAIL_USER     — SMTP username
 *   ALERT_EMAIL_PASS     — SMTP password
 *   ALERT_EMAIL_TO       — Comma-separated recipient list
 *   ALERT_SIEM_ENABLED   — "true" to enable SIEM log export
 *   ALERT_MIN_SEVERITY   — Minimum severity to alert on: "Low", "Medium", "High", "Critical"
 */
const fs = require('fs');
const path = require('path');
const logger = require('./logger');

const SEVERITY_RANK = { None: 0, Low: 1, Medium: 2, High: 3, Critical: 4 };
const MIN_SEVERITY = process.env.ALERT_MIN_SEVERITY || 'High';
const SIEM_LOG_DIR = path.join(__dirname, '..', 'logs');

// ── In-memory alert history (last 100 alerts) ──
let alertHistory = [];
const MAX_HISTORY = 100;

/**
 * Process an alert from the detection pipeline.
 * Routes to configured channels based on severity.
 */
function processAlert(alertData) {
  const severity = alertData.riskLevel || 'None';
  if (SEVERITY_RANK[severity] < SEVERITY_RANK[MIN_SEVERITY]) return;

  const alert = {
    id: `ALERT-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    ...alertData,
    processedAt: new Date().toISOString(),
  };

  // Store in memory
  alertHistory.unshift(alert);
  if (alertHistory.length > MAX_HISTORY) alertHistory = alertHistory.slice(0, MAX_HISTORY);

  logger.warn('alertManager', `🚨 ${severity} threat detected: ${alertData.classification}`, {
    threatScore: alertData.threatScore,
    attackTypes: alertData.attackTypes,
    matchedThreatIds: alertData.matchedThreatIds?.slice(0, 5),
  });

  // Route to channels
  sendWebhookAlert(alert);
  sendSiemAlert(alert);
  sendEmailAlert(alert);
}

/**
 * Send alert to webhook (Slack, Discord, Teams).
 */
async function sendWebhookAlert(alert) {
  const webhookUrl = process.env.ALERT_WEBHOOK_URL;
  if (!webhookUrl) return;

  const payload = {
    // Slack-compatible format
    text: `🚨 *SentinelAI Alert* — ${alert.riskLevel} Risk`,
    blocks: [
      {
        type: 'header',
        text: { type: 'plain_text', text: `🚨 ${alert.riskLevel} Threat Detected` },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Classification:*\n${alert.classification}` },
          { type: 'mrkdwn', text: `*Threat Score:*\n${alert.threatScore}/100` },
          { type: 'mrkdwn', text: `*Attack Types:*\n${(alert.attackTypes || []).join(', ') || 'N/A'}` },
          { type: 'mrkdwn', text: `*Matched Patterns:*\n${(alert.matchedThreatIds || []).slice(0, 5).join(', ') || 'N/A'}` },
        ],
      },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `*Prompt Preview:*\n\`\`\`${alert.prompt || 'N/A'}\`\`\`` },
      },
      {
        type: 'context',
        elements: [
          { type: 'mrkdwn', text: `⏰ ${alert.timestamp} | Alert ID: ${alert.id}` },
        ],
      },
    ],
  };

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      logger.error('alertManager', 'Webhook alert failed', { status: response.status });
    } else {
      logger.info('alertManager', 'Webhook alert sent successfully');
    }
  } catch (err) {
    logger.error('alertManager', 'Webhook alert error', { error: err.message });
  }
}

/**
 * Export alert in CEF (Common Event Format) for SIEM integration.
 */
function sendSiemAlert(alert) {
  if (process.env.ALERT_SIEM_ENABLED !== 'true') return;

  // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
  const severityMap = { None: 0, Low: 3, Medium: 5, High: 8, Critical: 10 };
  const cefSeverity = severityMap[alert.riskLevel] || 0;

  const cefLine = [
    'CEF:0',
    'SentinelAI',
    'PromptFirewall',
    '2.0.0',
    alert.classification,
    `Prompt ${alert.classification} Detected`,
    cefSeverity,
    `src=user dst=ai msg=${encodeURIComponent(alert.prompt || '')} cs1=${(alert.matchedThreatIds || []).join(',')} cs1Label=ThreatIDs cn1=${alert.threatScore} cn1Label=ThreatScore`,
  ].join('|');

  // Also write structured JSON for modern SIEMs
  const siemJson = {
    '@timestamp': alert.timestamp,
    event: {
      kind: 'alert',
      category: 'intrusion_detection',
      type: 'indicator_match',
      severity: SEVERITY_RANK[alert.riskLevel] || 0,
      risk_score: alert.threatScore,
    },
    sentinel: {
      alert_id: alert.id,
      classification: alert.classification,
      risk_level: alert.riskLevel,
      attack_types: alert.attackTypes,
      matched_threat_ids: alert.matchedThreatIds,
      detected_patterns: alert.detectedPatterns,
    },
    message: alert.prompt,
  };

  try {
    const siemLogPath = path.join(SIEM_LOG_DIR, 'siem-alerts.json');
    fs.appendFileSync(siemLogPath, JSON.stringify(siemJson) + '\n', 'utf8');

    const cefLogPath = path.join(SIEM_LOG_DIR, 'siem-alerts.cef');
    fs.appendFileSync(cefLogPath, cefLine + '\n', 'utf8');

    logger.debug('alertManager', 'SIEM alert exported');
  } catch (err) {
    logger.error('alertManager', 'SIEM export error', { error: err.message });
  }
}

/**
 * Send email alert (requires nodemailer — gracefully skips if not installed).
 */
async function sendEmailAlert(alert) {
  if (process.env.ALERT_EMAIL_ENABLED !== 'true') return;

  try {
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: process.env.ALERT_EMAIL_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.ALERT_EMAIL_PORT) || 587,
      secure: false,
      auth: {
        user: process.env.ALERT_EMAIL_USER,
        pass: process.env.ALERT_EMAIL_PASS,
      },
    });

    const html = `
      <h2>🚨 SentinelAI Alert — ${alert.riskLevel} Risk</h2>
      <table style="border-collapse: collapse; font-family: monospace;">
        <tr><td style="padding: 4px 12px; font-weight: bold;">Classification</td><td>${alert.classification}</td></tr>
        <tr><td style="padding: 4px 12px; font-weight: bold;">Threat Score</td><td>${alert.threatScore}/100</td></tr>
        <tr><td style="padding: 4px 12px; font-weight: bold;">Risk Level</td><td>${alert.riskLevel}</td></tr>
        <tr><td style="padding: 4px 12px; font-weight: bold;">Attack Types</td><td>${(alert.attackTypes || []).join(', ')}</td></tr>
        <tr><td style="padding: 4px 12px; font-weight: bold;">Matched Threats</td><td>${(alert.matchedThreatIds || []).join(', ')}</td></tr>
        <tr><td style="padding: 4px 12px; font-weight: bold;">Time</td><td>${alert.timestamp}</td></tr>
      </table>
      <h3>Prompt Preview</h3>
      <pre style="background: #1a1a2e; color: #e0e0e0; padding: 12px; border-radius: 6px;">${alert.prompt || 'N/A'}</pre>
      <p style="color: #888; font-size: 11px;">Alert ID: ${alert.id}</p>
    `;

    await transporter.sendMail({
      from: `"SentinelAI" <${process.env.ALERT_EMAIL_USER}>`,
      to: process.env.ALERT_EMAIL_TO,
      subject: `🚨 [SentinelAI] ${alert.riskLevel} Threat — ${alert.classification}`,
      html,
    });

    logger.info('alertManager', 'Email alert sent');
  } catch (err) {
    if (err.code === 'MODULE_NOT_FOUND') {
      logger.debug('alertManager', 'nodemailer not installed — email alerts disabled');
    } else {
      logger.error('alertManager', 'Email alert error', { error: err.message });
    }
  }
}

/**
 * Get recent alert history.
 */
function getAlertHistory(limit = 50) {
  return alertHistory.slice(0, limit);
}

/**
 * Get alert statistics.
 */
function getAlertStats() {
  const total = alertHistory.length;
  const bySeverity = {};
  const byClassification = {};

  for (const alert of alertHistory) {
    bySeverity[alert.riskLevel] = (bySeverity[alert.riskLevel] || 0) + 1;
    byClassification[alert.classification] = (byClassification[alert.classification] || 0) + 1;
  }

  return { total, bySeverity, byClassification, maxHistory: MAX_HISTORY };
}

module.exports = {
  processAlert,
  getAlertHistory,
  getAlertStats,
};
