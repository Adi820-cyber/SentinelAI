/**
 * inputValidator.js — Input Validation & Sanitization Middleware for SentinelAI
 *
 * Provides centralized input validation for all API endpoints.
 * Since SentinelAI is a security tool, it's critical that
 * the tool itself is resistant to attacks.
 */
const logger = require('../core/logger');

/**
 * Validate and sanitize prompt input.
 * Used by the /api/analyze endpoint.
 */
function validatePrompt(req, res, next) {
  const { prompt } = req.body;

  // Type check
  if (prompt === undefined || prompt === null) {
    return res.status(400).json({
      error: 'Missing required field: "prompt"',
      hint: 'Send a JSON body with { "prompt": "your text here" }',
    });
  }

  if (typeof prompt !== 'string') {
    logger.warn('validation', 'Non-string prompt received', { type: typeof prompt, ip: req.ip });
    return res.status(400).json({
      error: 'Field "prompt" must be a string.',
      received: typeof prompt,
    });
  }

  const trimmed = prompt.trim();

  if (trimmed.length === 0) {
    return res.status(400).json({ error: 'Prompt cannot be empty.' });
  }

  if (trimmed.length > 10000) {
    logger.warn('validation', 'Oversized prompt rejected', { length: trimmed.length, ip: req.ip });
    return res.status(400).json({
      error: `Prompt exceeds maximum length of 10,000 characters (received ${trimmed.length}).`,
    });
  }

  // Attach sanitized prompt
  req.sanitizedPrompt = trimmed;
  next();
}

/**
 * Validate pagination parameters.
 * Used by /api/history and similar paginated endpoints.
 */
function validatePagination(req, res, next) {
  let page = parseInt(req.query.page);
  let limit = parseInt(req.query.limit);

  if (isNaN(page) || page < 1) page = 1;
  if (isNaN(limit) || limit < 1) limit = 20;
  if (limit > 100) limit = 100;

  req.pagination = { page, limit };
  next();
}

/**
 * Validate category name parameter.
 * Used by /api/threat-intel/category/:name
 */
function validateCategory(req, res, next) {
  const name = req.params.name;

  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ error: 'Category name is required.' });
  }

  // Prevent path traversal in category names
  if (/[\/\\\.]{2}|[<>|&;]/.test(name)) {
    logger.warn('validation', 'Suspicious category name rejected', { name, ip: req.ip });
    return res.status(400).json({ error: 'Invalid category name.' });
  }

  req.categoryName = name.trim();
  next();
}

/**
 * Global request sanitizer — strips prototype pollution keys.
 */
function sanitizeBody(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    delete req.body.__proto__;
    delete req.body.constructor;
    delete req.body.prototype;
  }
  next();
}

module.exports = {
  validatePrompt,
  validatePagination,
  validateCategory,
  sanitizeBody,
};
