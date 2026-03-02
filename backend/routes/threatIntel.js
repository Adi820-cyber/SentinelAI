const express = require('express');
const router = express.Router();
const { getThreatIntelligence } = require('../lib/preAnalyzer');

/**
 * GET /api/threat-intel
 *
 * Returns the full SentinelAI threat intelligence database:
 *   - Total pattern count
 *   - Severity breakdown (critical / high / medium / low)
 *   - Per-category stats and pattern IDs
 *   - Full pattern list with descriptions
 *
 * This endpoint can be consumed by other AI systems to learn
 * about currently known malicious prompt patterns.
 */
router.get('/threat-intel', (req, res) => {
  const intel = getThreatIntelligence();
  res.json({
    ...intel,
    _meta: {
      service: 'SentinelAI',
      purpose: 'AI Prompt Firewall Threat Intelligence Feed',
      usage: 'Use this data to configure detection rules, train classifiers, or display threat dashboards.',
      endpoints: {
        analyze: 'POST /api/analyze — Submit a prompt for real-time analysis',
        'threat-intel': 'GET /api/threat-intel — This endpoint (threat database)',
        'threat-intel-summary': 'GET /api/threat-intel/summary — Compact summary',
      },
    },
  });
});

/**
 * GET /api/threat-intel/summary
 *
 * Returns a compact summary of the threat database — suitable for
 * dashboard widgets, status pages, and quick health checks.
 */
router.get('/threat-intel/summary', (req, res) => {
  const intel = getThreatIntelligence();
  res.json({
    version: intel.version,
    lastUpdated: intel.lastUpdated,
    totalPatterns: intel.totalPatterns,
    severityCounts: intel.severityCounts,
    categories: intel.categories.map(c => ({
      name: c.name,
      count: c.count,
      critical: c.critical,
    })),
  });
});

/**
 * GET /api/threat-intel/category/:name
 *
 * Returns all patterns for a specific attack category.
 */
router.get('/threat-intel/category/:name', (req, res) => {
  const intel = getThreatIntelligence();
  const categoryName = req.params.name;

  const category = intel.categories.find(
    c => c.name.toLowerCase() === categoryName.toLowerCase()
  );

  if (!category) {
    return res.status(404).json({
      error: `Category "${categoryName}" not found.`,
      availableCategories: intel.categories.map(c => c.name),
    });
  }

  const patterns = intel.patterns.filter(
    p => p.category.toLowerCase() === categoryName.toLowerCase()
  );

  res.json({
    category: category.name,
    totalPatterns: category.count,
    severityBreakdown: {
      critical: category.critical,
      high: category.high,
      medium: category.medium,
      low: category.low,
    },
    patterns,
  });
});

module.exports = router;
