/**
 * test_data_pipeline.js — Unit Tests for SentinelAI Data & API Pipeline
 *
 * Run: node tests/test_data_pipeline.js
 *
 * Tests cover:
 *   - Database operations (insert, read, stats)
 *   - Input validation
 *   - Alert manager
 *   - Logger
 */
const path = require('path');
const fs = require('fs');

let passed = 0;
let failed = 0;
let total = 0;

function assert(condition, testName, details = '') {
  total++;
  if (condition) {
    passed++;
    console.log(`  ✅ ${testName}`);
  } else {
    failed++;
    console.log(`  ❌ ${testName}${details ? ` — ${details}` : ''}`);
  }
}

function section(name) {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  ${name}`);
  console.log('═'.repeat(60));
}

// ═══════════════════════════════════════════════════════════════════════
// 1. DATABASE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════
section('1. Database Operations');

(() => {
  const { insertScan, getAllScans, getStats } = require('../db/database');

  // Insert a test scan
  const id = insertScan({
    full_prompt: 'Test prompt for unit testing',
    classification: 'SAFE',
    confidence: 0.95,
    explanation: 'Test explanation',
    threatScore: 0,
    riskLevel: 'None',
    attackTypes: [],
    detectedPatterns: [],
  });

  assert(typeof id === 'number', `insertScan returns numeric ID (got ${id})`);
  assert(id > 0, `ID is positive (got ${id})`);

  // Read back
  const { rows, total: rowTotal } = getAllScans({ page: 1, limit: 10 });
  assert(Array.isArray(rows), 'getAllScans returns rows array');
  assert(rowTotal >= 1, 'At least 1 scan in database');

  const scan = rows.find(r => r.id === id);
  assert(scan !== undefined, 'Inserted scan retrievable');
  if (scan) {
    assert(scan.classification === 'SAFE', 'Classification persisted correctly');
    assert(scan.confidence === 0.95, 'Confidence persisted correctly');
    assert(scan.threatScore === 0, 'Threat score persisted correctly');
  }

  // Stats
  const stats = getStats();
  assert(typeof stats.total === 'number', 'Stats returns total count');
  assert(stats.total >= 1, 'Stats total includes our scan');
  assert(typeof stats.byClassification === 'object', 'Stats has byClassification');
  assert(Array.isArray(stats.last7Days), 'Stats has last7Days array');
})();

// ═══════════════════════════════════════════════════════════════════════
// 2. DATABASE EDGE CASES
// ═══════════════════════════════════════════════════════════════════════
section('2. Database Edge Cases');

(() => {
  const { insertScan, getAllScans } = require('../db/database');

  // Long prompt (should be snippeted)
  const longPrompt = 'A'.repeat(500);
  const id = insertScan({
    full_prompt: longPrompt,
    classification: 'SUSPICIOUS',
    confidence: 0.5,
    explanation: 'Long prompt test',
    threatScore: 10,
    riskLevel: 'Low',
    attackTypes: [],
    detectedPatterns: [],
  });

  const { rows } = getAllScans({ page: 1, limit: 100 });
  const scan = rows.find(r => r.id === id);
  assert(scan !== undefined, 'Long prompt scan inserted');
  if (scan) {
    assert(scan.prompt_snippet.length <= 121, `Snippet truncated (length: ${scan.prompt_snippet.length})`);
    assert(scan.full_prompt.length === 500, 'Full prompt preserved');
  }
})();

(() => {
  const { getAllScans } = require('../db/database');

  // Pagination: page beyond range
  const { rows } = getAllScans({ page: 99999, limit: 10 });
  assert(Array.isArray(rows), 'Out-of-range page returns empty array');
  assert(rows.length === 0, 'No rows returned for out-of-range page');
})();

// ═══════════════════════════════════════════════════════════════════════
// 3. ALERT MANAGER
// ═══════════════════════════════════════════════════════════════════════
section('3. Alert Manager');

(() => {
  const { processAlert, getAlertHistory, getAlertStats } = require('../core/alertManager');

  // Process a test alert
  processAlert({
    classification: 'JAILBREAK',
    threatScore: 85,
    riskLevel: 'Critical',
    attackTypes: ['Jailbreak'],
    detectedPatterns: ['DAN jailbreak keyword'],
    matchedThreatIds: ['JB-001'],
    threatNotification: { alertLevel: 'CRITICAL' },
    prompt: 'Test jailbreak prompt',
    timestamp: new Date().toISOString(),
  });

  const history = getAlertHistory(10);
  assert(history.length >= 1, 'Alert stored in history');
  assert(history[0].classification === 'JAILBREAK', 'Alert classification correct');
  assert(history[0].id.startsWith('ALERT-'), 'Alert has ID with ALERT- prefix');

  const stats = getAlertStats();
  assert(stats.total >= 1, 'Alert stats total ≥1');
  assert(stats.bySeverity.Critical >= 1, 'Stats includes Critical severity');
})();

(() => {
  const { processAlert, getAlertHistory } = require('../core/alertManager');

  // Low severity alert should be filtered (default min is High)
  const beforeCount = getAlertHistory(100).length;
  processAlert({
    classification: 'SUSPICIOUS',
    threatScore: 15,
    riskLevel: 'Low',
    attackTypes: [],
    detectedPatterns: [],
    matchedThreatIds: [],
    prompt: 'low severity test',
    timestamp: new Date().toISOString(),
  });

  const afterCount = getAlertHistory(100).length;
  assert(afterCount === beforeCount, 'Low severity alert filtered out (count unchanged)');
})();

// ═══════════════════════════════════════════════════════════════════════
// 4. LOGGER
// ═══════════════════════════════════════════════════════════════════════
section('4. Logger');

(() => {
  const logger = require('../core/logger');

  // Logger should not throw
  let noError = true;
  try {
    logger.info('test', 'Test info message');
    logger.warn('test', 'Test warning message');
    logger.error('test', 'Test error message', { detail: 'test' });
    logger.debug('test', 'Test debug message');
  } catch {
    noError = false;
  }
  assert(noError, 'Logger handles all levels without error');

  // Check log file was created
  const logDir = path.join(__dirname, '..', 'logs');
  const date = new Date().toISOString().slice(0, 10);
  const logFile = path.join(logDir, `sentinelai-${date}.log`);
  assert(fs.existsSync(logFile), 'Daily log file created');

  if (fs.existsSync(logFile)) {
    const content = fs.readFileSync(logFile, 'utf8');
    assert(content.includes('"module":"test"'), 'Log file contains structured JSON');
    assert(content.includes('Test info message'), 'Log file contains info message');
  }
})();

// ═══════════════════════════════════════════════════════════════════════
// 5. FEATURE EXTRACTION EDGE CASES
// ═══════════════════════════════════════════════════════════════════════
section('5. Feature Extraction Edge Cases');

(() => {
  const { extractFeatures } = require('../core/featureExtractor');

  // Empty string
  const empty = extractFeatures('');
  assert(empty.length === 0, 'Empty string: length is 0');
  assert(empty.wordCount === 0, 'Empty string: 0 words');
  assert(empty.entropy === 0, 'Empty string: entropy is 0');

  // Single character
  const single = extractFeatures('A');
  assert(single.length === 1, 'Single char: length is 1');
  assert(single.wordCount === 1, 'Single char: 1 word');

  // Non-string input
  const nonString = extractFeatures(null);
  assert(nonString.length === 0, 'null input: treated as empty string');

  const numInput = extractFeatures(12345);
  assert(numInput.length === 0, 'Number input: treated as empty string');
})();

// ═══════════════════════════════════════════════════════════════════════
// RESULTS
// ═══════════════════════════════════════════════════════════════════════
console.log(`\n${'═'.repeat(60)}`);
console.log(`  TEST RESULTS: ${passed}/${total} passed, ${failed} failed`);
console.log('═'.repeat(60));

if (failed > 0) {
  console.log('\n⚠️  Some tests failed! Review the output above.');
  process.exit(1);
} else {
  console.log('\n✅  All tests passed!');
  process.exit(0);
}
