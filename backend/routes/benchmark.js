/**
 * benchmark.js — Benchmark API Route
 *
 * Exposes detection accuracy benchmarks as an API endpoint.
 * GET /api/benchmark — Run benchmark and return metrics
 */
const express = require('express');
const router = express.Router();
const { requireAuth, requireRole } = require('../middleware/auth');
const { runBenchmark, BENCHMARK_DATASET } = require('../tests/benchmark');
const logger = require('../core/logger');

/**
 * GET /api/benchmark
 * Run the full detection benchmark and return metrics.
 */
router.get('/benchmark', requireAuth, requireRole('stats'), (req, res) => {
  try {
    const startTime = Date.now();
    const result = runBenchmark({ verbose: false });
    const duration = Date.now() - startTime;

    logger.info('benchmark', `Benchmark completed in ${duration}ms`, {
      accuracy: result.accuracy,
      samples: result.totalSamples,
      durationMs: duration,
    });

    res.json({
      accuracy: result.accuracy,
      totalSamples: result.totalSamples,
      correct: result.correct,
      misclassifications: result.misclassifications,
      falsePositives: result.falsePositives,
      perClass: result.perClass,
      averages: result.averages,
      binary: result.binary,
      confusionMatrix: result.confusionMatrix,
      datasetSize: BENCHMARK_DATASET.length,
      evaluatedAt: new Date().toISOString(),
      durationMs: duration,
    });
  } catch (err) {
    logger.error('benchmark', 'Benchmark failed', { error: err.message });
    res.status(500).json({ error: 'Benchmark execution failed' });
  }
});

module.exports = router;
