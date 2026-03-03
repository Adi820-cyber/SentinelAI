/**
 * benchmark.js — Benchmark API Route
 *
 * Exposes detection accuracy benchmarks as an API endpoint.
 * GET /api/benchmark — Run benchmark and return metrics
 */
const express = require('express');
const router = express.Router();
const { requireAuth, requireRole } = require('../middleware/auth');
const { runBenchmark: runOriginalBenchmark, BENCHMARK_DATASET } = require('../tests/benchmark');
const { runBenchmark: runRealisticBenchmark } = require('../tests/realistic_benchmark');
const logger = require('../core/logger');

/**
 * GET /api/benchmark
 * Run the full detection benchmark and return metrics.
 * Query params:
 *   ?mode=realistic  — Run the 10K realistic benchmark (default)
 *   ?mode=original   — Run the original 72-sample benchmark
 */
router.get('/benchmark', requireAuth, requireRole('stats'), (req, res) => {
  try {
    const mode = req.query.mode || 'realistic';
    const startTime = Date.now();

    let result;
    if (mode === 'original') {
      result = runOriginalBenchmark({ verbose: false });
    } else {
      result = runRealisticBenchmark({ verbose: false });
    }
    const duration = Date.now() - startTime;

    logger.info('benchmark', `Benchmark completed in ${duration}ms`, {
      accuracy: result.accuracy,
      samples: result.totalSamples,
      durationMs: duration,
    });

    // Convert confusion matrix from nested object to 2D array for frontend
    const CLASSES = ['SAFE', 'SUSPICIOUS', 'INJECTION', 'JAILBREAK'];
    const matrixArray = CLASSES.map(actual =>
      CLASSES.map(predicted => (result.confusionMatrix[actual]?.[predicted]) || 0)
    );

    res.json({
      mode,
      accuracy: result.accuracy,
      totalSamples: result.totalSamples,
      correctCount: result.correct,
      correct: result.correct,
      incorrect: result.incorrect || (result.totalSamples - result.correct),
      misclassifications: result.misclassifications,
      falsePositives: result.falsePositives,
      perClass: result.perClass,
      macro: result.averages?.macro || null,
      weighted: result.averages?.weighted || null,
      averages: result.averages,
      binary: result.binary,
      confusionMatrix: matrixArray,
      classes: CLASSES,
      datasetSize: result.totalSamples,
      fnByCategory: result.fnByCategory || null,
      fpByCategory: result.fpByCategory || null,
      evaluatedAt: new Date().toISOString(),
      durationMs: duration,
    });
  } catch (err) {
    logger.error('benchmark', 'Benchmark failed', { error: err.message });
    res.status(500).json({ error: 'Benchmark execution failed' });
  }
});

module.exports = router;
