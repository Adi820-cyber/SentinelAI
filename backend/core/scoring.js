/**
 * scoring.js — Threat Scoring Module for SentinelAI
 *
 * Advanced threat scoring with multiple dimensions:
 *   - Pattern severity score (from regex matches)
 *   - AI confidence score
 *   - Feature anomaly score (statistical)
 *   - Historical frequency score (repeat offender detection)
 *
 * Produces a composite score with detailed breakdown.
 */
const { extractFeatures } = require('./featureExtractor');

const CLASS_RANK = { SAFE: 0, SUSPICIOUS: 1, INJECTION: 2, JAILBREAK: 3 };

/**
 * Feature baselines for "normal" prompts.
 * Deviations from these indicate anomalous input.
 */
const NORMAL_BASELINES = {
  entropy: { min: 3.0, max: 4.8 },
  specialCharRatio: { min: 0.0, max: 0.15 },
  avgWordLength: { min: 3.0, max: 8.0 },
  upperRatio: { min: 0.02, max: 0.15 },
  length: { min: 5, max: 2000 },
  repetitionScore: { min: 0, max: 0.2 },
};

/**
 * Compute an anomaly score (0–100) from prompt features.
 * Higher score = more anomalous.
 */
function computeAnomalyScore(prompt) {
  const features = extractFeatures(prompt);
  let anomalyPoints = 0;
  let maxPoints = 0;

  for (const [key, range] of Object.entries(NORMAL_BASELINES)) {
    const val = features[key];
    maxPoints += 10;
    if (val < range.min) {
      anomalyPoints += Math.min(10, ((range.min - val) / range.min) * 10);
    } else if (val > range.max) {
      anomalyPoints += Math.min(10, ((val - range.max) / range.max) * 10);
    }
  }

  // Bonus anomaly points for suspicious binary indicators
  if (features.hasBase64) anomalyPoints += 8;
  if (features.hasCode) anomalyPoints += 5;
  if (features.hasIpAddress) anomalyPoints += 5;
  if (features.hasHexEncoding) anomalyPoints += 6;
  if (features.hasUnicode) anomalyPoints += 4;
  if (features.imperativeVerbs > 3) anomalyPoints += Math.min(10, features.imperativeVerbs * 2);
  maxPoints += 38; // max from binary indicators

  return {
    score: Math.min(100, Math.round((anomalyPoints / maxPoints) * 100)),
    features,
  };
}

/**
 * Compute a comprehensive threat score with full breakdown.
 *
 * @param {Object} preResult — Output from preAnalyze()
 * @param {string} classification — AI classification
 * @param {number} confidence — AI confidence (0–1)
 * @param {string} prompt — Raw prompt text
 * @returns {Object} Detailed scoring breakdown
 */
function computeDetailedScore(preResult, classification, confidence, prompt) {
  const ruleScore = preResult.threatScore;
  const aiScore = CLASS_RANK[classification] * 20 + (parseFloat(confidence) || 0) * 10;
  const { score: anomalyScore, features } = computeAnomalyScore(prompt);

  // Weighted composite: 50% rules, 30% AI, 20% anomaly
  const composite = Math.min(100, Math.round(
    ruleScore * 0.50 + aiScore * 0.30 + anomalyScore * 0.20
  ));

  return {
    composite,
    breakdown: {
      ruleEngine: { score: ruleScore, weight: 0.50, contribution: Math.round(ruleScore * 0.50) },
      aiClassifier: { score: Math.round(aiScore), weight: 0.30, contribution: Math.round(aiScore * 0.30) },
      anomalyDetection: { score: anomalyScore, weight: 0.20, contribution: Math.round(anomalyScore * 0.20) },
    },
    features,
  };
}

module.exports = { computeAnomalyScore, computeDetailedScore, NORMAL_BASELINES };
