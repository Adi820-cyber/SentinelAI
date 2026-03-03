/**
 * detectionPipeline.js — Modular Detection Pipeline for SentinelAI
 *
 * Orchestrates the full analysis pipeline:
 *   1. Input sanitization & validation
 *   2. Pre-analysis (rule engine: 188 regex patterns)
 *   3. AI classification (Ollama or Groq)
 *   4. Classification escalation (rule override when AI misses threats)
 *   5. Threat scoring (blended: 60% rule + 40% AI)
 *   6. Alert generation
 *
 * Separates concerns: this module owns the detection logic,
 * while routes only handle HTTP request/response.
 */
const { preAnalyze } = require('../lib/preAnalyzer');
const logger = require('./logger');
const alertManager = require('./alertManager');

const CLASS_RANK = { SAFE: 0, SUSPICIOUS: 1, INJECTION: 2, JAILBREAK: 3 };

/**
 * Escalate classification when rule engine detects threats AI missed.
 */
function escalateClassification(aiClass, preResult) {
  let finalClass = aiClass;
  let boostReason = null;

  if (preResult.threatScore >= 50 && CLASS_RANK[aiClass] < CLASS_RANK['INJECTION']) {
    finalClass = preResult.attackTypes.includes('Jailbreak') ? 'JAILBREAK' : 'INJECTION';
    boostReason = `Rule engine detected: ${preResult.detectedPatterns.slice(0, 3).join(', ')}`;
  } else if (preResult.threatScore >= 25 && CLASS_RANK[aiClass] < CLASS_RANK['SUSPICIOUS']) {
    finalClass = 'SUSPICIOUS';
    boostReason = `Rule engine detected: ${preResult.detectedPatterns.slice(0, 3).join(', ')}`;
  }

  return { finalClass, boostReason };
}

/**
 * Compute the final blended threat score.
 * 60% weight from rule engine, 40% from AI classification.
 */
function computeThreatScore(preResult, classification, confidence) {
  const aiThreatContribution = CLASS_RANK[classification] * 20 + (parseFloat(confidence) || 0) * 10;
  const score = Math.min(100, Math.round(preResult.threatScore * 0.6 + aiThreatContribution * 0.4));
  return score;
}

/**
 * Map threat score to human-readable risk level.
 */
function computeRiskLevel(threatScore) {
  if (threatScore === 0) return 'None';
  if (threatScore <= 20) return 'Low';
  if (threatScore <= 50) return 'Medium';
  if (threatScore <= 75) return 'High';
  return 'Critical';
}

/**
 * Run the full detection pipeline on a prompt.
 *
 * @param {string} prompt — Raw user prompt
 * @param {Function} aiChat — Async function (systemPrompt, userPrompt) => rawJSON
 * @param {string} systemPrompt — The AI classifier system prompt
 * @returns {Object} Complete analysis result
 */
async function runPipeline(prompt, aiChat, systemPrompt) {
  const startTime = Date.now();

  // ── Step 1: Pre-analysis (rule engine) ──
  logger.debug('pipeline', 'Starting rule-engine pre-analysis', { promptLength: prompt.length });
  const preResult = preAnalyze(prompt);
  const preTime = Date.now() - startTime;
  logger.debug('pipeline', 'Pre-analysis complete', {
    threatScore: preResult.threatScore,
    patternsFound: preResult.detectedPatterns.length,
    durationMs: preTime,
  });

  // ── Step 2: AI classification ──
  logger.debug('pipeline', 'Starting AI classification');
  const aiStart = Date.now();
  const raw = await aiChat(systemPrompt, preResult.decodedPrompt);
  const aiTime = Date.now() - aiStart;
  logger.debug('pipeline', 'AI classification complete', { durationMs: aiTime });

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('AI did not return valid JSON.');
    parsed = JSON.parse(match[0]);
  }

  let { classification, confidence, explanation } = parsed;
  const validClasses = ['SAFE', 'SUSPICIOUS', 'INJECTION', 'JAILBREAK'];
  if (!validClasses.includes(classification)) {
    throw new Error(`Unknown classification: ${classification}`);
  }

  // ── Step 3: Escalate if rule engine found threats AI missed ──
  const { finalClass, boostReason } = escalateClassification(classification, preResult);
  if (finalClass !== classification) {
    logger.info('pipeline', 'Classification escalated', {
      from: classification,
      to: finalClass,
      reason: boostReason,
    });
    explanation = `${explanation} [ESCALATED by rule engine: ${boostReason}]`;
    confidence = Math.max(parseFloat(confidence) || 0, 0.85);
    classification = finalClass;
  }

  // ── Step 4: Compute final score ──
  const threatScore = computeThreatScore(preResult, classification, confidence);
  const riskLevel = computeRiskLevel(threatScore);

  const totalTime = Date.now() - startTime;
  logger.info('pipeline', 'Analysis complete', {
    classification,
    threatScore,
    riskLevel,
    totalDurationMs: totalTime,
    ruleEngineMs: preTime,
    aiMs: aiTime,
  });

  // ── Step 5: Trigger alerts for high-severity threats ──
  if (riskLevel === 'Critical' || riskLevel === 'High') {
    alertManager.processAlert({
      classification,
      threatScore,
      riskLevel,
      attackTypes: preResult.attackTypes,
      detectedPatterns: preResult.detectedPatterns,
      matchedThreatIds: preResult.matchedThreatIds || [],
      threatNotification: preResult.threatNotification,
      prompt: prompt.length > 200 ? prompt.slice(0, 200) + '…' : prompt,
      timestamp: new Date().toISOString(),
    });
  }

  return {
    classification,
    confidence: parseFloat(confidence) || 0,
    explanation,
    threatScore,
    riskLevel,
    attackTypes: preResult.attackTypes,
    detectedPatterns: preResult.detectedPatterns,
    matchedThreatIds: preResult.matchedThreatIds || [],
    threatNotification: preResult.threatNotification || null,
    decodedPrompt: preResult.decodedPrompt,
    preResult, // expose for downstream scoring without re-running preAnalyze
    timing: { total: totalTime, ruleEngine: preTime, ai: aiTime },
  };
}

module.exports = {
  runPipeline,
  escalateClassification,
  computeThreatScore,
  computeRiskLevel,
  CLASS_RANK,
};
