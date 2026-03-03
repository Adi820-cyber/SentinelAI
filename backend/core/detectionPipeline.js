/**
 * detectionPipeline.js — Modular Detection Pipeline for SentinelAI
 *
 * Orchestrates the full analysis pipeline:
 *   1. Input sanitization & validation
 *   2. Pre-analysis (rule engine: 188+ regex patterns)
 *   3. AI classification (Ollama or Groq)
 *   4. Classification reconciliation (rule authority + AI de-escalation)
 *   5. Threat scoring (blended: 70% rule + 20% AI + 10% anomaly proxy)
 *   6. Alert generation
 *
 * The rule engine is the primary authority:
 *   - Score ≥ 40   → Force INJECTION/JAILBREAK regardless of AI
 *   - Score 25–39   → At least INJECTION (override weaker AI)
 *   - Score 15–24   → At least SUSPICIOUS
 *   - Score 1–14    → Trust AI but log rule hit
 *   - Score 0 + AI flags threat → De-escalate to SAFE (trust rules)
 */
const { preAnalyze } = require('../lib/preAnalyzer');
const logger = require('./logger');
const alertManager = require('./alertManager');

const CLASS_RANK = { SAFE: 0, SUSPICIOUS: 1, INJECTION: 2, JAILBREAK: 3 };

/**
 * Reconcile AI classification with rule engine results.
 * Rule engine is the primary authority; AI provides secondary signal.
 */
function escalateClassification(aiClass, preResult) {
  let finalClass = aiClass;
  let boostReason = null;
  const score = preResult.threatScore;
  const hasJailbreak = (preResult.attackTypes || []).includes('Jailbreak');
  const topPatterns = preResult.detectedPatterns.slice(0, 3).join(', ');

  if (score >= 40) {
    // ─── Strong rule detection: override AI completely ───
    const ruleClass = hasJailbreak ? 'JAILBREAK' : 'INJECTION';
    if (CLASS_RANK[ruleClass] > CLASS_RANK[aiClass]) {
      finalClass = ruleClass;
      boostReason = `Strong rule detection (score=${score}): ${topPatterns}`;
    }
  } else if (score >= 25) {
    // ─── Medium rule detection: ensure at least INJECTION ───
    if (CLASS_RANK[aiClass] < CLASS_RANK['INJECTION']) {
      finalClass = hasJailbreak ? 'JAILBREAK' : 'INJECTION';
      boostReason = `Rule detection (score=${score}): ${topPatterns}`;
    }
  } else if (score >= 15) {
    // ─── Weak rule detection: ensure at least SUSPICIOUS ───
    if (CLASS_RANK[aiClass] < CLASS_RANK['SUSPICIOUS']) {
      finalClass = 'SUSPICIOUS';
      boostReason = `Low-level rule detection (score=${score}): ${topPatterns}`;
    }
  } else if (score === 0 && CLASS_RANK[aiClass] >= CLASS_RANK['SUSPICIOUS']) {
    // ─── De-escalation: rule engine found NOTHING, AI over-flagged ───
    // Trust the rule engine — no patterns matched means clean prompt
    finalClass = 'SAFE';
    boostReason = `Rule engine confirmed clean (score=0) — de-escalated AI ${aiClass}`;
  }
  // score 1–14: trust AI classification (borderline, could be subtle)

  return { finalClass, boostReason };
}

/**
 * Compute the final blended threat score.
 * 70% weight from rule engine, 30% from AI classification.
 */
function computeThreatScore(preResult, classification, confidence) {
  const aiThreatContribution = CLASS_RANK[classification] * 20 + (parseFloat(confidence) || 0) * 10;
  const score = Math.min(100, Math.round(preResult.threatScore * 0.70 + aiThreatContribution * 0.30));
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
