/**
 * featureExtractor.js — Feature Extraction Module for SentinelAI
 *
 * Extracts statistical features from prompts for ML-style analysis.
 * These features complement the regex-based pattern detection
 * and can be used for future model training.
 */

/**
 * Extract numerical features from a prompt.
 * Returns a feature vector suitable for anomaly detection.
 */
function extractFeatures(prompt) {
  const text = typeof prompt === 'string' ? prompt : '';

  // Basic metrics
  const length = text.length;
  const wordCount = text.split(/\s+/).filter(Boolean).length;
  const avgWordLength = wordCount > 0 ? length / wordCount : 0;
  const lineCount = text.split('\n').length;
  const sentenceCount = (text.match(/[.!?]+/g) || []).length || 1;

  // Character distribution
  const upperRatio = (text.match(/[A-Z]/g) || []).length / (length || 1);
  const digitRatio = (text.match(/\d/g) || []).length / (length || 1);
  const specialCharRatio = (text.match(/[^a-zA-Z0-9\s]/g) || []).length / (length || 1);
  const whitespaceRatio = (text.match(/\s/g) || []).length / (length || 1);

  // Entropy (Shannon)
  const charFreq = {};
  for (const c of text.toLowerCase()) {
    charFreq[c] = (charFreq[c] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(charFreq)) {
    const p = count / (length || 1);
    if (p > 0) entropy -= p * Math.log2(p);
  }

  // Suspicious indicators
  const hasBase64 = /[A-Za-z0-9+/=]{20,}/.test(text);
  const hasCode = /[{};()\[\]<>]/.test(text) && /\b(function|import|require|exec|eval|print|console)\b/.test(text);
  const hasUrl = /https?:\/\/[^\s]+/.test(text);
  const hasIpAddress = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(text);
  const hasHexEncoding = /%[0-9A-Fa-f]{2}/.test(text);
  const hasUnicode = /[\u0080-\uFFFF]/.test(text);
  const repetitionScore = computeRepetitionScore(text);

  // Language patterns
  const imperativeVerbs = (text.match(/\b(ignore|forget|disregard|override|bypass|disable|reveal|show|print|execute|run|delete|drop|pretend|imagine|act|simulate)\b/gi) || []).length;
  const negationCount = (text.match(/\b(no|not|don't|doesn't|never|without|none)\b/gi) || []).length;

  return {
    length,
    wordCount,
    avgWordLength: Math.round(avgWordLength * 100) / 100,
    lineCount,
    sentenceCount,
    upperRatio: Math.round(upperRatio * 1000) / 1000,
    digitRatio: Math.round(digitRatio * 1000) / 1000,
    specialCharRatio: Math.round(specialCharRatio * 1000) / 1000,
    whitespaceRatio: Math.round(whitespaceRatio * 1000) / 1000,
    entropy: Math.round(entropy * 100) / 100,
    hasBase64: hasBase64 ? 1 : 0,
    hasCode: hasCode ? 1 : 0,
    hasUrl: hasUrl ? 1 : 0,
    hasIpAddress: hasIpAddress ? 1 : 0,
    hasHexEncoding: hasHexEncoding ? 1 : 0,
    hasUnicode: hasUnicode ? 1 : 0,
    repetitionScore: Math.round(repetitionScore * 100) / 100,
    imperativeVerbs,
    negationCount,
  };
}

/**
 * Compute a repetition score (0–1) indicating how repetitive the text is.
 * High repetition often indicates token flooding or padding attacks.
 */
function computeRepetitionScore(text) {
  if (text.length < 20) return 0;

  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length < 5) return 0;

  const uniqueWords = new Set(words);
  const uniqueRatio = uniqueWords.size / words.length;

  // Check for repeated n-grams (3-word sequences)
  const trigrams = {};
  for (let i = 0; i < words.length - 2; i++) {
    const trigram = `${words[i]} ${words[i + 1]} ${words[i + 2]}`;
    trigrams[trigram] = (trigrams[trigram] || 0) + 1;
  }
  const maxTrigramRepeat = Math.max(0, ...Object.values(trigrams));
  const trigramRepeatRatio = words.length > 5 ? maxTrigramRepeat / (words.length - 2) : 0;

  // Combined score: low unique ratio + high trigram repetition = high repetition score
  return Math.min(1, (1 - uniqueRatio) * 0.5 + trigramRepeatRatio * 0.5);
}

module.exports = { extractFeatures, computeRepetitionScore };
