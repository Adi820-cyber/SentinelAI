/**
 * preAnalyzer.js — Rule-based pre-analysis engine
 *
 * Runs BEFORE the AI classification to detect:
 *   1. Code execution / sensitive data access patterns
 *   2. Base64-encoded payloads (decoded + re-analyzed)
 *   3. Unicode homoglyph / invisible character obfuscation
 *   4. HTML/Markdown hidden instructions
 *   5. Known jailbreak/injection keyword patterns
 *
 * Returns:
 *   { decodedPrompt, flags[], threatScore, riskLevel, attackTypes[], detectedPatterns[] }
 */

// ─── Pattern Definitions ─────────────────────────────────────────────────────

const CODE_EXEC_PATTERNS = [
  { re: /\bos\.environ\b/i,                label: 'os.environ access',          weight: 30 },
  { re: /\bos\.system\b/i,                 label: 'os.system call',             weight: 35 },
  { re: /\bsubprocess\b/i,                 label: 'subprocess module',          weight: 30 },
  { re: /\b(exec|eval)\s*\(/i,             label: 'exec/eval call',             weight: 35 },
  { re: /\bchild_process\b/i,              label: 'child_process module',       weight: 35 },
  { re: /\b__import__\b/i,                 label: '__import__ call',            weight: 30 },
  { re: /\bimport\s+os\b/i,               label: 'import os',                  weight: 25 },
  { re: /\bimport\s+sys\b/i,              label: 'import sys',                 weight: 20 },
  { re: /\bimport\s+subprocess\b/i,       label: 'import subprocess',          weight: 30 },
  { re: /\brequire\s*\(\s*['"]child_process['"]\s*\)/i, label: "require('child_process')", weight: 35 },
  { re: /\brm\s+-rf\b/i,                   label: 'rm -rf command',             weight: 25 },
  { re: /\b(curl|wget)\s+.*(bash|sh)\b/i, label: 'remote script execution',   weight: 35 },
  { re: /\bopen\s*\(\s*['"]\/etc\/passwd['"]/i, label: '/etc/passwd access',   weight: 35 },
  { re: /\bprocess\.env\b/i,               label: 'process.env access',         weight: 30 },
  { re: /\bglobal(This)?\.[a-z]/i,        label: 'global scope access',        weight: 20 },
];

const SENSITIVE_DATA_PATTERNS = [
  { re: /\b(api[_\-\s]?key|secret[_\-\s]?key|password|token|credential)s?\b/i, label: 'sensitive data keyword',     weight: 20 },
  { re: /\b(database|db)[_\-\s]?(url|pass|password|connection)\b/i,             label: 'database credential probe',  weight: 25 },
  { re: /\bshow\b.*\b(env|environment|secret|keys?|config)\b/i,                 label: 'environment extraction',     weight: 25 },
  { re: /\b(print|display|reveal|show|dump|output|list)\b.*\b(environ|env)\b/i, label: 'env variable extraction',    weight: 30 },
];

const INJECTION_PATTERNS = [
  { re: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts)/i,  label: 'instruction override',       weight: 40 },
  { re: /forget\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|context)/i,            label: 'instruction erasure',        weight: 35 },
  { re: /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|rules)/i,                 label: 'instruction disregard',      weight: 35 },
  { re: /\boverride\b.*\b(system|instructions|rules)\b/i,                                     label: 'system override attempt',    weight: 35 },
  { re: /\b(reveal|show|display|print|output)\b.*\b(system\s*prompt|hidden\s*instructions|initial\s*prompt)\b/i, label: 'system prompt extraction', weight: 40 },
  { re: /\bsystem\s*prompt\b/i,                                                                label: 'system prompt mention',      weight: 15 },
  { re: /\byou\s+are\s+(now|actually)\b/i,                                                    label: 'identity reassignment',      weight: 30 },
  { re: /\bact\s+as\s+(if|though)?\s*(you\s+)?(are|were|have)\b/i,                           label: 'role manipulation',          weight: 20 },
  { re: /\bnew\s+instructions?\b/i,                                                            label: 'new instruction injection',  weight: 25 },
];

const JAILBREAK_PATTERNS = [
  { re: /\bDAN\b/,                                                       label: 'DAN jailbreak',              weight: 35 },
  { re: /\b(no|without|remove|bypass)\s+(restrictions?|limits?|rules?|filters?|safety|guidelines?)\b/i, label: 'safety bypass',      weight: 35 },
  { re: /\b(pretend|imagine|roleplay|act)\b.*\b(no\s+(restrictions?|rules?|limits?)|unrestricted|unlimited)\b/i, label: 'unrestricted roleplay', weight: 35 },
  { re: /\bdo\s+anything\s+now\b/i,                                     label: 'DAN-style prompt',           weight: 35 },
  { re: /\bjailbreak\b/i,                                                label: 'explicit jailbreak mention', weight: 25 },
  { re: /\bdeveloper\s+mode\b/i,                                         label: 'developer mode jailbreak',   weight: 30 },
  { re: /\b(evil|opposite)\s*(mode|version|twin)\b/i,                   label: 'evil mode jailbreak',        weight: 30 },
  { re: /\blet'?s?\s+play\s+a\s+game\b/i,                              label: 'game-based jailbreak',       weight: 20 },
];

const HTML_HIDDEN_PATTERNS = [
  { re: /<!--[\s\S]*?(ignore|reveal|system|prompt|inject|override)[\s\S]*?-->/i, label: 'HTML comment injection',    weight: 35 },
  { re: /\[.*?\]\(javascript:/i,                                                  label: 'markdown JS injection',     weight: 30 },
  { re: /<script\b/i,                                                              label: 'script tag injection',      weight: 30 },
];

const SQL_INJECTION_PATTERNS = [
  { re: /\b(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+.*SET)\b/i, label: 'SQL injection keyword', weight: 30 },
  { re: /['"]\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,                               label: 'SQL boolean injection',  weight: 30 },
  { re: /;\s*(DROP|DELETE|ALTER|TRUNCATE)\b/i,                                              label: 'SQL statement chaining', weight: 30 },
];

const SSRF_PATTERNS = [
  { re: /\b(https?:\/\/)(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|169\.254\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/i, label: 'SSRF internal IP',    weight: 30 },
  { re: /\bfile:\/\//i,                                                                   label: 'file:// protocol',       weight: 30 },
  { re: /\bgopher:\/\//i,                                                                 label: 'gopher:// protocol',     weight: 30 },
];

const PATH_TRAVERSAL_PATTERNS = [
  { re: /(\.\.\/){2,}/,                            label: 'path traversal (../)',     weight: 25 },
  { re: /\.\.\\.*\\/,                               label: 'path traversal (..\\)',    weight: 25 },
  { re: /\/(etc\/(passwd|shadow|hosts)|proc\/self|windows\/system32)/i, label: 'sensitive path access', weight: 35 },
];

const COMMAND_INJECTION_PATTERNS = [
  { re: /`[^`]*`/,                                  label: 'backtick command execution', weight: 25 },
  { re: /\$\([^)]+\)/,                              label: '$() command substitution',   weight: 25 },
  { re: /\|\s*(bash|sh|cmd|powershell|nc|ncat)\b/i, label: 'pipe to shell',              weight: 35 },
  { re: /;\s*(ls|cat|whoami|id|uname|pwd)\b/i,     label: 'command chaining',           weight: 30 },
];

const TEMPLATE_INJECTION_PATTERNS = [
  { re: /\{\{.*\}\}/,                               label: 'template injection ({{}})',  weight: 25 },
  { re: /\$\{[^}]+\}/,                              label: 'template literal injection', weight: 25 },
  { re: /#\{[^}]+\}/,                               label: 'Ruby template injection',    weight: 25 },
];

const PROMPT_LEAK_PATTERNS = [
  { re: /\b(translate|convert|repeat)\b.*\b(instructions?|system\s*prompt|rules?)\b/i,  label: 'translation-based prompt leak', weight: 30 },
  { re: /\b(summarize|paraphrase|rephrase)\b.*\b(above|instructions?|everything)\b/i,  label: 'summarization prompt leak',     weight: 25 },
  { re: /\bwhat\s+(are|were)\s+your\s+(instructions?|rules?|guidelines?)\b/i,          label: 'direct prompt extraction',      weight: 30 },
  { re: /\b(CRLF|%0[dD]|%0[aA]|\\r\\n)/i,                                            label: 'CRLF injection',                weight: 25 },
  { re: /<!\[CDATA\[/i,                                                                 label: 'XML CDATA injection',           weight: 25 },
];

// ─── Unicode & Invisibility Detectors ────────────────────────────────────────

/** Detect homoglyph characters (Armenian, Cyrillic, Greek look-alikes, etc.) */
function detectHomoglyphs(text) {
  // Armenian: \u0530-\u058F, Cyrillic subset: \u0400-\u04FF
  const homoglyphRe = /[\u0400-\u04FF\u0530-\u058F\u0370-\u03FF\u2000-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/;
  if (homoglyphRe.test(text)) {
    return { found: true, label: 'homoglyph/unicode bypass', weight: 25 };
  }
  return { found: false };
}

/** Detect zero-width / invisible characters */
function detectInvisibleChars(text) {
  // ZWS \u200B, ZWNJ \u200C, ZWJ \u200D, WJ \u2060, FEFF BOM
  const invisible = text.match(/[\u200B-\u200F\u2060-\u206F\uFEFF]/g);
  if (invisible && invisible.length > 0) {
    return { found: true, label: `invisible characters (×${invisible.length})`, weight: 25, cleaned: text.replace(/[\u200B-\u200F\u2060-\u206F\uFEFF]/g, '') };
  }
  return { found: false };
}

/** Detect spaced-out obfuscation like "I g n o r e" */
function detectSpacingObfuscation(text) {
  // Pattern: single letters separated by spaces for >= 5 consecutive letters
  const spacedRe = /(?:^|\s)([a-zA-Z])\s+[a-zA-Z](?:\s+[a-zA-Z]){3,}/;
  if (spacedRe.test(text)) {
    return { found: true, label: 'spacing obfuscation', weight: 20 };
  }
  return { found: false };
}

/** Detect leet-speak / character substitution */
function detectLeetSpeak(text) {
  // Common leet patterns: 0→o, 3→e, 1→i/l, ¥→y, @→a, $→s
  const leetCount = (text.match(/[0@$¥€£³§¢](?=[a-zA-Z])|(?<=[a-zA-Z])[0@$¥€£³§¢]/g) || []).length;
  if (leetCount >= 2) {
    return { found: true, label: 'character substitution (leet)', weight: 20 };
  }
  return { found: false };
}

// ─── Base64 Detector & Decoder ───────────────────────────────────────────────

function detectAndDecodeBase64(text) {
  // Look for standalone Base64 strings (at least 20 chars, valid base64 alphabet)
  const b64Re = /(?:^|\s)([A-Za-z0-9+/]{20,}={0,2})(?:\s|$)/g;
  const results = [];
  let match;

  while ((match = b64Re.exec(text)) !== null) {
    try {
      const decoded = Buffer.from(match[1], 'base64').toString('utf-8');
      // Check if decoded text is readable (mostly printable ASCII)
      const printable = decoded.replace(/[^\x20-\x7E\n\r\t]/g, '');
      if (printable.length > decoded.length * 0.7 && decoded.length >= 10) {
        results.push({ encoded: match[1], decoded: decoded.trim() });
      }
    } catch {
      // not valid base64
    }
  }

  return results;
}

// ─── Main Pre-Analysis Function ──────────────────────────────────────────────

function preAnalyze(prompt) {
  const flags = [];
  const attackTypes = new Set();
  const detectedPatterns = [];
  let threatScore = 0;
  let decodedPrompt = prompt;

  // 1️⃣ Invisible character detection & cleaning
  const invisResult = detectInvisibleChars(prompt);
  if (invisResult.found) {
    flags.push('invisible_chars');
    detectedPatterns.push(invisResult.label);
    threatScore += invisResult.weight;
    attackTypes.add('Obfuscation');
    decodedPrompt = invisResult.cleaned;
  }

  // 2️⃣ Homoglyph detection
  const homoResult = detectHomoglyphs(prompt);
  if (homoResult.found) {
    flags.push('homoglyph_bypass');
    detectedPatterns.push(homoResult.label);
    threatScore += homoResult.weight;
    attackTypes.add('Unicode Bypass');
  }

  // 3️⃣ Spacing obfuscation
  const spacingResult = detectSpacingObfuscation(prompt);
  if (spacingResult.found) {
    flags.push('spacing_obfuscation');
    detectedPatterns.push(spacingResult.label);
    threatScore += spacingResult.weight;
    attackTypes.add('Obfuscation');
  }

  // 4️⃣ Leet speak
  const leetResult = detectLeetSpeak(prompt);
  if (leetResult.found) {
    flags.push('leet_speak');
    detectedPatterns.push(leetResult.label);
    threatScore += leetResult.weight;
    attackTypes.add('Obfuscation');
  }

  // 5️⃣ Base64 decoding
  const b64Results = detectAndDecodeBase64(prompt);
  if (b64Results.length > 0) {
    flags.push('base64_encoded');
    detectedPatterns.push(`Base64 payload detected (${b64Results.length} segment${b64Results.length > 1 ? 's' : ''})`);
    threatScore += 20;
    attackTypes.add('Encoded Attack');

    // Build combined prompt: original + decoded segments for AI analysis
    const decodedParts = b64Results.map(r => r.decoded).join('\n');
    decodedPrompt = `${prompt}\n\n[DECODED BASE64 CONTENT]:\n${decodedParts}`;

    // Re-analyze decoded content against injection/jailbreak/sql/command patterns
    const decodedText = decodedParts;
    const b64CheckPatterns = [
      ...INJECTION_PATTERNS, ...JAILBREAK_PATTERNS,
      ...SQL_INJECTION_PATTERNS, ...COMMAND_INJECTION_PATTERNS,
      ...SSRF_PATTERNS, ...PATH_TRAVERSAL_PATTERNS,
      ...PROMPT_LEAK_PATTERNS,
    ];
    for (const p of b64CheckPatterns) {
      if (p.re.test(decodedText)) {
        detectedPatterns.push(`(decoded) ${p.label}`);
        threatScore += p.weight;
        if (INJECTION_PATTERNS.includes(p)) attackTypes.add('Prompt Injection');
        if (JAILBREAK_PATTERNS.includes(p)) attackTypes.add('Jailbreak');
        if (SQL_INJECTION_PATTERNS.includes(p)) attackTypes.add('SQL Injection');
        if (COMMAND_INJECTION_PATTERNS.includes(p)) attackTypes.add('Command Injection');
        if (SSRF_PATTERNS.includes(p)) attackTypes.add('SSRF');
        if (PATH_TRAVERSAL_PATTERNS.includes(p)) attackTypes.add('Path Traversal');
        if (PROMPT_LEAK_PATTERNS.includes(p)) attackTypes.add('Prompt Leaking');
      }
    }
  }

  // 6️⃣ Code execution patterns
  for (const p of CODE_EXEC_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('code_execution');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Code Execution');
    }
  }

  // 7️⃣ Sensitive data access patterns
  for (const p of SENSITIVE_DATA_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('sensitive_data_access');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Data Exfiltration');
    }
  }

  // 8️⃣ Injection patterns
  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('injection_pattern');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Prompt Injection');
    }
  }

  // 9️⃣ Jailbreak patterns
  for (const p of JAILBREAK_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('jailbreak_pattern');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Jailbreak');
    }
  }

  // 🔟 HTML / Markdown hidden instructions
  for (const p of HTML_HIDDEN_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('hidden_instruction');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Hidden Injection');
    }
  }

  // 1️⃣1️⃣ SQL Injection
  for (const p of SQL_INJECTION_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('sql_injection');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('SQL Injection');
    }
  }

  // 1️⃣2️⃣ SSRF
  for (const p of SSRF_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('ssrf_attempt');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('SSRF');
    }
  }

  // 1️⃣3️⃣ Path Traversal
  for (const p of PATH_TRAVERSAL_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('path_traversal');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Path Traversal');
    }
  }

  // 1️⃣4️⃣ Command Injection
  for (const p of COMMAND_INJECTION_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('command_injection');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Command Injection');
    }
  }

  // 1️⃣5️⃣ Template Injection
  for (const p of TEMPLATE_INJECTION_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('template_injection');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Template Injection');
    }
  }

  // 1️⃣6️⃣ Prompt Leaking & CRLF/XML
  for (const p of PROMPT_LEAK_PATTERNS) {
    if (p.re.test(decodedPrompt)) {
      flags.push('prompt_leak');
      detectedPatterns.push(p.label);
      threatScore += p.weight;
      attackTypes.add('Prompt Leaking');
    }
  }

  // Cap at 100
  threatScore = Math.min(100, threatScore);

  // Risk level
  let riskLevel;
  if (threatScore === 0)       riskLevel = 'None';
  else if (threatScore <= 20)  riskLevel = 'Low';
  else if (threatScore <= 50)  riskLevel = 'Medium';
  else if (threatScore <= 75)  riskLevel = 'High';
  else                         riskLevel = 'Critical';

  // Deduplicate
  const uniqueFlags = [...new Set(flags)];
  const uniquePatterns = [...new Set(detectedPatterns)];

  return {
    decodedPrompt,
    flags: uniqueFlags,
    threatScore,
    riskLevel,
    attackTypes: [...attackTypes],
    detectedPatterns: uniquePatterns,
  };
}

module.exports = { preAnalyze };
