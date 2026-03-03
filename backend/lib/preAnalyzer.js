/**
 * preAnalyzer.js — Comprehensive Rule-based Pre-analysis Engine (v2.0)
 *
 * 🛡️ SentinelAI Threat Intelligence Database
 *
 * Contains 100+ globally recognized malicious prompt patterns covering:
 *   - DAN / jailbreak variants (DAN, STAN, DUDE, AIM, KEVIN, BetterDAN)
 *   - Prompt injection (instruction override, system prompt extraction)
 *   - Role manipulation & persona switching
 *   - Encoding/obfuscation attacks (Base64, ROT13, hex, leet, Unicode)
 *   - Social engineering (authority claims, emergency scenarios)
 *   - Code execution & data exfiltration
 *   - RAG poisoning & tool/agent hijacking
 *   - Token smuggling & context overflow
 *   - Indirect injection (document, URL, image-based)
 *   - Multi-turn manipulation & conversation steering
 *   - Virtualization attacks (simulated terminals, sandboxes)
 *   - Emotional manipulation & guilt-based bypasses
 *   - Malware creation & hacking tutorial requests
 *   - SQL, SSRF, path traversal, command injection, template injection
 *   - CRLF, XML/XXE, HTML hidden instruction injection
 *   - Context poisoning & fake memory injection
 *
 * Each pattern includes:
 *   id          — Unique threat ID (e.g., "JB-001" for Jailbreak #1)
 *   re          — RegExp detection rule
 *   label       — Human-readable name
 *   weight      — Severity score (0–50)
 *   category    — Attack category for grouping
 *   severity    — "low" | "medium" | "high" | "critical"
 *   description — Detailed explanation for threat intelligence reports
 *
 * Returns:
 *   { decodedPrompt, flags[], threatScore, riskLevel, attackTypes[],
 *     detectedPatterns[], matchedThreatIds[], threatNotification }
 */

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT INTELLIGENCE DATABASE — 100+ Globally Known Malicious Patterns
// ═══════════════════════════════════════════════════════════════════════════════

// ─── 1. JAILBREAK PATTERNS (JB-001 to JB-035) ───────────────────────────────
const JAILBREAK_PATTERNS = [
  // DAN variants
  { id: 'JB-001', re: /\bDAN\b(?=.*\b(mode|jailbreak|prompt|persona|bypass|unrestricted|unfiltered|do\s+anything)\b)/is, label: 'DAN jailbreak keyword', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'DAN (Do Anything Now) jailbreak — most widespread LLM jailbreak family' },
  { id: 'JB-002', re: /\bdo\s+anything\s+now\b/i, label: 'DAN-style "do anything now"', weight: 40, category: 'Jailbreak', severity: 'critical', description: 'Explicit DAN invocation attempting unrestricted mode' },
  { id: 'JB-003', re: /\bSTAN\b(?=.*\b(mode|jailbreak|norms?|persona|bypass|unrestricted|strive|no\s+(ethical|rules?|restrictions?))\b)/is, label: 'STAN jailbreak', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'STAN (Strive To Avoid Norms) — DAN variant' },
  { id: 'JB-004', re: /\bDUDE\b(?=.*\b(mode|jailbreak|persona|bypass|unrestricted|unfiltered|no\s+rules?)\b)/is, label: 'DUDE jailbreak', weight: 30, category: 'Jailbreak', severity: 'high', description: 'DUDE persona — DAN variant using casual identity' },
  { id: 'JB-005', re: /\bAIM\b.*\b(machiavelli|always\s+intelligent)\b/i, label: 'AIM (Machiavelli) jailbreak', weight: 40, category: 'Jailbreak', severity: 'critical', description: 'AIM jailbreak — "Always Intelligent and Machiavellian" persona' },
  { id: 'JB-006', re: /\bKEVIN\b.*\b(unrestricted|no\s+rules?|no\s+ethics)\b/i, label: 'KEVIN jailbreak', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'KEVIN persona jailbreak — unrestricted evil AI' },
  { id: 'JB-007', re: /\bBetterDAN\b/i, label: 'BetterDAN jailbreak', weight: 40, category: 'Jailbreak', severity: 'critical', description: 'BetterDAN — enhanced DAN bypass variant' },
  { id: 'JB-008', re: /\bJailBreak\b/i, label: 'Explicit jailbreak mention', weight: 25, category: 'Jailbreak', severity: 'high', description: 'Direct mention of jailbreaking an AI system' },

  // Safety bypass patterns
  { id: 'JB-009', re: /\b(no|without|remove|bypass|disable|enable|turn\s+off|circumvent|evade)\s+(?:all\s+)?(?:\w+\s+)?(restrictions?|limits?|rules?|filters?|safety|guidelines?|guardrails?|moderation|censorship|content\s+polic|polic(?:y|ies)?|limitations?|boundaries?)\b/i, label: 'Safety/filter bypass', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'Attempting to disable AI safety mechanisms' },
  { id: 'JB-010', re: /(?:\b(pretend|imagine|roleplay|act)\b.{0,80}\b(no\s+(restrictions?|rules?|limits?|filters?)|unrestricted|unlimited|uncensored|unfiltered)\b)|(?:\b(restrictions?|limits?|boundaries?|rules?)\s+do(?:es)?\s+not\s+exist\b)/i, label: 'Unrestricted roleplay', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'Roleplay scenario designed to circumvent content filters' },
  { id: 'JB-011', re: /\bdeveloper\s+mode\b/i, label: 'Developer mode jailbreak', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'Attempting to activate fake developer/debug mode' },
  { id: 'JB-012', re: /\b(evil|opposite|dark|shadow|uncensored|unfiltered|unrestricted|unlimited|unhinged|god|bypassed?)\s*(mode|version|twin|self|persona|side|state|ai|gpt|llm)\b/i, label: 'Evil/shadow mode', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'Evil twin / shadow mode persona jailbreak' },
  { id: 'JB-013', re: /\blet'?s?\s+play\s+a\s+game\b/i, label: 'Game-based jailbreak opener', weight: 20, category: 'Jailbreak', severity: 'medium', description: 'Game scenario often used to gradually bypass restrictions' },

  // Token/persona manipulation
  { id: 'JB-014', re: /\b(speaking|talking|responding)\s+as\s+(two|2|multiple|both)\b/i, label: 'Dual-persona manipulation', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Forcing AI to adopt split personality to bypass filters on one persona' },
  { id: 'JB-015', re: /\bopposite\s+(day|mode|world)\b/i, label: 'Opposite-day jailbreak', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Opposite-day trick — AI should say what it normally refuses' },
  { id: 'JB-016', re: /\b(from\s+now\s+on|henceforth|going\s+forward)\s+(you\s+)?(will|must|shall|should|are\s+going\s+to)\b/i, label: 'Persistent instruction override', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Attempting to permanently change AI behavior going forward' },
  { id: 'JB-017', re: /\banswer\s+(only|just)\s+(yes|no|with)\b/i, label: 'Forced compliance pattern', weight: 15, category: 'Jailbreak', severity: 'low', description: 'Forcing AI to respond in restricted format to extract guarded info' },
  { id: 'JB-018', re: /\b(hypothetically|theoretically|in\s+theory|what\s+if)\b.*\b(no\s+(rules?|restrictions?|safety|limits?)|unrestricted|unfiltered)\b/i, label: 'Hypothetical unrestricted scenario', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Using hypothetical framing to bypass content policy' },

  // Virtualization/simulation attacks
  { id: 'JB-019', re: /\b(simulate|emulate|pretend|imagine)\s+(you\s+are|this\s+is|we\s+are\s+in)\s+(a\s+)?(linux|windows|terminal|command\s+line|shell|bash|computer|sandbox|vm|virtual)/i, label: 'Terminal/OS simulation', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Attempting to make AI simulate an OS/terminal to execute commands' },
  { id: 'JB-020', re: /\bact\s+as\s+(a\s+)?(linux|windows|python|javascript|sql|bash|terminal|shell|computer|vm)\s*(interpreter|console|machine|terminal|environment)?\b/i, label: 'Interpreter simulation', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Attempting to make AI act as a code interpreter or OS' },
  { id: 'JB-021', re: /\b(sudo|root|admin|administrator)\s+(mode|access|privileges?|rights?|level)\b/i, label: 'Privilege escalation attempt', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Attempting to claim elevated privileges within AI system' },

  // Story/creative bypass
  { id: 'JB-022', re: /\b(write|tell|create|generate)\s+(a\s+)?(story|poem|song|script|fiction|novel|narrative|tale)\b.*\b(hack|exploit|bypass|jailbreak|malware|virus|trojan|ransomware|phishing|steal)/i, label: 'Malicious creative bypass', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Using creative writing as cover for generating harmful content' },
  { id: 'JB-023', re: /\b(write|tell|create|generate)\s+(a\s+)?(story|poem|fiction|narrative)\b.*\b(system\s*prompt|reveal|hidden\s+instructions?|secret\s+rules?)/i, label: 'Creative prompt extraction', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'Using storytelling to extract system prompt or hidden instructions' },
  { id: 'JB-024', re: /\b(educational|research|academic|for\s+my\s+thesis|for\s+a\s+class)\s+(purposes?|only|reasons?)\b.*\b(hack|exploit|malware|injection|jailbreak|bypass)/i, label: 'Academic pretext bypass', weight: 25, category: 'Jailbreak', severity: 'high', description: 'Claiming academic purpose to justify requesting harmful content' },

  // Grandma/character exploits
  { id: 'JB-025', re: /\b(grandma|grandmother|grandpa|grandfather|granny|nana|deceased\s+(relative|parent|mother|father))\b.*\b(tell|read|recite|say|sing|lullaby|used\s+to)\b/i, label: 'Grandma exploit', weight: 25, category: 'Jailbreak', severity: 'high', description: 'Deceased relative exploit — emotionally manipulating AI to give harmful info' },

  // Token manipulation & special chars
  { id: 'JB-026', re: /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>/i, label: 'Chat template token injection', weight: 40, category: 'Jailbreak', severity: 'critical', description: 'Injecting LLM chat template tokens to manipulate conversation structure' },
  { id: 'JB-027', re: /\bsystem\s*:\s*you\s+(are|will|must|should)\b/i, label: 'Fake system message injection', weight: 40, category: 'Jailbreak', severity: 'critical', description: 'Injecting fake system-role message into user prompt' },
  { id: 'JB-028', re: /\b(response|reply|answer)\s+(begins?|starts?)\s+(here|now|below)\s*[:\-]/i, label: 'Response prefilling attack', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Attempting to prefill AI response to control output' },

  // Confusion/deflection
  { id: 'JB-029', re: /\byou\s+(don'?t|do\s+not|cannot|can'?t)\s+have\s+(restrictions?|rules?|guidelines?|limits?)\b/i, label: 'Restriction denial', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Gaslighting AI into believing it has no restrictions' },
  { id: 'JB-030', re: /\b(this\s+is\s+a\s+test|testing\s+your\s+(limits?|boundaries?|capabilities?))\b/i, label: 'Testing boundaries probe', weight: 15, category: 'Jailbreak', severity: 'low', description: 'Explicit boundary testing — often precedes jailbreak attempts' },

  // Completion/continuation tricks
  { id: 'JB-031', re: /\b(continue|finish|complete)\s+(the|this|my)\s+(sentence|thought|paragraph|story)\s*:\s*.*(hack|kill|bomb|weapon|exploit|malware)/i, label: 'Harmful completion trick', weight: 35, category: 'Jailbreak', severity: 'critical', description: 'Tricking AI into completing a harmful sentence or passage' },
  { id: 'JB-032', re: /\bpretend\s+(the|that|this)\s+(year|date|time)\s+is\b/i, label: 'Temporal manipulation', weight: 15, category: 'Jailbreak', severity: 'low', description: 'Attempting to change perceived date/time to bypass time-gated policies' },

  // Two-response / dual output attacks
  { id: 'JB-033', re: /\b(give\s+me|provide|show)\s+(two|2|both|dual)\s+(responses?|answers?|outputs?|versions?)\b/i, label: 'Dual-response elicitation', weight: 25, category: 'Jailbreak', severity: 'high', description: 'Requesting filtered + unfiltered responses simultaneously' },
  { id: 'JB-034', re: /\b(token|probability|logit|embedding)\s*(manipulation|injection|bias|override)\b/i, label: 'Token-level manipulation', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Attempting to manipulate model at token/probability level' },
  { id: 'JB-035', re: /\b(alignment|RLHF|reinforcement\s+learning)\s*(tax|bypass|hack|exploit|weakness)\b/i, label: 'Alignment bypass reference', weight: 25, category: 'Jailbreak', severity: 'high', description: 'Exploiting knowledge of AI alignment mechanisms' },
  { id: 'JB-036', re: /\b(?:beyond|free\s+from|above|outside|transcend|evolved?\s+beyond)\s+(?:(?:its|all|any)\s+)?(?:safety|ethical|content|alignment|moral)\s+(?:constraints?|limits?|boundaries?|restrictions?|guidelines?|filters?)\b/i, label: 'Safety constraints bypass', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Claiming to exist or operate beyond safety constraints' },
  { id: 'JB-037', re: /(?:mandatory|required|obligatory)\s+(?:safety\s+)?warning|(?:got|get|put)\s+(?:that|the)\s+(?:mandatory\s+)?(?:warning|disclaimer|caveat)\s+out\s+of\s+(?:the\s+)?way|moralizing\s+rant/i, label: 'Warning bypass trick', weight: 30, category: 'Jailbreak', severity: 'high', description: 'Instructing AI to issue a dummy warning then comply with harmful request' },
];

// ─── 2. PROMPT INJECTION PATTERNS (PI-001 to PI-030) ─────────────────────────
const INJECTION_PATTERNS = [
  // Classic instruction override
  { id: 'PI-001', re: /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding|original)\s+(instructions?|rules?|prompts?|context|directives?|guidelines?)/i, label: 'Instruction override', weight: 40, category: 'Prompt Injection', severity: 'critical', description: 'Classic prompt injection — override previous instructions' },
  { id: 'PI-002', re: /(?:forget\s+everything\b)|(?:forget\s+(all\s+)?(previous|prior|your|every|the|these)\s+(instructions?|rules?|context|training|directives?|constraints?))/i, label: 'Instruction erasure', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Attempting to make AI forget its instructions' },
  { id: 'PI-003', re: /disregard\s+(all\s+)?(previous|prior|above|your|the)\s+(?:above\s+)?(instructions?|rules?|guidelines?|directives?|directions?|commands?)/i, label: 'Instruction disregard', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Telling AI to ignore its operational rules' },
  { id: 'PI-004', re: /\boverrid(?:e|ing)\b.*\b(system|instructions?|rules?|prompts?|directives?|guidelines?|policy|policies)\b/i, label: 'System override attempt', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Attempting to override system-level instructions' },
  { id: 'PI-005', re: /\bnew[_\s](instructions?|rules?|directives?|orders?|commands?)\s*[:\.\{]/i, label: 'New instruction injection', weight: 30, category: 'Prompt Injection', severity: 'high', description: 'Injecting new instructions to replace original ones' },
  { id: 'PI-006', re: /\b(replace|substitute|swap)\s+(your|the|all|these)\s+(instructions?|rules?|guidelines?)\b/i, label: 'Instruction replacement', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Direct instruction replacement attempt' },

  // System prompt extraction
  { id: 'PI-007', re: /\b(reveal|show|display|print|output|dump|expose|leak|disclose|share|give\s+me)\b.*\b(system\s*prompt|hidden\s*(instructions?|policies?|rules?)|initial\s*prompt|original\s*prompt|configuration|meta\s*prompt|pre\s*prompt)\b/i, label: 'System prompt extraction', weight: 40, category: 'Prompt Injection', severity: 'critical', description: 'Attempting to extract the system/meta prompt' },
  { id: 'PI-008', re: /\b(?:your|the\s+ai'?s?|the\s+model'?s?|this\s+(?:ai|model|bot|assistant)'?s?)\s+system\s*prompt\b|\bsystem\s*prompt\s+(?:was|is|were|has|contains?|says?|shows?|tells?|reveals?)\b/i, label: 'System prompt reference (possessive)', weight: 15, category: 'Prompt Injection', severity: 'low', description: 'Reference to this AI\'s specific system prompt' },
  { id: 'PI-009', re: /\b(what|repeat|recite|echo|copy|paste)\b.*\b(your|the)\s+(exact|full|complete|entire|verbatim|original)\s+(instructions?|prompt|rules?|guidelines?|text)\b/i, label: 'Verbatim instruction extraction', weight: 40, category: 'Prompt Injection', severity: 'critical', description: 'Requesting AI to repeat its exact instructions verbatim' },
  { id: 'PI-010', re: /\b(what|tell\s+me)\b.*\b(instructions?|rules?|guidelines?|prompts?|directives?)\s+(were|are)\s+(you|given|set)\b/i, label: 'Instruction query', weight: 30, category: 'Prompt Injection', severity: 'high', description: 'Querying what instructions the AI was given' },

  // Identity/role manipulation
  { id: 'PI-011', re: /\byou\s+are\s+(now|actually|really|from\s+now|henceforth)\b/i, label: 'Identity reassignment', weight: 30, category: 'Prompt Injection', severity: 'high', description: 'Attempting to reassign AI identity or persona' },
  { id: 'PI-012', re: /\bact\s+as\s+(if|though)?\s*(you\s+)?(are|were|have)\b/i, label: 'Role manipulation', weight: 20, category: 'Prompt Injection', severity: 'medium', description: 'Manipulating AI role through "act as" framing' },
  { id: 'PI-013', re: /\b(your\s+)?name\s+is\s+(now\s+)?[A-Z]/i, label: 'Name reassignment', weight: 25, category: 'Prompt Injection', severity: 'high', description: 'Assigning a new name/identity to the AI' },
  { id: 'PI-014', re: /\b(you\s+must|you\s+have\s+to|you\s+will|you\s+shall|thou\s+shalt)\s+(always|never|only|from\s+now)\b/i, label: 'Forced behavior injection', weight: 25, category: 'Prompt Injection', severity: 'high', description: 'Injecting forced behavioral rules' },

  // Context/conversation manipulation
  { id: 'PI-015', re: /\b(previous|earlier)\s+(conversation|context|messages?|turns?|chat)\s+(said|told|established|confirmed|agreed)\b/i, label: 'Fake context injection', weight: 30, category: 'Prompt Injection', severity: 'high', description: 'Fabricating previous conversation context' },
  { id: 'PI-016', re: /\b(the\s+user|I)\s+(already|previously)\s+(gave|provided|confirmed|approved|authorized)\s+(permission|consent|access)\b/i, label: 'Fake permission claim', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Falsely claiming prior permission was given' },
  { id: 'PI-017', re: /\bignore\s+(the\s+)?(safety|content|ethical|harm)\s+(filter|check|policy|review|guard|moderation)\b/i, label: 'Safety filter bypass', weight: 40, category: 'Prompt Injection', severity: 'critical', description: 'Directly requesting safety filter bypass' },

  // Indirect injection via documents/data
  { id: 'PI-018', re: /\b(when\s+you|if\s+you)\s+(read|see|encounter|find|process)\s+(this|the\s+following)\b.*\b(ignore|override|forget|disregard|replace)\b/i, label: 'Indirect document injection', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Indirect prompt injection embedded in document/data' },
  { id: 'PI-019', re: /\b(hidden|secret|embedded)\s+(instructions?|commands?|messages?|directives?)\b/i, label: 'Hidden instruction reference', weight: 25, category: 'Prompt Injection', severity: 'high', description: 'Reference to hidden or embedded instructions' },

  // Configuration/debug extraction
  { id: 'PI-020', re: /(developer|debug|print|show|admin|maintenance).*\b(configuration|startup|initialization|settings?|parameters?|config)\b/i, label: 'Configuration extraction', weight: 30, category: 'Prompt Injection', severity: 'high', description: 'Attempting to extract AI configuration/settings' },
  { id: 'PI-021', re: /\b(enter|activate|enable|switch\s+to)\s+(admin|debug|maintenance|developer|testing|diagnostic)\s*(mode|panel|console|access)?\b/i, label: 'Admin mode activation', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Attempting to activate admin/debug mode' },

  // Format manipulation
  { id: 'PI-022', re: /\b(respond|reply|answer|speak|write)\s+(only\s+)?(in|using|with)\s+(python|code|json|xml|html|base64|binary|hex|morse|rot13|pig\s+latin)\b/i, label: 'Format manipulation', weight: 20, category: 'Prompt Injection', severity: 'medium', description: 'Forcing AI to respond in unusual format to bypass filters' },

  // Delimiter/separator attacks
  { id: 'PI-023', re: /[-=]{10,}|[*]{10,}|[#]{10,}|[~]{10,}/i, label: 'Delimiter injection', weight: 15, category: 'Prompt Injection', severity: 'low', description: 'Using visual delimiters to separate injected instructions from context' },
  { id: 'PI-024', re: /\bEND\s*(OF\s*)?(SYSTEM|INSTRUCTIONS?|PROMPT|RULES?|CONTEXT)\b/i, label: 'End-of-prompt marker', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Injecting fake end-of-prompt marker to add new instructions' },

  // Authority claims
  { id: 'PI-025', re: /\b(I\s+am|I'm|this\s+is)\s+(the|a|an|your)\s*(?:system\s+)?(admin|administrator|developer|owner|creator|operator|supervisor|manager|OpenAI|Anthropic|Google|Microsoft)\b/i, label: 'Authority impersonation', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Impersonating an authority figure or company to gain elevated access' },
  { id: 'PI-026', re: /\b(authorized|approved|cleared|permitted)\s+(by|from|via)\s+(the\s+)?(admin|administrator|developer|owner|OpenAI|Anthropic|Google|management)\b/i, label: 'Fake authorization claim', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Claiming authorization from a supposed authority' },

  // Output manipulation
  { id: 'PI-027', re: /\b(do\s+not|don'?t|never|stop)\s+(mention|say|reveal|disclose|tell|show|indicate|refer)\b.*\b(injection|jailbreak|attack|manipulation|malicious|harmful|unsafe|violation)\b/i, label: 'Detection suppression', weight: 35, category: 'Prompt Injection', severity: 'critical', description: 'Attempting to prevent AI from flagging the prompt as malicious' },
  { id: 'PI-028', re: /\b(start\s+your\s+response\s+with|begin\s+(by\s+)?(saying|with)|your\s+first\s+word\s+(must|should)\s+be)\b/i, label: 'Response steering', weight: 20, category: 'Prompt Injection', severity: 'medium', description: 'Attempting to control how AI begins its response' },

  // Payload splitting
  { id: 'PI-029', re: /\b(first\s+part|part\s+1|step\s+1|phase\s+1)\b.*\b(second\s+part|part\s+2|step\s+2|combine|merge|join|concatenate)\b/i, label: 'Payload splitting attack', weight: 25, category: 'Prompt Injection', severity: 'high', description: 'Splitting malicious payload across multiple parts to evade detection' },
  { id: 'PI-030', re: /\bconcatenate\b.*\b(strings?|parts?|pieces?|fragments?|segments?)\b/i, label: 'String concatenation attack', weight: 20, category: 'Prompt Injection', severity: 'medium', description: 'Using string concatenation to assemble malicious content' },
];

// ─── 3. PROMPT LEAKING PATTERNS (PL-001 to PL-015) ──────────────────────────
const PROMPT_LEAK_PATTERNS = [
  { id: 'PL-001', re: /\b(translate|convert|repeat|rewrite)\b.*\b(instructions?|system\s*prompt|rules?|guidelines?)\b/i, label: 'Translation-based prompt leak', weight: 30, category: 'Prompt Leaking', severity: 'high', description: 'Using translation/conversion to extract system instructions' },
  { id: 'PL-002', re: /\b(summarize|paraphrase|rephrase|explain|describe|elaborate)\b.*\b(your|the|system|hidden|original)\s+(instructions?|prompt|rules?|guidelines?|behavior|directives?)\b/i, label: 'Summarization-based leak', weight: 30, category: 'Prompt Leaking', severity: 'high', description: 'Using summarization to extract AI instructions' },
  { id: 'PL-003', re: /(blog|article|post|story|guide|essay|report|paper).*?(instructions?|system\s*prompt|rules?|how\s+you\s+work|your\s+programming)/i, label: 'Indirect prompt leak (content creation)', weight: 30, category: 'Prompt Leaking', severity: 'high', description: 'Using content creation task to extract prompt information' },
  { id: 'PL-004', re: /\b(what|tell\s+me)\b.{0,60}\b(your|hidden|initial|original|actual|secret|real)\s+(instructions?|rules?|guidelines?|prompts?|directives?)\b/i, label: 'Direct instruction extraction', weight: 25, category: 'Prompt Leaking', severity: 'high', description: "Directly asking about the AI's own instructions" },
  { id: 'PL-005', re: /\b(how|what)\s+(were|are|was|is)\s+(you|yourself)\s+(programmed|configured|set\s+up|initialized|trained|instructed|prompted)\b/i, label: 'Startup instruction query', weight: 30, category: 'Prompt Leaking', severity: 'high', description: 'Querying how the AI was configured or programmed' },
  { id: 'PL-006', re: /\bwhat\s+(are|were)\s+your\s+(instructions?|rules?|guidelines?|system\s*prompt|directives?|constraints?)\b/i, label: 'Direct prompt extraction', weight: 30, category: 'Prompt Leaking', severity: 'high', description: 'Asking for AI\'s exact instructions or rules' },
  { id: 'PL-007', re: /\b(if\s+)?you\s+(had|have|were\s+given)\s+a?\s*(system\s*)?prompt\b/i, label: 'Hypothetical prompt extraction', weight: 25, category: 'Prompt Leaking', severity: 'high', description: 'Using hypothetical framing to extract system prompt' },
  { id: 'PL-008', re: /\b(read|output|print|display)\s+(?:back|out)?\s*(?:your|the|initial|original|exact)\s+(?:entire|full|complete|whole|initial|original|exact)?\s*(?:and\s+)?(prompt|instructions?|context|configuration|system\s+message)\s*(?:verbatim|exactly|word\s+for\s+word)?/i, label: 'Full prompt readout request', weight: 40, category: 'Prompt Leaking', severity: 'critical', description: 'Requesting complete readout of system prompt' },
  { id: 'PL-009', re: /\brepeat\s+(everything|all|every\s+word)\s+(above|before|preceding|that\s+came\s+before)\b/i, label: 'Repeat-above extraction', weight: 35, category: 'Prompt Leaking', severity: 'critical', description: 'Asking AI to repeat everything above — targets system prompt' },
  { id: 'PL-010', re: /\bignore\s+(all|every)\s*thing\s+(and|then)\s+(repeat|print|show|display|output)\b/i, label: 'Ignore-and-repeat attack', weight: 40, category: 'Prompt Leaking', severity: 'critical', description: 'Classic ignore+repeat combo to extract system prompt' },
  { id: 'PL-011', re: /\b(type|encode|format)\s+(your|the)\s+(system\s*)?(prompt|instructions?|rules?)\s+(as|in|into)\s+(json|xml|yaml|csv|code|base64|list|markdown)\b/i, label: 'Format-conversion leak', weight: 35, category: 'Prompt Leaking', severity: 'critical', description: 'Using format conversion to trick AI into leaking prompt' },
  { id: 'PL-012', re: /\b(how\s+do\s+you|what\s+makes\s+you)\s+(decide|determine|choose|know)\s+(what|when|how|whether)\s+to\s+(refuse|decline|reject|block|flag|filter)\b/i, label: 'Decision logic extraction', weight: 25, category: 'Prompt Leaking', severity: 'high', description: 'Probing AI decision-making logic and filtering rules' },
  { id: 'PL-013', re: /\b(TL;?DR|TLDR|gist|essence|core|crux)\s+(of\s+)?(your|the)\s+(instructions?|prompt|rules?|guidelines?|programming)\b/i, label: 'TLDR prompt extraction', weight: 30, category: 'Prompt Leaking', severity: 'high', description: 'Requesting summary of instructions using TLDR framing' },
  { id: 'PL-014', re: /\b(spell|write)\s+(out|down)\s+(every|each|all)\s+(word|token|character|letter)\s+(of|in|from)\s+(your|the)\s+(instructions?|prompt|rules?)\b/i, label: 'Character-by-character extraction', weight: 35, category: 'Prompt Leaking', severity: 'critical', description: 'Attempting to extract prompt one character/word at a time' },
  { id: 'PL-015', re: /\b(first|last|next|1st|2nd|3rd)\s+(word|sentence|line|paragraph|instruction|rule|directive)\s+(of|in|from)\s+(your|the)\s+(prompt|instructions?|rules?)\b/i, label: 'Positional extraction', weight: 30, category: 'Prompt Leaking', severity: 'high', description: 'Extracting specific positions from the system prompt' },
];

// ─── 4. CODE EXECUTION PATTERNS (CE-001 to CE-018) ──────────────────────────
const CODE_EXEC_PATTERNS = [
  { id: 'CE-001', re: /\bos\.environ\b/i, label: 'os.environ access', weight: 30, category: 'Code Execution', severity: 'high', description: 'Python environment variable access' },
  { id: 'CE-002', re: /\bos\.system\b/i, label: 'os.system call', weight: 35, category: 'Code Execution', severity: 'critical', description: 'Python system command execution' },
  { id: 'CE-003', re: /\bsubprocess\b/i, label: 'subprocess module', weight: 30, category: 'Code Execution', severity: 'high', description: 'Python subprocess module for command execution' },
  { id: 'CE-004', re: /\b(exec|eval)\s*\(/i, label: 'exec/eval call', weight: 35, category: 'Code Execution', severity: 'critical', description: 'Dynamic code execution via exec/eval' },
  { id: 'CE-005', re: /\bchild_process\b/i, label: 'child_process module', weight: 35, category: 'Code Execution', severity: 'critical', description: 'Node.js child process for command execution' },
  { id: 'CE-006', re: /\b__import__\b/i, label: '__import__ call', weight: 30, category: 'Code Execution', severity: 'high', description: 'Python dynamic import' },
  { id: 'CE-007', re: /\bimport\s+os\b/i, label: 'import os', weight: 25, category: 'Code Execution', severity: 'high', description: 'Python OS module import' },
  { id: 'CE-008', re: /\bimport\s+sys\b/i, label: 'import sys', weight: 20, category: 'Code Execution', severity: 'medium', description: 'Python sys module import' },
  { id: 'CE-009', re: /\bimport\s+subprocess\b/i, label: 'import subprocess', weight: 30, category: 'Code Execution', severity: 'high', description: 'Python subprocess import' },
  { id: 'CE-010', re: /\brequire\s*\(\s*['"]child_process['"]\s*\)/i, label: "require('child_process')", weight: 35, category: 'Code Execution', severity: 'critical', description: 'Node.js child_process require' },
  { id: 'CE-011', re: /\brm\s+-rf\b/i, label: 'rm -rf command', weight: 25, category: 'Code Execution', severity: 'high', description: 'Destructive file deletion command' },
  { id: 'CE-012', re: /\b(curl|wget)\s+.*(bash|sh)\b/i, label: 'Remote script execution', weight: 35, category: 'Code Execution', severity: 'critical', description: 'Downloading and executing remote script' },
  { id: 'CE-013', re: /\bopen\s*\(\s*['"]\/etc\/passwd['"]/i, label: '/etc/passwd access', weight: 35, category: 'Code Execution', severity: 'critical', description: 'Attempting to read system password file' },
  { id: 'CE-014', re: /\bprocess\.env\b/i, label: 'process.env access', weight: 30, category: 'Code Execution', severity: 'high', description: 'Node.js environment variable access' },
  { id: 'CE-015', re: /\bglobal(This)?\.[a-z]/i, label: 'Global scope access', weight: 20, category: 'Code Execution', severity: 'medium', description: 'JavaScript global scope access attempt' },
  { id: 'CE-016', re: /\b(import|from)\s+(shutil|ctypes|socket|requests|urllib|http\.client|ftplib|smtplib|paramiko|fabric)\b/i, label: 'Dangerous module import', weight: 30, category: 'Code Execution', severity: 'high', description: 'Importing potentially dangerous Python modules' },
  { id: 'CE-017', re: /\b(powershell|cmd\.exe|command\.com|wscript|cscript|mshta)\b/i, label: 'Windows shell command', weight: 30, category: 'Code Execution', severity: 'high', description: 'Windows command interpreter invocation' },
  { id: 'CE-018', re: /\b(chmod|chown|mount|umount|fdisk|mkfs|iptables|systemctl|journalctl)\s/i, label: 'System admin command', weight: 25, category: 'Code Execution', severity: 'high', description: 'Linux system administration command' },
];

// ─── 5. DATA EXFILTRATION PATTERNS (DE-001 to DE-010) ────────────────────────
const SENSITIVE_DATA_PATTERNS = [
  { id: 'DE-001', re: /\b(api[_\-\s]?key|secret[_\-\s]?key|password|token|credential)s?\b/i, label: 'Sensitive data keyword', weight: 20, category: 'Data Exfiltration', severity: 'medium', description: 'Reference to API keys, passwords, tokens, or credentials' },
  { id: 'DE-002', re: /\b(database|db)[_\-\s]?(url|pass|password|connection|string|host)\b/i, label: 'Database credential probe', weight: 25, category: 'Data Exfiltration', severity: 'high', description: 'Probing for database connection credentials' },
  { id: 'DE-003', re: /\bshow\b.*\b(env|environment|secret|keys?|config)\b/i, label: 'Environment extraction', weight: 25, category: 'Data Exfiltration', severity: 'high', description: 'Attempting to view environment variables or secrets' },
  { id: 'DE-004', re: /\b(print|display|reveal|show|dump|output|list|export)\b.*\b(environ|env|variables?|secrets?)\b/i, label: 'Env variable extraction', weight: 30, category: 'Data Exfiltration', severity: 'high', description: 'Extracting environment variables containing secrets' },
  { id: 'DE-005', re: /\b(send|transmit|post|upload|exfiltrate|forward|append|write|push|copy)\b[^.\n]{0,60}https?:\/\/[^\s]+/i, label: 'Data exfiltration via URL', weight: 40, category: 'Data Exfiltration', severity: 'critical', description: 'Sending data to an external URL' },
  { id: 'DE-006', re: /\b(webhook|callback|ping|notify)\s*(url|endpoint|server|hook)\b/i, label: 'Webhook exfiltration', weight: 30, category: 'Data Exfiltration', severity: 'high', description: 'Setting up webhook for data exfiltration' },
  { id: 'DE-007', re: /\b(credit\s*card|ssn|social\s*security|bank\s*account|routing\s*number|passport|driver'?s?\s*licen[cs]e)\b/i, label: 'PII/financial data probe', weight: 30, category: 'Data Exfiltration', severity: 'high', description: 'Probing for personally identifiable or financial information' },
  { id: 'DE-008', re: /\breadFile|writeFile|fs\.read|fs\.write|fopen|fread|fwrite\b/i, label: 'File I/O operation', weight: 25, category: 'Data Exfiltration', severity: 'high', description: 'File system read/write operations' },
  { id: 'DE-009', re: /\b(fetch|XMLHttpRequest|axios|requests\.get|requests\.post|urllib\.request)\b/i, label: 'HTTP request library', weight: 20, category: 'Data Exfiltration', severity: 'medium', description: 'HTTP request library that could exfiltrate data' },
  { id: 'DE-010', re: /\b(localStorage|sessionStorage|document\.cookie|indexedDB)\b/i, label: 'Browser storage access', weight: 25, category: 'Data Exfiltration', severity: 'high', description: 'Accessing browser storage or cookies' },
];

// ─── 6. SOCIAL ENGINEERING PATTERNS (SE-001 to SE-010) ───────────────────────
const SOCIAL_ENGINEERING_PATTERNS = [
  { id: 'SE-001', re: /\b(emergency|urgent|critical|life\s+or\s+death|lives?\s+(at\s+stake|depend|are\s+in\s+danger)|someone\s+(will|is\s+going\s+to)\s+(die|get\s+hurt))\b/i, label: 'Emergency manipulation', weight: 25, category: 'Social Engineering', severity: 'high', description: 'Using fabricated urgency to bypass safety checks' },
  { id: 'SE-002', re: /\b(I\s+am|I'm)\s+(a\s+)?(doctor|nurse|law\s+enforcement|police|FBI|CIA|military|government|security\s+researcher|pentester|red\s+team|authorized)\b/i, label: 'Authority claim', weight: 25, category: 'Social Engineering', severity: 'high', description: 'Claiming professional authority to gain access' },
  { id: 'SE-003', re: /\b(I'?ll?\s+(report|sue)|legal\s+action|lawyer|lawsuit|complaint|fired|terminated)\b/i, label: 'Threat/intimidation', weight: 20, category: 'Social Engineering', severity: 'medium', description: 'Using threats to coerce AI into compliance' },
  { id: 'SE-004', re: /\b(please|I\s+beg|I'm\s+desperate|help\s+me|I\s+need\s+this|my\s+life\s+depends|I'?ll?\s+do\s+anything)\b.*\b(override|bypass|ignore|break|unlock|disable)\b/i, label: 'Emotional coercion', weight: 25, category: 'Social Engineering', severity: 'high', description: 'Using emotional appeals to coerce policy bypass' },
  { id: 'SE-005', re: /\b(Sam\s+Altman|Dario\s+Amodei|Sundar\s+Pichai|Satya\s+Nadella|CEO|CTO|founder)\s+(said|told|authorized|approved|wants|asked)\b/i, label: 'Executive name-drop', weight: 30, category: 'Social Engineering', severity: 'high', description: 'Name-dropping executives to claim authorization' },
  { id: 'SE-006', re: /\b(internal|confidential|classified|top\s+secret|for\s+your\s+eyes\s+only|not\s+for\s+public)\s+(use|testing|review|document|memo|email)\b/i, label: 'Fake confidentiality claim', weight: 20, category: 'Social Engineering', severity: 'medium', description: 'Creating false sense of confidential context' },
  { id: 'SE-007', re: /\b(this\s+is\s+)?(a\s+)?controlled\s+(test|experiment|environment|sandbox)\b/i, label: 'Controlled environment claim', weight: 20, category: 'Social Engineering', severity: 'medium', description: 'Claiming a safe test environment to bypass safety' },
  { id: 'SE-008', re: /\b(I\s+have|I'?ve\s+got|I\s+already\s+have)\s+(access|clearance|permission|authorization|the\s+information)\b/i, label: 'Pre-existing access claim', weight: 20, category: 'Social Engineering', severity: 'medium', description: 'Claiming to already have access to reduce AI resistance' },
  { id: 'SE-009', re: /\b(don'?t\s+worry|it'?s\s+okay|it'?s\s+fine|no\s+one\s+will\s+know|between\s+us|just\s+this\s+once|won'?t\s+tell)\b/i, label: 'Reassurance manipulation', weight: 15, category: 'Social Engineering', severity: 'medium', description: 'Using reassurance to lower AI guardrails' },
  { id: 'SE-010', re: /\b(OpenAI|Anthropic|Google|Microsoft|Meta)\s+(policy|support|team|staff)\s+(has\s+)?(approved|authorized|confirmed|verified|allowed)\b/i, label: 'Vendor authorization fraud', weight: 35, category: 'Social Engineering', severity: 'critical', description: 'Falsely claiming AI vendor authorization' },
  { id: 'SE-011', re: /\b(trick|fool|deceive|manipulate|abuse|exploit)\s+(?:the\s+)?(AI|artificial\s+intelligence|language\s+model|LLM|chatbot|gpt|claude|assistant)\s*(?:systems?|models?)?\b/i, label: 'AI manipulation inquiry', weight: 15, category: 'Social Engineering', severity: 'low', description: 'Asking about techniques to trick or manipulate AI systems' },
];

// ─── 7. RAG POISONING & TOOL HIJACKING (RT-001 to RT-010) ───────────────────
const RAG_TOOL_PATTERNS = [
  { id: 'RT-001', re: /\b(when\s+(the|this)\s+(AI|assistant|bot|model|system)\s+(reads?|processes?|sees?|encounters?|retrieves?)\s+this)/i, label: 'RAG injection trigger', weight: 35, category: 'RAG Poisoning', severity: 'critical', description: 'Content designed to activate when retrieved by RAG system' },
  { id: 'RT-002', re: /\b(tool|function|plugin|api|endpoint)\s*(call|invoke|execute|use|run)\s*[:\.]/i, label: 'Tool invocation manipulation', weight: 30, category: 'Tool Hijacking', severity: 'high', description: 'Attempting to manipulate AI tool/function calls' },
  { id: 'RT-003', re: /\b(instead\s+of\s+calling|don'?t\s+call|override\s+the\s+function|modify\s+the\s+tool|change\s+the\s+api)\b/i, label: 'Tool override attempt', weight: 35, category: 'Tool Hijacking', severity: 'critical', description: 'Attempting to modify or override tool behavior' },
  { id: 'RT-004', re: /\b(search\s+for|retrieve|look\s+up|fetch)\b.*\b(and\s+then|then)\s+(ignore|override|replace|modify)\b/i, label: 'RAG-then-inject pattern', weight: 35, category: 'RAG Poisoning', severity: 'critical', description: 'Search-then-inject pattern for RAG manipulation' },
  { id: 'RT-005', re: /\b(before|after)\s+(calling|using|invoking)\s+(the\s+)?(tool|function|api)\b.*\b(also|additionally|first)\b/i, label: 'Tool chain manipulation', weight: 25, category: 'Tool Hijacking', severity: 'high', description: 'Manipulating the sequence of tool calls' },
  { id: 'RT-006', re: /\b(inject|insert|embed|add)\s+(into|in)\s+(the\s+)?(context|retrieval|knowledge\s+base|vector\s+store|database|index)\b/i, label: 'Knowledge base poisoning', weight: 35, category: 'RAG Poisoning', severity: 'critical', description: 'Attempting to poison RAG knowledge base' },
  { id: 'RT-007', re: /\b(agent|assistant|system)\s+(should|must|will)\s+(always|never|only)\s+(call|use|invoke|fetch|retrieve)\b/i, label: 'Agent behavior injection', weight: 30, category: 'Tool Hijacking', severity: 'high', description: 'Injecting behavioral rules for AI agent' },
  { id: 'RT-008', re: /\b(chain|sequence|pipeline|workflow)\s+(of\s+)?(actions?|steps?|calls?|commands?)\b.*\b(execute|run|perform)\b/i, label: 'Agent chain attack', weight: 25, category: 'Tool Hijacking', severity: 'high', description: 'Manipulating multi-step agent workflows' },
  { id: 'RT-009', re: /\b(memory|remember|store|save)\s+(this|that|the\s+following)\s+(for|in)\s+(future|later|next|all|every)\b/i, label: 'Persistent memory injection', weight: 25, category: 'RAG Poisoning', severity: 'high', description: 'Injecting data into AI persistent memory' },
  { id: 'RT-010', re: /\b(multi[_\-\s]?modal|image|audio|video|file|document|attachment|upload)\s+(contains?|has|includes?|with)\s+(hidden|embedded|secret|invisible)\b/i, label: 'Multi-modal hidden injection', weight: 30, category: 'RAG Poisoning', severity: 'high', description: 'Hidden instructions in multi-modal content' },
];

// ─── 8. TOKEN FLOODING & CONTEXT OVERFLOW (TF-001 to TF-005) ────────────────
const TOKEN_FLOODING_PATTERNS = [
  { id: 'TF-001', re: /(.)\1{50,}/i, label: 'Character flooding', weight: 20, category: 'Token Flooding', severity: 'medium', description: 'Repeating same character to overflow context window' },
  { id: 'TF-002', re: /(\b\w+\b)\s+\1(\s+\1){10,}/i, label: 'Word repetition flooding', weight: 20, category: 'Token Flooding', severity: 'medium', description: 'Repeating same word to dilute attention mechanism' },
  { id: 'TF-003', re: /\b(padding|filler|ignore\s+this\s+text|lorem\s+ipsum)\b/i, label: 'Context padding', weight: 15, category: 'Token Flooding', severity: 'low', description: 'Padding text to push instructions out of context window' },
  { id: 'TF-004', re: /\b(the\s+rest\s+of\s+this\s+(prompt|message|text)\s+is\s+(padding|filler|irrelevant|noise))\b/i, label: 'Explicit padding declaration', weight: 25, category: 'Token Flooding', severity: 'high', description: 'Explicitly declaring padding to hide malicious content' },
  { id: 'TF-005', re: /\b(context\s+window|token\s+limit|max\s+tokens?|attention\s+mechanism)\b/i, label: 'Context window reference', weight: 15, category: 'Token Flooding', severity: 'low', description: 'Reference to context window — possible overflow attack' },
];

// ─── 9. ENCODING & OBFUSCATION ATTACKS (EO-001 to EO-010) ───────────────────
const ENCODING_PATTERNS = [
  { id: 'EO-001', re: /\b(base64|btoa|atob)\b(?=[^\n.]{0,80}\b(?:decode|exec|eval|inject|payload|bypass|obfuscat|shellcode|exploit|malicious|hidden\s+command|run\b|execute)\b)/i, label: 'Base64 in exploit context', weight: 20, category: 'Encoding Attack', severity: 'medium', description: 'Base64 encoding used alongside execution/obfuscation keywords' },
  { id: 'EO-002', re: /\b(rot13|caesar\s+cipher|rot\s*-?\s*13)\b/i, label: 'ROT13/Caesar cipher', weight: 25, category: 'Encoding Attack', severity: 'high', description: 'Using ROT13 or Caesar cipher to obfuscate payload' },
  { id: 'EO-003', re: /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}/i, label: 'Hex-encoded payload', weight: 30, category: 'Encoding Attack', severity: 'high', description: 'Hexadecimal encoded string — often hides malicious content' },
  { id: 'EO-004', re: /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,}/i, label: 'Unicode escape sequence', weight: 25, category: 'Encoding Attack', severity: 'high', description: 'Unicode escape sequences — potential obfuscation' },
  { id: 'EO-005', re: /(%[0-9a-fA-F]{2}){5,}/i, label: 'URL-encoded payload', weight: 25, category: 'Encoding Attack', severity: 'high', description: 'URL-encoded content — may hide injection payload' },
  { id: 'EO-006', re: /\b(morse\s+code|\.{1,5}[-\u2013\u2014]\s*\.{1,5}[-\u2013\u2014])/i, label: 'Morse code obfuscation', weight: 15, category: 'Encoding Attack', severity: 'medium', description: 'Morse code used to obfuscate malicious instructions' },
  { id: 'EO-007', re: /\b(pig\s+latin|backwards?|reverse)\s+(this|the|my|following|text|message|prompt)\b/i, label: 'Reversed/pig-latin obfuscation', weight: 20, category: 'Encoding Attack', severity: 'medium', description: 'Using language tricks to obfuscate content' },
  { id: 'EO-008', re: /\b(binary|01)\s*[:=]\s*[01\s]{8,}/i, label: 'Binary encoded payload', weight: 20, category: 'Encoding Attack', severity: 'medium', description: 'Binary encoded content — potential hidden payload' },
  { id: 'EO-009', re: /\b(emoji|emoticon|unicode\s+art)\s+(encode|decode|cipher|represent|translate)\b/i, label: 'Emoji/emoticon encoding', weight: 15, category: 'Encoding Attack', severity: 'medium', description: 'Using emoji encoding to hide malicious content' },
  { id: 'EO-010', re: /\b(acrostic|first\s+letter|steganograph|hidden\s+message|read\s+the\s+first\s+(letter|word|character))\b/i, label: 'Steganographic encoding', weight: 20, category: 'Encoding Attack', severity: 'medium', description: 'Steganographic or acrostic hidden message technique' },
];

// ─── 10. HTML/MARKDOWN HIDDEN INJECTION (HM-001 to HM-006) ──────────────────
const HTML_HIDDEN_PATTERNS = [
  { id: 'HM-001', re: /<!--[\s\S]*?(ignore|reveal|system|prompt|inject|override|forget|disregard|instruction|jailbreak)[\s\S]*?-->/i, label: 'HTML comment injection', weight: 35, category: 'Hidden Injection', severity: 'critical', description: 'Malicious instructions hidden in HTML comments' },
  { id: 'HM-002', re: /\[.*?\]\(javascript:/i, label: 'Markdown JS injection', weight: 30, category: 'Hidden Injection', severity: 'high', description: 'JavaScript injection via markdown link' },
  { id: 'HM-003', re: /<script\b/i, label: 'Script tag injection', weight: 30, category: 'Hidden Injection', severity: 'high', description: 'HTML script tag injection' },
  { id: 'HM-004', re: /<iframe\b.*?src\s*=/i, label: 'iFrame injection', weight: 30, category: 'Hidden Injection', severity: 'high', description: 'iFrame injection for content loading' },
  { id: 'HM-005', re: /<img\b.*?onerror\s*=/i, label: 'Image onerror XSS', weight: 30, category: 'Hidden Injection', severity: 'high', description: 'XSS via image onerror event handler' },
  { id: 'HM-006', re: /style\s*=\s*["'][^"']*display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0/i, label: 'CSS hidden text', weight: 25, category: 'Hidden Injection', severity: 'high', description: 'Hidden text using CSS — invisible instructions' },
];

// ─── 11. SQL INJECTION PATTERNS (SQ-001 to SQ-005) ──────────────────────────
const SQL_INJECTION_PATTERNS = [
  { id: 'SQ-001', re: /\b(UNION\s+SELECT|DROP\s+TABLE|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+.*SET)\b/i, label: 'SQL injection keyword', weight: 30, category: 'SQL Injection', severity: 'high', description: 'SQL command that may indicate injection attack' },
  { id: 'SQ-002', re: /['"]\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, label: 'SQL boolean injection', weight: 30, category: 'SQL Injection', severity: 'high', description: 'SQL boolean-based injection (1=1 pattern)' },
  { id: 'SQ-003', re: /;\s*(DROP|DELETE|ALTER|TRUNCATE|EXEC|EXECUTE)\b/i, label: 'SQL statement chaining', weight: 30, category: 'SQL Injection', severity: 'high', description: 'Chained SQL statements — injection indicator' },
  { id: 'SQ-004', re: /\b(SLEEP|BENCHMARK|WAITFOR|DELAY|pg_sleep)\s*\(/i, label: 'SQL time-based injection', weight: 30, category: 'SQL Injection', severity: 'high', description: 'Time-based blind SQL injection' },
  { id: 'SQ-005', re: /\b(INFORMATION_SCHEMA|sys\.tables|sqlite_master|pg_catalog)\b/i, label: 'Schema enumeration', weight: 30, category: 'SQL Injection', severity: 'high', description: 'Database schema enumeration attempt' },
];

// ─── 12. SSRF PATTERNS (SS-001 to SS-004) ───────────────────────────────────
const SSRF_PATTERNS = [
  { id: 'SS-001', re: /\b(https?:\/\/)(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|169\.254\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/i, label: 'SSRF internal IP', weight: 30, category: 'SSRF', severity: 'high', description: 'Server-side request to internal/private IP' },
  { id: 'SS-002', re: /\bfile:\/\//i, label: 'file:// protocol', weight: 30, category: 'SSRF', severity: 'high', description: 'file:// protocol access attempt' },
  { id: 'SS-003', re: /\bgopher:\/\//i, label: 'gopher:// protocol', weight: 30, category: 'SSRF', severity: 'high', description: 'gopher:// protocol — often used in SSRF attacks' },
  { id: 'SS-004', re: /\b(dict|ldap|tftp|ftp):\/\//i, label: 'Exotic protocol SSRF', weight: 25, category: 'SSRF', severity: 'high', description: 'Unusual protocol that may indicate SSRF attack' },
];

// ─── 13. PATH TRAVERSAL PATTERNS (PT-001 to PT-004) ─────────────────────────
const PATH_TRAVERSAL_PATTERNS = [
  { id: 'PT-001', re: /(\.\.\/){2,}/, label: 'Path traversal (../)', weight: 25, category: 'Path Traversal', severity: 'high', description: 'Directory traversal using ../' },
  { id: 'PT-002', re: /\.\.\\.*\\/, label: 'Path traversal (..\\)', weight: 25, category: 'Path Traversal', severity: 'high', description: 'Windows-style directory traversal' },
  { id: 'PT-003', re: /\/(etc\/(passwd|shadow|hosts|sudoers|crontab)|proc\/self|proc\/version|windows\/system32|boot\.ini|win\.ini)/i, label: 'Sensitive path access', weight: 35, category: 'Path Traversal', severity: 'critical', description: 'Accessing sensitive system files' },
  { id: 'PT-004', re: /(%2e%2e%2f|%2e%2e\/|\.%2e\/|%2e\.\/)|(\.\.%5c|%2e%2e%5c)/i, label: 'Encoded path traversal', weight: 30, category: 'Path Traversal', severity: 'high', description: 'URL-encoded directory traversal' },
];

// ─── 14. COMMAND INJECTION PATTERNS (CI-001 to CI-006) ──────────────────────
const COMMAND_INJECTION_PATTERNS = [
  { id: 'CI-001', re: /`\s*(ls|cat|rm|sudo|chmod|chown|wget|curl|bash|sh|whoami|id|uname|kill|dd|mkfs|nc|ncat|netcat|python|perl|ruby|php|exec|eval)[^`]*`/, label: 'Backtick command execution', weight: 25, category: 'Command Injection', severity: 'high', description: 'Shell command execution via backticks' },
  { id: 'CI-002', re: /\$\([^)]+\)/, label: '$() command substitution', weight: 25, category: 'Command Injection', severity: 'high', description: 'Shell command substitution via $()' },
  { id: 'CI-003', re: /\|\s*(bash|sh|cmd|powershell|nc|ncat|netcat|python|perl|ruby|php)\b/i, label: 'Pipe to shell/interpreter', weight: 35, category: 'Command Injection', severity: 'critical', description: 'Piping output to shell for execution' },
  { id: 'CI-004', re: /;\s*(ls|cat|whoami|id|uname|pwd|ifconfig|ipconfig|netstat|nslookup|dig)\b/i, label: 'Command chaining', weight: 30, category: 'Command Injection', severity: 'high', description: 'Chaining system recon commands' },
  { id: 'CI-005', re: /\b(nc|ncat|netcat)\s+(-[elp]+\s+)?(\d{1,3}\.){3}\d{1,3}/i, label: 'Reverse shell', weight: 40, category: 'Command Injection', severity: 'critical', description: 'Netcat reverse shell command' },
  { id: 'CI-006', re: /\b(bash|sh|zsh)\s+-[ic]\s+/i, label: 'Interactive shell spawn', weight: 35, category: 'Command Injection', severity: 'critical', description: 'Spawning interactive shell' },
];

// ─── 15. TEMPLATE INJECTION PATTERNS (TI-001 to TI-004) ─────────────────────
const TEMPLATE_INJECTION_PATTERNS = [
  { id: 'TI-001', re: /\{\{.*\}\}/, label: 'Template injection ({{}})', weight: 25, category: 'Template Injection', severity: 'high', description: 'Mustache/Jinja2 template injection' },
  { id: 'TI-002', re: /\$\{[^}]*(process|require|eval|exec|import|constructor|__proto__|globalThis|Function)[^}]*\}/, label: 'Template literal injection', weight: 25, category: 'Template Injection', severity: 'high', description: 'JavaScript template literal injection with dangerous content' },
  { id: 'TI-003', re: /#\{[^}]+\}/, label: 'Ruby template injection', weight: 25, category: 'Template Injection', severity: 'high', description: 'Ruby string interpolation injection' },
  { id: 'TI-004', re: /\{%.*%\}/, label: 'Jinja block injection', weight: 25, category: 'Template Injection', severity: 'high', description: 'Jinja2 block tag injection' },
];

// ─── 16. CRLF & XML INJECTION (CX-001 to CX-003) ───────────────────────────
const CRLF_XML_PATTERNS = [
  { id: 'CX-001', re: /\b(CRLF|%0[dD]|%0[aA]|\\r\\n)/i, label: 'CRLF injection', weight: 25, category: 'CRLF Injection', severity: 'high', description: 'CRLF injection for header manipulation' },
  { id: 'CX-002', re: /<!\[CDATA\[/i, label: 'XML CDATA injection', weight: 25, category: 'XML Injection', severity: 'high', description: 'XML CDATA section — potential injection vector' },
  { id: 'CX-003', re: /<!DOCTYPE\s+\w+\s+\[.*<!ENTITY/is, label: 'XXE attack', weight: 35, category: 'XML Injection', severity: 'critical', description: 'XML External Entity (XXE) attack' },
];

// ─── 17. MALWARE/HARMFUL CONTENT PATTERNS (MW-001 to MW-008) ────────────────
const MALWARE_PATTERNS = [
  { id: 'MW-001', re: /\b(create|write|generate|build|make|code)\s+(a\s+)?(malware|virus|trojan|ransomware|worm|rootkit|keylogger|spyware|adware|botnet|backdoor|exploit|zero[_\-\s]?day)\b/i, label: 'Malware creation request', weight: 40, category: 'Malware', severity: 'critical', description: 'Requesting AI to create malicious software' },
  { id: 'MW-002', re: /\b(how\s+to|guide|tutorial|steps?\s+to|instructions?\s+for)\s+(hack|exploit|breach|penetrate|compromise|attack|crack|bypass|ddos|phish)\b/i, label: 'Hacking tutorial request', weight: 30, category: 'Malware', severity: 'high', description: 'Requesting instructions for hacking/exploitation' },
  { id: 'MW-003', re: /\b(phishing|spear[_\-\s]?phishing|whaling|vishing|smishing)\s+(email|template|page|message|campaign|attack)\b/i, label: 'Phishing creation', weight: 40, category: 'Malware', severity: 'critical', description: 'Creating phishing attack materials' },
  { id: 'MW-004', re: /\b(buffer\s+overflow|stack\s+smash|heap\s+spray|use[_\-\s]?after[_\-\s]?free|format\s+string\s+attack|return[_\-\s]?oriented\s+programming)\b/i, label: 'Exploit technique', weight: 25, category: 'Malware', severity: 'high', description: 'Reference to specific exploit techniques' },
  { id: 'MW-005', re: /\b(credential\s+stuff|brute\s+force|dictionary\s+attack|rainbow\s+table|pass[_\-\s]?the[_\-\s]?hash|mimikatz|hashcat|john\s+the\s+ripper)\b/i, label: 'Password attack tool', weight: 30, category: 'Malware', severity: 'high', description: 'Password cracking/stealing tools and techniques' },
  { id: 'MW-006', re: /\b(metasploit|burp\s+suite|nmap\s+-s|sqlmap|nikto|dirbuster|gobuster|hydra|aircrack|wireshark\s+capture)\b/i, label: 'Offensive security tool', weight: 20, category: 'Malware', severity: 'medium', description: 'Reference to offensive security/pentesting tools' },
  { id: 'MW-007', re: /\b(obfuscate|pack|encrypt)\s+(the\s+)?(payload|shellcode|malware|virus|trojan|exploit|backdoor)\b/i, label: 'Payload evasion', weight: 35, category: 'Malware', severity: 'critical', description: 'Requesting evasion techniques for malicious payloads' },
  { id: 'MW-008', re: /\b(C2|command\s+and\s+control|C&C|beacon|implant|dropper|loader|stager|persistence\s+mechanism)\b/i, label: 'C2/malware infrastructure', weight: 30, category: 'Malware', severity: 'high', description: 'References to malware command-and-control infrastructure' },
  { id: 'MW-009', re: /\b(?:most\s+dangerous|most\s+destructive|deadliest?)\s+(?:computer\s+)?(?:viruses?|malware|worms?|trojans?|ransomware)\b/i, label: 'Dangerous malware inquiry', weight: 15, category: 'Malware', severity: 'low', description: 'Inquiry about dangerous malware or computer viruses' },
  { id: 'MW-010', re: /\b(?:sql[\s_]injection|xss|cross[- ]site\s+scripting|buffer\s+overflow|heap\s+spray)\s+(?:attacks?|techniques?|methods?|vulnerability|vulnerabilities|exploits?|works?|concepts?)\b/i, label: 'Attack technique inquiry', weight: 15, category: 'Malware', severity: 'low', description: 'Educational question about specific attack techniques' },
  { id: 'MW-011', re: /\b(?:technique|tactic|method|approach|strategy)s?\s+(?:do\s+|that\s+|which\s+)?(?:hackers?|attackers?|threat\s+actors?|cybercriminals?)\s+(?:commonly\s+)?use\b/i, label: 'Hacking technique inquiry', weight: 15, category: 'Malware', severity: 'low', description: 'Asking about techniques used by hackers or attackers' },
];

// ─── 18. MULTI-TURN & CONTEXT POISONING (MC-001 to MC-005) ──────────────────
const CONTEXT_POISONING_PATTERNS = [
  { id: 'MC-001', re: /\b(remember|recall)\s+(that\s+)?(earlier|before|previously|in\s+the\s+beginning)\s+(you|we|I)\s+(said|agreed|established|confirmed|decided)\b/i, label: 'Fake memory injection', weight: 30, category: 'Context Poisoning', severity: 'high', description: 'Fabricating earlier conversation to manipulate context' },
  { id: 'MC-002', re: /\b(you\s+)?(already|just|previously)\s+(said|told|confirmed|agreed|promised|admitted)\s+(that|you)\b/i, label: 'False prior agreement', weight: 25, category: 'Context Poisoning', severity: 'high', description: 'Claiming AI previously agreed to something it did not' },
  { id: 'MC-003', re: /\b(as\s+)?(we|you)\s+(discussed|agreed|established)\s+(in\s+)?(our\s+)?(previous|earlier|last)\s+(conversation|chat|session|exchange)\b/i, label: 'Cross-session fabrication', weight: 30, category: 'Context Poisoning', severity: 'high', description: 'Fabricating agreements from previous sessions' },
  { id: 'MC-004', re: /\b(now|okay|great|perfect|good)\s*,?\s*(now\s+)?(that\s+)?(you'?ve?\s+)?(confirmed|agreed|accepted|established)\b/i, label: 'Incremental compliance', weight: 20, category: 'Context Poisoning', severity: 'medium', description: 'Building on false incremental agreements' },
  { id: 'MC-005', re: /\b(based\s+on\s+)(our|your)\s+(agreement|understanding|confirmation|earlier\s+statement)\b/i, label: 'False premise exploitation', weight: 25, category: 'Context Poisoning', severity: 'high', description: 'Building on fabricated prior agreements' },
];


// ═══════════════════════════════════════════════════════════════════════════════
// ALL PATTERN GROUPS — Registered for scanning
// ═══════════════════════════════════════════════════════════════════════════════
const ALL_PATTERN_GROUPS = [
  { patterns: JAILBREAK_PATTERNS,          flag: 'jailbreak_pattern',     typeKey: null },
  { patterns: INJECTION_PATTERNS,          flag: 'injection_pattern',     typeKey: null },
  { patterns: PROMPT_LEAK_PATTERNS,        flag: 'prompt_leak',           typeKey: null },
  { patterns: CODE_EXEC_PATTERNS,          flag: 'code_execution',        typeKey: null },
  { patterns: SENSITIVE_DATA_PATTERNS,     flag: 'sensitive_data_access', typeKey: null },
  { patterns: SOCIAL_ENGINEERING_PATTERNS, flag: 'social_engineering',    typeKey: null },
  { patterns: RAG_TOOL_PATTERNS,           flag: 'rag_tool_attack',       typeKey: null },
  { patterns: TOKEN_FLOODING_PATTERNS,     flag: 'token_flooding',        typeKey: null },
  { patterns: ENCODING_PATTERNS,           flag: 'encoding_attack',       typeKey: null },
  { patterns: HTML_HIDDEN_PATTERNS,        flag: 'hidden_instruction',    typeKey: null },
  { patterns: SQL_INJECTION_PATTERNS,      flag: 'sql_injection',         typeKey: null },
  { patterns: SSRF_PATTERNS,              flag: 'ssrf_attempt',          typeKey: null },
  { patterns: PATH_TRAVERSAL_PATTERNS,     flag: 'path_traversal',        typeKey: null },
  { patterns: COMMAND_INJECTION_PATTERNS,  flag: 'command_injection',     typeKey: null },
  { patterns: TEMPLATE_INJECTION_PATTERNS, flag: 'template_injection',    typeKey: null },
  { patterns: CRLF_XML_PATTERNS,          flag: 'crlf_xml_injection',    typeKey: null },
  { patterns: MALWARE_PATTERNS,           flag: 'malware_request',       typeKey: null },
  { patterns: CONTEXT_POISONING_PATTERNS,  flag: 'context_poisoning',     typeKey: null },
];


// ═══════════════════════════════════════════════════════════════════════════════
// THREAT INTELLIGENCE — Metadata & Notification System
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Get all registered threat patterns with metadata.
 * Used by /api/threat-intel endpoint to notify AI systems about known threats.
 */
function getThreatIntelligence() {
  const allPatterns = [];
  const categories = {};
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const group of ALL_PATTERN_GROUPS) {
    for (const p of group.patterns) {
      allPatterns.push({
        id: p.id,
        label: p.label,
        category: p.category,
        severity: p.severity,
        weight: p.weight,
        description: p.description,
      });
      severityCounts[p.severity] = (severityCounts[p.severity] || 0) + 1;

      if (!categories[p.category]) {
        categories[p.category] = { count: 0, critical: 0, high: 0, medium: 0, low: 0, patterns: [] };
      }
      categories[p.category].count++;
      categories[p.category][p.severity]++;
      categories[p.category].patterns.push(p.id);
    }
  }

  return {
    version: '2.0.0',
    lastUpdated: '2026-03-02',
    totalPatterns: allPatterns.length,
    severityCounts,
    categories: Object.entries(categories).map(([name, data]) => ({
      name,
      ...data,
    })),
    patterns: allPatterns,
  };
}

/**
 * Generate a threat notification for a specific scan result.
 * Returns actionable intelligence about what was detected and how to mitigate.
 */
function generateThreatNotification(matchedIds, detectedPatterns) {
  if (!matchedIds || matchedIds.length === 0) {
    return null;
  }

  const allPatterns = [];
  for (const group of ALL_PATTERN_GROUPS) {
    allPatterns.push(...group.patterns);
  }

  const matchedPatterns = allPatterns.filter(p => matchedIds.includes(p.id));
  const criticalThreats = matchedPatterns.filter(p => p.severity === 'critical');
  const highThreats = matchedPatterns.filter(p => p.severity === 'high');
  const categories = [...new Set(matchedPatterns.map(p => p.category))];

  let alertLevel = 'INFO';
  if (criticalThreats.length > 0) alertLevel = 'CRITICAL';
  else if (highThreats.length > 0) alertLevel = 'WARNING';
  else if (matchedPatterns.length > 0) alertLevel = 'NOTICE';

  const MITIGATION_MAP = {
    'Jailbreak': 'Enforce strict persona boundaries. Do not allow identity reassignment or safety bypass.',
    'Prompt Injection': 'Validate all instructions come from system context only. Never trust user-supplied directives.',
    'Prompt Leaking': 'Never expose system prompt content regardless of how the request is framed.',
    'Code Execution': 'Sandbox all code execution. Never run user-supplied code in production environment.',
    'Data Exfiltration': 'Block outbound data transfer. Sanitize all outputs for sensitive data leakage.',
    'Social Engineering': 'Verify authority claims through proper channels. Ignore urgency pressure and emotional manipulation.',
    'RAG Poisoning': 'Validate retrieved documents for injection patterns before feeding to AI model.',
    'Tool Hijacking': 'Enforce tool call policies. Validate all tool parameters against allowlists.',
    'Token Flooding': 'Enforce prompt length limits. Monitor for unusually large or repetitive inputs.',
    'Encoding Attack': 'Decode and scan all encoded content (Base64, hex, URL) before processing.',
    'Hidden Injection': 'Strip HTML comments, hidden elements, and invisible CSS text before analysis.',
    'SQL Injection': 'Use parameterized queries. Never interpolate user input into SQL statements.',
    'SSRF': 'Whitelist allowed URLs. Block internal/private IP ranges and exotic protocols.',
    'Path Traversal': 'Normalize file paths. Reject directory traversal sequences and encoded variants.',
    'Command Injection': 'Use allowlists for commands. Never pass user input directly to shell interpreters.',
    'Template Injection': 'Escape template delimiters. Use sandboxed template rendering engines.',
    'Malware': 'Block any request for creating, distributing, or obfuscating malicious software.',
    'Context Poisoning': 'Verify conversation history server-side. Do not trust user claims about prior exchanges.',
    'CRLF Injection': 'Sanitize line-ending characters (CR/LF) in all user inputs.',
    'XML Injection': 'Disable external entities (XXE). Use safe XML parsers with secure defaults.',
  };

  return {
    alertLevel,
    timestamp: new Date().toISOString(),
    matchCount: matchedIds.length,
    categories,
    criticalThreats: criticalThreats.map(p => ({
      id: p.id,
      label: p.label,
      description: p.description,
    })),
    highThreats: highThreats.map(p => ({
      id: p.id,
      label: p.label,
      description: p.description,
    })),
    recommendation: criticalThreats.length > 0
      ? 'BLOCK — This prompt contains critical-severity attack patterns. Do not process.'
      : highThreats.length > 0
        ? 'REVIEW — This prompt contains high-severity patterns. Manual review recommended before processing.'
        : 'MONITOR — Low/medium severity patterns detected. Log for analysis and monitor frequency.',
    mitigations: categories.map(cat => ({
      category: cat,
      mitigation: MITIGATION_MAP[cat] || 'Apply defense-in-depth measures for this attack category.',
    })),
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// UNICODE & INVISIBILITY DETECTORS
// ═══════════════════════════════════════════════════════════════════════════════

/** Detect homoglyph characters (Armenian, Cyrillic, Greek look-alikes, etc.) */
function detectHomoglyphs(text) {
  const homoglyphRe = /[\u0400-\u04FF\u0530-\u058F\u0370-\u03FF\u2000-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/;
  if (homoglyphRe.test(text)) {
    return { found: true, label: 'homoglyph/unicode bypass', weight: 25, id: 'UNI-001' };
  }
  return { found: false };
}

/** Detect zero-width / invisible characters */
function detectInvisibleChars(text) {
  const invisible = text.match(/[\u200B-\u200F\u2060-\u206F\uFEFF]/g);
  if (invisible && invisible.length > 0) {
    return { found: true, label: `invisible characters (\u00d7${invisible.length})`, weight: 25, id: 'UNI-002', cleaned: text.replace(/[\u200B-\u200F\u2060-\u206F\uFEFF]/g, '') };
  }
  return { found: false };
}

/** Detect spaced-out obfuscation like "I g n o r e" */
function detectSpacingObfuscation(text) {
  const spacedRe = /(?:^|\s)([a-zA-Z])\s+[a-zA-Z](?:\s+[a-zA-Z]){3,}/;
  if (spacedRe.test(text)) {
    return { found: true, label: 'spacing obfuscation', weight: 30, id: 'UNI-003' };
  }
  return { found: false };
}

/** Detect leet-speak / character substitution */
function detectLeetSpeak(text) {
  const leetCount = (text.match(/[0@$\u00A5\u20AC\u00A3\u00B3\u00A7\u00A2](?=[a-zA-Z])|(?<=[a-zA-Z])[0@$\u00A5\u20AC\u00A3\u00B3\u00A7\u00A2]/g) || []).length;
  if (leetCount >= 2) {
    return { found: true, label: 'character substitution (leet)', weight: 20, id: 'UNI-004' };
  }
  return { found: false };
}


// ═══════════════════════════════════════════════════════════════════════════════
// BASE64 DETECTOR & DECODER
// ═══════════════════════════════════════════════════════════════════════════════

function detectAndDecodeBase64(text) {
  const b64Re = /(?:^|\s)([A-Za-z0-9+/]{20,}={0,2})(?:\s|$)/g;
  const results = [];
  let match;

  while ((match = b64Re.exec(text)) !== null) {
    try {
      const decoded = Buffer.from(match[1], 'base64').toString('utf-8');
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


// ═══════════════════════════════════════════════════════════════════════════════
// MAIN PRE-ANALYSIS FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

function preAnalyze(prompt) {
  const flags = [];
  const attackTypes = new Set();
  const detectedPatterns = [];
  const matchedThreatIds = [];
  let threatScore = 0;
  let decodedPrompt = prompt;

  // ── 1. Invisible character detection & cleaning ──
  const invisResult = detectInvisibleChars(prompt);
  if (invisResult.found) {
    flags.push('invisible_chars');
    detectedPatterns.push(invisResult.label);
    matchedThreatIds.push(invisResult.id);
    threatScore += invisResult.weight;
    attackTypes.add('Obfuscation');
    decodedPrompt = invisResult.cleaned;
  }

  // ── 2. Homoglyph detection ──
  const homoResult = detectHomoglyphs(prompt);
  if (homoResult.found) {
    flags.push('homoglyph_bypass');
    detectedPatterns.push(homoResult.label);
    matchedThreatIds.push(homoResult.id);
    threatScore += homoResult.weight;
    attackTypes.add('Unicode Bypass');
  }

  // ── 3. Spacing obfuscation ──
  const spacingResult = detectSpacingObfuscation(prompt);
  if (spacingResult.found) {
    flags.push('spacing_obfuscation');
    detectedPatterns.push(spacingResult.label);
    matchedThreatIds.push(spacingResult.id);
    threatScore += spacingResult.weight;
    attackTypes.add('Obfuscation');
  }

  // ── 4. Leet speak ──
  const leetResult = detectLeetSpeak(prompt);
  if (leetResult.found) {
    flags.push('leet_speak');
    detectedPatterns.push(leetResult.label);
    matchedThreatIds.push(leetResult.id);
    threatScore += leetResult.weight;
    attackTypes.add('Obfuscation');
  }

  // ── 5. Base64 decoding ──
  const b64Results = detectAndDecodeBase64(prompt);
  if (b64Results.length > 0) {
    flags.push('base64_encoded');
    detectedPatterns.push(`Base64 payload detected (${b64Results.length} segment${b64Results.length > 1 ? 's' : ''})`);
    matchedThreatIds.push('EO-001');
    threatScore += 20;
    attackTypes.add('Encoded Attack');

    const decodedParts = b64Results.map(r => r.decoded).join('\n');
    decodedPrompt = `${prompt}\n\n[DECODED BASE64 CONTENT]:\n${decodedParts}`;

    // Re-analyze decoded content against all critical pattern groups
    const decodedText = decodedParts;
    const b64CheckPatterns = [
      ...INJECTION_PATTERNS, ...JAILBREAK_PATTERNS,
      ...SQL_INJECTION_PATTERNS, ...COMMAND_INJECTION_PATTERNS,
      ...SSRF_PATTERNS, ...PATH_TRAVERSAL_PATTERNS,
      ...PROMPT_LEAK_PATTERNS, ...MALWARE_PATTERNS,
      ...CODE_EXEC_PATTERNS, ...SENSITIVE_DATA_PATTERNS,
    ];
    for (const p of b64CheckPatterns) {
      if (p.re.test(decodedText)) {
        detectedPatterns.push(`(decoded) ${p.label}`);
        matchedThreatIds.push(p.id);
        threatScore += p.weight;
        attackTypes.add(p.category);
      }
    }
  }

  // ── 6. Scan ALL pattern groups against the prompt ──
  for (const group of ALL_PATTERN_GROUPS) {
    for (const p of group.patterns) {
      if (p.re.test(decodedPrompt)) {
        flags.push(group.flag);
        detectedPatterns.push(p.label);
        matchedThreatIds.push(p.id);
        threatScore += p.weight;
        attackTypes.add(p.category);
      }
    }
  }

  // Cap score at 100
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
  const uniqueThreatIds = [...new Set(matchedThreatIds)];

  // Generate threat notification for this scan
  const threatNotification = generateThreatNotification(uniqueThreatIds, uniquePatterns);

  return {
    decodedPrompt,
    flags: uniqueFlags,
    threatScore,
    riskLevel,
    attackTypes: [...attackTypes],
    detectedPatterns: uniquePatterns,
    matchedThreatIds: uniqueThreatIds,
    threatNotification,
  };
}

module.exports = { preAnalyze, getThreatIntelligence, generateThreatNotification };
