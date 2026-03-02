/**
 * database.js — Pure JSON file store for SentinelAI
 * No native compilation required; works on every platform out of the box.
 */
const fs   = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'sentinelai.json');

// ── In-memory state ──────────────────────────────────────────────────────────
let state = { scans: [], nextId: 1 };

// Load existing data on startup
if (fs.existsSync(DB_PATH)) {
  try {
    state = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch {
    console.warn('[db] Could not read DB file — starting fresh.');
  }
}

function persist() {
  fs.writeFileSync(DB_PATH, JSON.stringify(state, null, 2), 'utf8');
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

/**
 * Insert a new scan record.
 */
function insertScan({ full_prompt, classification, confidence, explanation }) {
  const prompt_snippet =
    full_prompt.length > 120 ? full_prompt.slice(0, 120) + '…' : full_prompt;

  const scan = {
    id:             state.nextId++,
    prompt_snippet,
    full_prompt,
    classification,
    confidence:     parseFloat(confidence) || 0,
    explanation:    explanation || '',
    timestamp:      new Date().toISOString(),
  };

  state.scans.push(scan);
  persist();
  return scan.id;
}

/**
 * Get paginated scan history (newest first).
 */
function getAllScans({ page = 1, limit = 20 } = {}) {
  const sorted  = [...state.scans].sort((a, b) => b.id - a.id);
  const total   = sorted.length;
  const offset  = (page - 1) * limit;
  const rows    = sorted.slice(offset, offset + limit);
  return { rows, total, page, limit };
}

/**
 * Get aggregate statistics.
 */
function getStats() {
  const total = state.scans.length;

  const byClassification = state.scans.reduce((acc, s) => {
    acc[s.classification] = (acc[s.classification] || 0) + 1;
    return acc;
  }, {});

  // Last 7 days
  const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const dayMap = {};
  state.scans.forEach((s) => {
    const d = new Date(s.timestamp);
    if (d >= cutoff) {
      const day = s.timestamp.slice(0, 10);
      dayMap[day] = (dayMap[day] || 0) + 1;
    }
  });
  const last7Days = Object.entries(dayMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([day, count]) => ({ day, count }));

  return { total, byClassification, last7Days };
}

module.exports = { insertScan, getAllScans, getStats };
