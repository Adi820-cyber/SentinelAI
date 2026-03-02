# SentinelAI v2.0 — AI-Powered Prompt Firewall

Enterprise-grade real-time firewall that classifies LLM prompts for jailbreak attempts, prompt injection, data exfiltration, and 20+ adversarial attack categories. Combines a 188-pattern rule engine with AI classification, structured logging, multi-channel alerting, authentication/RBAC, and SIEM integration.

---

## Architecture

```
sentinelai/
├── backend/
│   ├── core/                    # Core engine modules
│   │   ├── logger.js            # Structured JSON logging, daily rotation
│   │   ├── detectionPipeline.js # Modular detection orchestrator
│   │   ├── alertManager.js      # Multi-channel alerting (Slack, email, SIEM)
│   │   ├── featureExtractor.js  # Statistical feature extraction (19 features)
│   │   └── scoring.js           # Composite threat scoring & anomaly detection
│   ├── middleware/
│   │   ├── auth.js              # API key + session auth, RBAC (3 roles)
│   │   └── inputValidator.js    # Input validation & sanitization
│   ├── routes/
│   │   ├── analyze.js           # POST /api/analyze — main classification
│   │   ├── history.js           # GET  /api/history — paginated scan log
│   │   ├── stats.js             # GET  /api/stats — aggregate statistics
│   │   ├── threatIntel.js       # GET  /api/threat-intel/* — pattern database
│   │   ├── auth.js              # POST /api/auth/login, logout, me, status
│   │   └── alerts.js            # GET  /api/alerts — alert history & stats
│   ├── lib/
│   │   └── preAnalyzer.js       # 188-pattern rule engine (20 categories)
│   ├── db/
│   │   └── database.js          # JSON file store with atomic writes
│   ├── tests/
│   │   ├── test_detection.js    # 53 detection & scoring tests
│   │   └── test_data_pipeline.js# 34 database, alerting & logging tests
│   ├── logs/                    # Auto-created: daily logs + SIEM exports
│   └── server.js                # Express app with security middleware
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── Dashboard.jsx       # Tab container
│       │   ├── PromptAnalyzer.jsx  # Prompt input + result display
│       │   ├── ThreatHistory.jsx   # Paginated scan history
│       │   ├── StatisticsPanel.jsx # Pie + bar charts
│       │   ├── ThreatIntelPanel.jsx# Threat intelligence browser
│       │   └── SeverityBadge.jsx   # Risk level badges
│       └── api.js               # API client (auto-detects local/deployed)
├── .env.example                 # Full configuration reference
├── vercel.json                  # Vercel deployment config
└── render.yaml                  # Render deployment config
```

---

## Quick Start

### Prerequisites
- **Node.js 18+** — [nodejs.org](https://nodejs.org)
- **Ollama** — [ollama.com](https://ollama.com) (for local mode)

```bash
# Pull the AI model (one-time ~2 GB download)
ollama pull llama3.2
ollama serve
```

### Install & Run

```bash
npm install
cd backend && npm install && cd ..
cd frontend && npm install && cd ..

# Start backend (:5000) + frontend (:5173)
npm run dev
```

Open **http://localhost:5173**.

---

## Features

### Detection Engine
- **188 regex patterns** across 20 attack categories (Jailbreak, Prompt Injection, Prompt Leaking, Code Execution, Data Exfiltration, Social Engineering, SQL Injection, XSS, Encoding/Obfuscation, etc.)
- **AI classification** via Ollama (local) or Groq (cloud) — 4-tier: Safe / Suspicious / Injection / Jailbreak
- **Blended scoring** — 60% rule engine + 40% AI confidence, with automatic escalation when rules detect threats AI missed
- **Feature extraction** — 19 statistical features (Shannon entropy, char ratios, repetition score, imperative verbs, etc.)
- **Anomaly detection** — baseline deviation scoring for unusual inputs

### Security & Operations
- **Authentication** — API key and session-based auth (disabled by default for dev)
- **RBAC** — 3 roles: admin, analyst, viewer with granular permissions
- **Rate limiting** — 20 req/min on analyze, 60 req/min on read endpoints
- **Input validation** — Prompt length limits, type checking, prototype pollution prevention
- **Security headers** — X-Content-Type-Options, X-Frame-Options, CSP-adjacent headers
- **Structured logging** — JSON format, daily rotation, configurable log level
- **Multi-channel alerting** — Slack/Discord/Teams webhooks, email (SMTP), SIEM (CEF + JSON)

### Frontend
- **Prompt Analyzer** — Real-time classification with threat score, risk level, matched patterns
- **Threat History** — Paginated scan log with severity badges
- **Statistics Dashboard** — Pie + bar charts (Recharts)
- **Threat Intelligence Panel** — Browse all 188 patterns by category and severity
- **Dark glassmorphism UI** — Modern aesthetic with responsive design

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/health` | No | Health check (version, auth status) |
| POST | `/api/analyze` | Yes* | Classify a prompt `{ "prompt": "..." }` |
| GET | `/api/history?page=1&limit=20` | Yes* | Paginated scan history |
| GET | `/api/stats` | Yes* | Aggregate classification statistics |
| GET | `/api/threat-intel/summary` | Yes* | Threat pattern database summary |
| GET | `/api/threat-intel/category/:name` | Yes* | Patterns by category |
| POST | `/api/auth/login` | No | `{ "username", "password" }` → token |
| POST | `/api/auth/logout` | Yes | Invalidate session |
| GET | `/api/auth/me` | Yes | Current user info |
| GET | `/api/auth/status` | No | Auth enabled/disabled status |
| GET | `/api/alerts` | Yes | Alert history (admin/analyst) |
| GET | `/api/alerts/stats` | Yes | Alert statistics by severity |
| GET | `/api/alerts/config` | Yes | Alert configuration (admin) |

\* Auth required only when `AUTH_ENABLED=true`. Default: disabled.

---

## Running Tests

```bash
cd backend

# Run all tests (87 total)
npm test

# Run individually
npm run test:detection   # 53 tests — patterns, scoring, pipeline
npm run test:pipeline    # 34 tests — database, alerts, logging
```

---

## Configuration

All options are set via environment variables. See `.env.example` for the full reference.

### AI Provider (choose one)

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_MODEL` | `llama3.2` | Local Ollama model name |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `GROQ_API_KEY` | — | Groq cloud API key (overrides Ollama) |
| `GROQ_MODEL` | `llama-3.1-8b-instant` | Groq model name |
| `AI_TIMEOUT_MS` | `30000` | AI request timeout |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_ENABLED` | `false` | Enable authentication |
| `AUTH_ADMIN_USER` | `admin` | Admin username |
| `AUTH_ADMIN_PASS` | — | Admin password (required when auth enabled) |
| `AUTH_API_KEYS` | — | API keys: `key1:role,key2:role` |
| `AUTH_USERS` | — | Additional users: `user:pass:role,...` |
| `AUTH_SESSION_SECRET` | auto-generated | Session token secret |

### Alerting

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERT_MIN_SEVERITY` | `High` | Minimum severity to trigger alerts |
| `ALERT_WEBHOOK_URL` | — | Slack/Discord/Teams webhook URL |
| `ALERT_EMAIL_ENABLED` | `false` | Enable email alerts |
| `ALERT_EMAIL_HOST` | — | SMTP host |
| `ALERT_EMAIL_PORT` | `587` | SMTP port |
| `ALERT_EMAIL_USER` | — | SMTP username |
| `ALERT_EMAIL_PASS` | — | SMTP password |
| `ALERT_EMAIL_TO` | — | Recipient email |
| `ALERT_SIEM_ENABLED` | `false` | Enable SIEM CEF/JSON export |

### General

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5000` | Backend server port |
| `LOG_LEVEL` | `INFO` | Logging level: ERROR, WARN, INFO, DEBUG |
| `NODE_ENV` | `development` | Environment (production hides error details) |
| `FRONTEND_URL` | — | Allowed CORS origins (comma-separated) |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js + Express |
| AI Engine | Ollama (local) or Groq (cloud) |
| Detection | 188-pattern rule engine + AI classification |
| Storage | JSON file store (atomic writes) |
| Auth | API keys + session tokens, RBAC |
| Alerting | Webhooks, SMTP email, SIEM (CEF + JSON) |
| Logging | Structured JSON, daily rotation |
| Frontend | React 18 + Vite 5 |
| Charts | Recharts |
| Styling | Dark glassmorphism CSS |
| Testing | Custom test runner (87 tests) |
| Dev | concurrently + nodemon |
| Deployment | Vercel (frontend) + Render (backend) |
