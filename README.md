# 🛡️ SentinelAI — LLM Prompt Injection & Jailbreak Firewall

> An AI-powered real-time firewall that analyzes incoming prompts for jailbreak attempts, prompt injection, and adversarial inputs — running 100% locally with zero cloud dependencies.

---

## Quick Start

### Prerequisites
1. **Node.js 18+** — [nodejs.org](https://nodejs.org)
2. **Ollama** — [ollama.com](https://ollama.com)

```bash
# Pull the AI model (one-time ~2-4GB download)
ollama pull llama3.2

# Start Ollama in the background
ollama serve
```

### Installation & Run

```bash
# From the sentinelai/ folder:
npm install
cd backend && npm install
cd ../frontend && npm install
cd ..

# Start both servers (backend :5000 + frontend :5173)
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Features

| | Feature | Description |
|---|---|---|
| ⚡ | **Prompt Analyzer** | Paste any prompt and get an instant threat classification |
| 🎯 | **4-tier Classification** | 🟢 Safe · 🟡 Suspicious · 🟠 Injection · 🔴 Jailbreak |
| 💡 | **AI Explanation** | Human-readable reason for every decision |
| 📋 | **Threat History** | Paginated log of all past scans |
| 📊 | **Statistics Dashboard** | Pie + bar charts with threat distribution |
| 🔒 | **Rate Limiting** | 30 req/min per IP on the analyze endpoint |
| 💾 | **Local Storage** | All data stored in a local JSON file — no cloud, no surveillance |

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET  | `/api/health` | Server health check |
| POST | `/api/analyze` | Analyze a prompt `{ "prompt": "..." }` |
| GET  | `/api/history?page=1&limit=20` | Paginated scan history |
| GET  | `/api/stats` | Aggregate statistics |

---

## Configuration (`.env`)

```env
PORT=5000
OLLAMA_MODEL=llama3.2
OLLAMA_HOST=http://localhost:11434
```

Swap `OLLAMA_MODEL` to `mistral` or any other locally installed model.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js + Express |
| AI Engine | Ollama (local) + `ollama` npm SDK |
| Storage | JSON file (no native compilation needed) |
| Frontend | React 18 + Vite 5 |
| Charts | Recharts |
| Styling | Vanilla CSS — dark glassmorphism theme |
| Dev | concurrently + nodemon |
