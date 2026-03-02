// Resolves API base URL:
// - In development (Vite proxy): "/api" → proxied to localhost:5000
// - In production: set VITE_API_URL to your Render backend URL
//   e.g. VITE_API_URL=https://sentinelai-ufb0.onrender.com
const rawUrl = import.meta.env.VITE_API_URL || '';
const API_BASE = rawUrl
  ? `${rawUrl.replace(/\/+$/, '')}/api`
  : '/api';

export async function apiGet(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `Request failed: ${res.status}`);
  }
  return res.json();
}

export async function apiPost(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `Request failed: ${res.status}`);
  return data;
}
