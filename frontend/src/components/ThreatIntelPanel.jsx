import { useState, useEffect } from 'react';
import { apiGet } from '../api';

const SEVERITY_CONFIG = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', icon: '🚨' },
  high:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)', icon: '⚠️' },
  medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.12)',  icon: '🟡' },
  low:      { color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  icon: '🟢' },
};

export default function ThreatIntelPanel() {
  const [summary, setSummary] = useState(null);
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [categoryData, setCategoryData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [catLoading, setCatLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    apiGet('/threat-intel/summary')
      .then(setSummary)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const loadCategory = async (catName) => {
    if (selectedCategory === catName) {
      setSelectedCategory(null);
      setCategoryData(null);
      return;
    }
    setSelectedCategory(catName);
    setCatLoading(true);
    try {
      const data = await apiGet(`/threat-intel/category/${encodeURIComponent(catName)}`);
      setCategoryData(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setCatLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="result-placeholder">
          <span className="spinner" style={{ width: 40, height: 40, borderWidth: 4 }} />
          <p style={{ marginTop: 12 }}>Loading Threat Intelligence…</p>
        </div>
      </div>
    );
  }

  if (error) return <div className="card"><div className="error-msg">⚠️ {error}</div></div>;
  if (!summary) return <div className="card empty-state">No threat intelligence data available.</div>;

  return (
    <div className="threat-intel-layout">
      {/* Summary Header */}
      <div className="card">
        <p className="analyzer-label">🛡️ Threat Intelligence Database</p>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
          v{summary.version} — {summary.totalPatterns} patterns across {summary.totalCategories} categories
        </p>

        {/* Severity breakdown chips */}
        <div className="ti-severity-grid">
          {Object.entries(summary.severityCounts || {}).map(([sev, count]) => {
            const cfg = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.low;
            return (
              <div key={sev} className="ti-severity-chip" style={{ borderColor: cfg.color + '44', background: cfg.bg }}>
                <span className="ti-sev-icon">{cfg.icon}</span>
                <span className="ti-sev-count" style={{ color: cfg.color }}>{count}</span>
                <span className="ti-sev-label">{sev.toUpperCase()}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Category browser */}
      <div className="card">
        <p className="analyzer-label">📂 Pattern Categories</p>
        <div className="ti-category-grid">
          {summary.categories && summary.categories.map((cat) => (
            <button
              key={cat.name}
              className={`ti-category-btn ${selectedCategory === cat.name ? 'active' : ''}`}
              onClick={() => loadCategory(cat.name)}
            >
              <span className="ti-cat-name">{cat.name}</span>
              <span className="ti-cat-count">{cat.count}</span>
            </button>
          ))}
        </div>

        {/* Expanded category detail */}
        {catLoading && (
          <div style={{ textAlign: 'center', padding: 20 }}>
            <span className="spinner" /> Loading patterns…
          </div>
        )}

        {categoryData && !catLoading && selectedCategory && (
          <div className="ti-category-detail">
            <p className="mini-label" style={{ marginTop: 16, marginBottom: 10 }}>
              {selectedCategory} — {categoryData.patterns?.length || 0} patterns
            </p>
            <div className="ti-pattern-table-wrap">
              <table className="ti-pattern-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Label</th>
                    <th>Severity</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {(categoryData.patterns || []).map((p) => {
                    const cfg = SEVERITY_CONFIG[p.severity] || SEVERITY_CONFIG.low;
                    return (
                      <tr key={p.id}>
                        <td><code className="ti-id">{p.id}</code></td>
                        <td>{p.label}</td>
                        <td>
                          <span className="ti-sev-badge" style={{ color: cfg.color, background: cfg.bg, borderColor: cfg.color }}>
                            {p.severity}
                          </span>
                        </td>
                        <td className="ti-desc-cell">{p.description}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* API Info */}
      <div className="card">
        <p className="analyzer-label">🔌 API Endpoints</p>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
          Other AI systems can query this threat intelligence via these endpoints:
        </p>
        <div className="ti-api-list">
          <div className="ti-api-item">
            <code className="ti-api-method">GET</code>
            <code className="ti-api-path">/api/threat-intel</code>
            <span className="ti-api-desc">Full threat database with all patterns and metadata</span>
          </div>
          <div className="ti-api-item">
            <code className="ti-api-method">GET</code>
            <code className="ti-api-path">/api/threat-intel/summary</code>
            <span className="ti-api-desc">Compact summary with counts and categories</span>
          </div>
          <div className="ti-api-item">
            <code className="ti-api-method">GET</code>
            <code className="ti-api-path">/api/threat-intel/category/:name</code>
            <span className="ti-api-desc">Patterns filtered by category</span>
          </div>
        </div>
      </div>
    </div>
  );
}
