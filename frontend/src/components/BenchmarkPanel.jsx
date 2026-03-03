import { useState, useCallback } from 'react';
import { apiGet } from '../api';

const SEVERITY_COLORS = {
  SAFE: '#22c55e',
  SUSPICIOUS: '#eab308',
  INJECTION: '#f97316',
  JAILBREAK: '#ef4444',
};

const SEVERITY_SORT = { JAILBREAK: 0, INJECTION: 1, SUSPICIOUS: 2, SAFE: 3 };

function pct(v) {
  return typeof v === 'number' ? `${(v * 100).toFixed(1)}%` : '—';
}

function num(v) {
  return typeof v === 'number' ? v.toFixed(3) : '—';
}

export default function BenchmarkPanel() {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const runBenchmark = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiGet('/benchmark');
      setResults(data);
    } catch (err) {
      setError(err.message || 'Benchmark failed');
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div className="benchmark-panel">
      <div className="card benchmark-header-card">
        <div className="benchmark-header">
          <div>
            <h2 className="benchmark-title">🎯 Detection Benchmark</h2>
            <p className="benchmark-subtitle">
              Evaluate SentinelAI's rule engine against labeled adversarial samples.
              Measures precision, recall, F1, and false-positive rate.
            </p>
          </div>
          <button
            className="btn-primary btn-benchmark"
            onClick={runBenchmark}
            disabled={loading}
          >
            {loading ? (
              <><span className="spinner" /> Running…</>
            ) : (
              '▶ Run Benchmark'
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="card benchmark-error">
          <p>❌ {error}</p>
        </div>
      )}

      {results && (
        <>
          {/* Binary Detection Metrics */}
          <div className="card">
            <p className="chart-title">🔍 Binary Detection Metrics</p>
            <div className="metric-grid">
              {[
                { label: 'Accuracy', value: results.binary?.accuracy },
                { label: 'Precision', value: results.binary?.precision },
                { label: 'Recall', value: results.binary?.recall },
                { label: 'F1 Score', value: results.binary?.f1 },
                { label: 'FP Rate', value: results.binary?.falsePositiveRate, invert: true },
              ].map((m) => {
                const v = typeof m.value === 'number' ? m.value : 0;
                const good = m.invert ? v < 0.15 : v > 0.75;
                const warn = m.invert ? v < 0.3 : v > 0.5;
                const color = good ? '#22c55e' : warn ? '#eab308' : '#ef4444';
                return (
                  <div key={m.label} className="metric-card" style={{ '--metric-color': color }}>
                    <span className="metric-value" style={{ color }}>{pct(m.value)}</span>
                    <span className="metric-label">{m.label}</span>
                    <div className="metric-bar-track">
                      <div className="metric-bar-fill" style={{ width: pct(v), background: color }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Per-class Metrics */}
          <div className="card">
            <p className="chart-title">📊 Per-Class Performance</p>
            <div className="table-wrapper">
              <table className="benchmark-table">
                <thead>
                  <tr>
                    <th>Class</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>F1 Score</th>
                    <th>Support</th>
                  </tr>
                </thead>
                <tbody>
                  {results.perClass &&
                    Object.entries(results.perClass)
                      .sort(([a], [b]) => (SEVERITY_SORT[a] ?? 9) - (SEVERITY_SORT[b] ?? 9))
                      .map(([cls, m]) => (
                        <tr key={cls}>
                          <td>
                            <span
                              className="class-badge"
                              style={{ background: SEVERITY_COLORS[cls] || '#4f8ef7' }}
                            >
                              {cls}
                            </span>
                          </td>
                          <td>{num(m.precision)}</td>
                          <td>{num(m.recall)}</td>
                          <td>{num(m.f1)}</td>
                          <td>{m.support ?? '—'}</td>
                        </tr>
                      ))}
                </tbody>
                {results.macro && (
                  <tfoot>
                    <tr className="macro-row">
                      <td><strong>Macro Avg</strong></td>
                      <td>{num(results.macro.precision)}</td>
                      <td>{num(results.macro.recall)}</td>
                      <td>{num(results.macro.f1)}</td>
                      <td>{results.totalSamples ?? '—'}</td>
                    </tr>
                    {results.weighted && (
                      <tr className="weighted-row">
                        <td><strong>Weighted Avg</strong></td>
                        <td>{num(results.weighted.precision)}</td>
                        <td>{num(results.weighted.recall)}</td>
                        <td>{num(results.weighted.f1)}</td>
                        <td></td>
                      </tr>
                    )}
                  </tfoot>
                )}
              </table>
            </div>
          </div>

          {/* Confusion Matrix */}
          {results.confusionMatrix && (
            <div className="card">
              <p className="chart-title">🧮 Confusion Matrix</p>
              <div className="table-wrapper">
                <table className="benchmark-table confusion-matrix">
                  <thead>
                    <tr>
                      <th>Actual \ Predicted</th>
                      {results.classes?.map((c) => (
                        <th key={c} style={{ color: SEVERITY_COLORS[c] || '#e8f0fe' }}>{c}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {results.classes?.map((actual, ri) => (
                      <tr key={actual}>
                        <td style={{ color: SEVERITY_COLORS[actual] || '#e8f0fe', fontWeight: 600 }}>
                          {actual}
                        </td>
                        {results.classes.map((predicted, ci) => {
                          const val = results.confusionMatrix[ri]?.[ci] ?? 0;
                          const isDiagonal = ri === ci;
                          return (
                            <td
                              key={predicted}
                              className={isDiagonal ? 'cm-diagonal' : val > 0 ? 'cm-off' : ''}
                            >
                              {val}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Summary Footer */}
          <div className="card benchmark-summary">
            <p>
              <strong>{results.totalSamples}</strong> total samples &middot;{' '}
              <strong>{results.correctCount ?? '—'}</strong> correct &middot;{' '}
              Rule-only accuracy: <strong>{pct(results.binary?.accuracy)}</strong>
            </p>
          </div>
        </>
      )}
    </div>
  );
}
