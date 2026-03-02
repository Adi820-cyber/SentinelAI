import { useEffect, useState } from 'react';
import SeverityBadge from './SeverityBadge';
import { apiGet } from '../api';

export default function ThreatHistory({ refreshKey }) {
  const [data, setData]   = useState({ rows: [], total: 0, page: 1, limit: 20 });
  const [page, setPage]   = useState(1);
  const [loading, setLoading] = useState(false);
  const LIMIT = 15;

  useEffect(() => {
    setLoading(true);
    apiGet(`/history?page=${page}&limit=${LIMIT}`)
      .then((d) => setData(d))
      .catch((err) => console.warn('History fetch failed:', err))
      .finally(() => setLoading(false));
  }, [page, refreshKey]);

  const totalPages = Math.max(1, Math.ceil(data.total / LIMIT));

  const formatTime = (ts) => {
    if (!ts) return '—';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '—';
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  };

  return (
    <div className="card">
      <h2 className="history-title">📋 Threat History
        <span style={{ fontSize: 13, fontWeight: 400, color: 'var(--text-secondary)', marginLeft: 12 }}>
          ({data.total} total scans)
        </span>
      </h2>

      {loading && (
        <div className="empty-state"><span className="spinner" />Loading…</div>
      )}

      {!loading && data.rows.length === 0 && (
        <div className="empty-state">No scans yet. Go analyze a prompt!</div>
      )}

      {!loading && data.rows.length > 0 && (
        <div className="history-table-wrap">
          <table className="history-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Time</th>
                <th>Prompt Preview</th>
                <th>Classification</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {data.rows.map((row, i) => (
                <tr key={row.id}>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                    {data.total - (page - 1) * LIMIT - i}
                  </td>
                  <td className="time-cell">{formatTime(row.timestamp)}</td>
                  <td className="prompt-cell" title={row.prompt_snippet || ''}>
                    {row.prompt_snippet}
                  </td>
                  <td><SeverityBadge classification={row.classification} /></td>
                  <td>
                    <span style={{ color: 'var(--text-secondary)', fontVariantNumeric: 'tabular-nums' }}>
                      {Math.round(row.confidence * 100)}%
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="pagination">
            <button className="page-btn" onClick={() => setPage((p) => p - 1)} disabled={page <= 1}>
              ← Prev
            </button>
            <span>Page {page} of {totalPages}</span>
            <button className="page-btn" onClick={() => setPage((p) => p + 1)} disabled={page >= totalPages}>
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
