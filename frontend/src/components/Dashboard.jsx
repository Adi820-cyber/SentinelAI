import { useEffect, useState } from 'react';
import { apiGet } from '../api';

export default function Dashboard({ refreshKey }) {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    apiGet('/stats')
      .then((data) => setStats(data))
      .catch((err) => console.warn('Dashboard stats fetch failed:', err));
  }, [refreshKey]);

  const by = stats?.byClassification || {};

  return (
    <div className="dashboard-bar">
      <div className="stat-chip total">
        <span className="stat-value">{stats?.total ?? '—'}</span>
        <span className="stat-label">Total Scans</span>
      </div>
      <div className="stat-chip safe">
        <span className="stat-value">{by.SAFE ?? 0}</span>
        <span className="stat-label">🟢 Safe</span>
      </div>
      <div className="stat-chip suspicious">
        <span className="stat-value">{by.SUSPICIOUS ?? 0}</span>
        <span className="stat-label">🟡 Suspicious</span>
      </div>
      <div className="stat-chip injection">
        <span className="stat-value">{by.INJECTION ?? 0}</span>
        <span className="stat-label">🟠 Injection</span>
      </div>
      <div className="stat-chip jailbreak">
        <span className="stat-value">{by.JAILBREAK ?? 0}</span>
        <span className="stat-label">🔴 Jailbreak</span>
      </div>
    </div>
  );
}
