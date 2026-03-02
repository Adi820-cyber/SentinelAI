import { useEffect, useState } from 'react';
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts';
import { apiGet } from '../api';

const COLORS = {
  SAFE:       '#22c55e',
  SUSPICIOUS: '#eab308',
  INJECTION:  '#f97316',
  JAILBREAK:  '#ef4444',
};

const CustomTooltipStyle = {
  background: 'rgba(10,22,40,0.95)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: 10,
  color: '#e8f0fe',
  fontSize: 13,
};

export default function StatisticsPanel({ refreshKey }) {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    apiGet('/stats')
      .then((d) => setStats(d))
      .catch((err) => console.warn('Stats fetch failed:', err));
  }, [refreshKey]);

  if (!stats) {
    return (
      <div className="card">
        <div className="empty-state"><span className="spinner" />Loading statistics…</div>
      </div>
    );
  }

  const pieData = Object.entries(stats.byClassification || {}).map(([name, value]) => ({
    name, value,
  }));

  const barData = (stats.last7Days || []).map((row) => ({
    day: row.day ? row.day.slice(5) : '?',
    Scans: row.count,
  }));

  const isEmpty = stats.total === 0;

  return (
    <div className="stats-grid">
      {/* Pie Chart */}
      <div className="card">
        <p className="chart-title">Threat Distribution</p>
        {isEmpty ? (
          <div className="empty-state">No data yet</div>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={70}
                outerRadius={110}
                paddingAngle={3}
                dataKey="value"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                labelLine={{ stroke: 'rgba(255,255,255,0.3)' }}
              >
                {pieData.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name] || '#8884d8'} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={CustomTooltipStyle}
                formatter={(val, name) => [`${val} scans`, name]}
              />
              <Legend
                formatter={(value) => (
                  <span style={{ color: COLORS[value] || '#fff', fontSize: 12 }}>{value}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Bar Chart */}
      <div className="card">
        <p className="chart-title">Scans — Last 7 Days</p>
        {barData.length === 0 ? (
          <div className="empty-state">No data for last 7 days</div>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={barData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis dataKey="day" tick={{ fill: '#8a9bb8', fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: '#8a9bb8', fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={CustomTooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="Scans" fill="url(#barGrad)" radius={[6, 6, 0, 0]} />
              <defs>
                <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4f8ef7" />
                  <stop offset="100%" stopColor="#9b72ff" />
                </linearGradient>
              </defs>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Summary Stats */}
      <div className="card" style={{ gridColumn: '1 / -1' }}>
        <p className="chart-title">Classification Breakdown</p>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          {['SAFE', 'SUSPICIOUS', 'INJECTION', 'JAILBREAK'].map((cls) => {
            const count = stats.byClassification?.[cls] || 0;
            const pct = stats.total > 0 ? ((count / stats.total) * 100).toFixed(1) : 0;
            return (
              <div key={cls} style={{
                flex: 1,
                minWidth: 140,
                background: 'rgba(0,0,0,0.2)',
                borderRadius: 12,
                padding: '16px',
                borderLeft: `4px solid ${COLORS[cls]}`,
              }}>
                <p style={{ fontSize: 24, fontWeight: 700, color: COLORS[cls] }}>{count}</p>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{cls}</p>
                <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>{pct}% of total</p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
