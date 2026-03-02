import { useEffect, useState } from 'react';
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Area, AreaChart,
} from 'recharts';
import { apiGet } from '../api';

const COLORS = {
  SAFE:       '#22c55e',
  SUSPICIOUS: '#eab308',
  INJECTION:  '#f97316',
  JAILBREAK:  '#ef4444',
};

const LABELS = {
  SAFE:       'Safe',
  SUSPICIOUS: 'Suspicious',
  INJECTION:  'Injection',
  JAILBREAK:  'Jailbreak',
};

const CustomTooltipStyle = {
  background: 'rgba(10,22,40,0.95)',
  border: '1px solid rgba(255,255,255,0.12)',
  borderRadius: 10,
  color: '#e8f0fe',
  fontSize: 13,
  padding: '8px 14px',
};

// Custom pie label that doesn't overlap
const renderCustomLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, name }) => {
  if (percent < 0.05) return null; // skip tiny slices
  const RADIAN = Math.PI / 180;
  const radius = outerRadius + 22;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill={COLORS[name] || '#fff'} textAnchor={x > cx ? 'start' : 'end'}
      dominantBaseline="central" fontSize={11} fontWeight={600}>
      {`${(percent * 100).toFixed(0)}%`}
    </text>
  );
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

  // Fill in missing days for last 7 days so bar chart shows proper spacing
  const fillLast7Days = (rawDays) => {
    const map = {};
    (rawDays || []).forEach(r => { map[r.day] = r.count; });
    const days = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000);
      const key = d.toISOString().slice(0, 10);
      days.push({ day: key.slice(5), Scans: map[key] || 0 });
    }
    return days;
  };

  const barData = fillLast7Days(stats.last7Days);
  const isEmpty = stats.total === 0;

  return (
    <div className="stats-grid">
      {/* Pie Chart — Donut */}
      <div className="card">
        <p className="chart-title">🎯 Threat Distribution</p>
        {isEmpty ? (
          <div className="empty-state">No data yet</div>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={100}
                paddingAngle={4}
                dataKey="value"
                label={renderCustomLabel}
                labelLine={{ stroke: 'rgba(255,255,255,0.15)', strokeWidth: 1 }}
                strokeWidth={0}
              >
                {pieData.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name] || '#8884d8'} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={CustomTooltipStyle}
                formatter={(val, name) => [`${val} scans`, LABELS[name] || name]}
              />
              <Legend
                verticalAlign="bottom"
                height={36}
                formatter={(value) => (
                  <span style={{ color: COLORS[value] || '#fff', fontSize: 11, fontWeight: 500 }}>
                    {LABELS[value] || value}
                  </span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Area Chart — Last 7 Days */}
      <div className="card">
        <p className="chart-title">📈 Scans — Last 7 Days</p>
        {barData.every(d => d.Scans === 0) ? (
          <div className="empty-state">No scans in last 7 days</div>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={barData} margin={{ top: 10, right: 16, left: -10, bottom: 0 }}>
              <defs>
                <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#4f8ef7" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#9b72ff" stopOpacity={0.05} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" vertical={false} />
              <XAxis dataKey="day" tick={{ fill: '#8a9bb8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: '#8a9bb8', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={CustomTooltipStyle} cursor={{ stroke: 'rgba(79,142,247,0.3)', strokeWidth: 1 }} />
              <Area type="monotone" dataKey="Scans" stroke="#4f8ef7" strokeWidth={2.5}
                fill="url(#areaGrad)" dot={{ r: 4, fill: '#4f8ef7', stroke: '#0a1628', strokeWidth: 2 }}
                activeDot={{ r: 6, fill: '#4f8ef7', stroke: '#fff', strokeWidth: 2 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Summary Stats Cards */}
      <div className="card" style={{ gridColumn: '1 / -1' }}>
        <p className="chart-title">📊 Classification Breakdown</p>
        <div className="breakdown-grid">
          {['SAFE', 'SUSPICIOUS', 'INJECTION', 'JAILBREAK'].map((cls) => {
            const count = stats.byClassification?.[cls] || 0;
            const pct = stats.total > 0 ? ((count / stats.total) * 100).toFixed(1) : '0.0';
            return (
              <div key={cls} className="breakdown-card" style={{ '--cls-color': COLORS[cls] }}>
                <div className="breakdown-header">
                  <span className="breakdown-count">{count}</span>
                  <span className="breakdown-pct">{pct}%</span>
                </div>
                <div className="breakdown-label">{LABELS[cls]}</div>
                <div className="breakdown-bar-track">
                  <div className="breakdown-bar-fill" style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
