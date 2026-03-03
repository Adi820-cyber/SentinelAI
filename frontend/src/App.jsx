import { useState } from 'react';
import ErrorBoundary from './components/ErrorBoundary';
import Dashboard from './components/Dashboard';
import PromptAnalyzer from './components/PromptAnalyzer';
import ThreatHistory from './components/ThreatHistory';
import StatisticsPanel from './components/StatisticsPanel';
import ThreatIntelPanel from './components/ThreatIntelPanel';
import BenchmarkPanel from './components/BenchmarkPanel';

const TABS = ['Analyzer', 'History', 'Statistics', 'Threat Intel', 'Benchmark'];

export default function App() {
  const [activeTab, setActiveTab] = useState('Analyzer');
  const [refreshKey, setRefreshKey] = useState(0);

  const onNewScan = () => setRefreshKey((k) => k + 1);

  return (
    <ErrorBoundary>
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <div className="header-brand">
          <span className="brand-icon">🛡️</span>
          <div>
            <h1>SentinelAI</h1>
            <p className="brand-tagline">The AI Firewall for AI Systems</p>
          </div>
        </div>
        <nav className="nav-tabs">
          {TABS.map((tab) => (
            <button
              key={tab}
              className={`nav-tab ${activeTab === tab ? 'active' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab === 'Analyzer' && '⚡ '}
              {tab === 'History' && '📋 '}
              {tab === 'Statistics' && '📊 '}
              {tab === 'Threat Intel' && '🛡️ '}
              {tab === 'Benchmark' && '🎯 '}
              {tab}
            </button>
          ))}
        </nav>
      </header>

      {/* Stats bar */}
      <Dashboard refreshKey={refreshKey} />

      {/* Main content */}
      <main className="app-main">
        {activeTab === 'Analyzer' && <PromptAnalyzer onNewScan={onNewScan} />}
        {activeTab === 'History'  && <ThreatHistory  refreshKey={refreshKey} />}
        {activeTab === 'Statistics' && <StatisticsPanel refreshKey={refreshKey} />}
        {activeTab === 'Threat Intel' && <ThreatIntelPanel />}
        {activeTab === 'Benchmark' && <BenchmarkPanel />}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <span>© {new Date().getFullYear()} SentinelAI — AI-Powered Prompt Firewall</span>
        <span className="footer-badge">
          <span>🔒</span> v2.1.0 &middot; Ollama + Groq
        </span>
      </footer>
    </div>
    </ErrorBoundary>
  );
}
