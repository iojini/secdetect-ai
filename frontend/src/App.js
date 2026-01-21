import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_URL = 'http://localhost:8000';

function App() {
  const [status, setStatus] = useState(null);
  const [rules, setRules] = useState([]);
  const [activeTab, setActiveTab] = useState('dashboard');
  
  // Detection form
  const [detectUser, setDetectUser] = useState('admin');
  const [detectHour, setDetectHour] = useState(3);
  const [detectionResult, setDetectionResult] = useState(null);
  
  // Enrichment form
  const [enrichUser, setEnrichUser] = useState('admin');
  const [enrichIP, setEnrichIP] = useState('45.33.32.156');
  const [enrichmentResult, setEnrichmentResult] = useState(null);
  
  // Analysis form
  const [analyzeQuery, setAnalyzeQuery] = useState('192.168.1.100');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchStatus();
    fetchRules();
  }, []);

  const fetchStatus = async () => {
    try {
      const res = await axios.get(`${API_URL}/api/status`);
      setStatus(res.data);
    } catch (err) {
      console.error('Error fetching status:', err);
    }
  };

  const fetchRules = async () => {
    try {
      const res = await axios.get(`${API_URL}/api/rules`);
      setRules(res.data.rules);
    } catch (err) {
      console.error('Error fetching rules:', err);
    }
  };

  const runDetection = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/api/detect`, {
        event_type: 'login',
        user: detectUser,
        hour: parseInt(detectHour)
      });
      setDetectionResult(res.data);
    } catch (err) {
      console.error('Error running detection:', err);
    }
    setLoading(false);
  };

  const runEnrichment = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/api/enrich`, {
        user: enrichUser,
        source_ip: enrichIP
      });
      setEnrichmentResult(res.data);
    } catch (err) {
      console.error('Error running enrichment:', err);
    }
    setLoading(false);
  };

  const runAnalysis = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${API_URL}/api/analyze`, {
        query: analyzeQuery
      });
      setAnalysisResult(res.data);
    } catch (err) {
      console.error('Error running analysis:', err);
    }
    setLoading(false);
  };

  const getRiskColor = (level) => {
    const colors = {
      low: '#22c55e',
      medium: '#eab308',
      high: '#f97316',
      critical: '#ef4444'
    };
    return colors[level] || '#6b7280';
  };

  return (
    <div className="app">
      <header className="header">
        <h1>🛡️ SecDetect AI</h1>
        <p>GenAI-Powered Detection Engineering Platform</p>
      </header>

      <nav className="nav">
        <button 
          className={activeTab === 'dashboard' ? 'active' : ''} 
          onClick={() => setActiveTab('dashboard')}
        >
          Dashboard
        </button>
        <button 
          className={activeTab === 'detect' ? 'active' : ''} 
          onClick={() => setActiveTab('detect')}
        >
          Detection
        </button>
        <button 
          className={activeTab === 'enrich' ? 'active' : ''} 
          onClick={() => setActiveTab('enrich')}
        >
          Enrichment
        </button>
        <button 
          className={activeTab === 'analyze' ? 'active' : ''} 
          onClick={() => setActiveTab('analyze')}
        >
          AI Analysis
        </button>
      </nav>

      <main className="main">
        {activeTab === 'dashboard' && (
          <div className="dashboard">
            <div className="status-card">
              <h2>System Status</h2>
              {status ? (
                <div className="status-grid">
                  <div className="status-item">
                    <span className="label">Status</span>
                    <span className="value online">✅ {status.status}</span>
                  </div>
                  <div className="status-item">
                    <span className="label">Version</span>
                    <span className="value">{status.version}</span>
                  </div>
                  <div className="status-item">
                    <span className="label">Detection Rules</span>
                    <span className="value">{status.rules_loaded} loaded</span>
                  </div>
                  <div className="status-item">
                    <span className="label">AI Engine</span>
                    <span className="value">🧠 {status.ai_status}</span>
                  </div>
                </div>
              ) : (
                <p>Loading...</p>
              )}
            </div>

            <div className="rules-card">
              <h2>Detection Rules</h2>
              {rules.length > 0 ? (
                <div className="rules-list">
                  {rules.map((rule, idx) => (
                    <div key={idx} className="rule-item">
                      <span 
                        className="rule-level" 
                        style={{ backgroundColor: getRiskColor(rule.level) }}
                      >
                        {rule.level?.toUpperCase()}
                      </span>
                      <div className="rule-info">
                        <strong>{rule.title}</strong>
                        <p>{rule.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p>No rules loaded</p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'detect' && (
          <div className="detect-panel">
            <h2>Run Detection</h2>
            <div className="form">
              <div className="form-group">
                <label>User</label>
                <input 
                  type="text" 
                  value={detectUser} 
                  onChange={(e) => setDetectUser(e.target.value)}
                  placeholder="e.g., admin, john.doe"
                />
              </div>
              <div className="form-group">
                <label>Hour (0-23)</label>
                <input 
                  type="number" 
                  value={detectHour} 
                  onChange={(e) => setDetectHour(e.target.value)}
                  min="0" 
                  max="23"
                />
              </div>
              <button onClick={runDetection} disabled={loading}>
                {loading ? 'Running...' : '🔍 Run Detection'}
              </button>
            </div>

            {detectionResult && (
              <div className={`result ${detectionResult.alert_triggered ? 'alert' : 'safe'}`}>
                <h3>
                  {detectionResult.alert_triggered ? '🚨 ALERT TRIGGERED' : '✅ No Alert'}
                </h3>
                {detectionResult.alert_triggered && detectionResult.matches.map((match, idx) => (
                  <div key={idx} className="match-details">
                    <p><strong>Rule:</strong> {match.rule_title}</p>
                    <p><strong>Severity:</strong> {match.level?.toUpperCase()}</p>
                    <p><strong>Description:</strong> {match.description}</p>
                    <p><strong>MITRE ATT&CK:</strong> {match.tags?.join(', ')}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'enrich' && (
          <div className="enrich-panel">
            <h2>Alert Enrichment</h2>
            <div className="form">
              <div className="form-group">
                <label>User</label>
                <input 
                  type="text" 
                  value={enrichUser} 
                  onChange={(e) => setEnrichUser(e.target.value)}
                  placeholder="e.g., admin, john.doe"
                />
              </div>
              <div className="form-group">
                <label>Source IP</label>
                <input 
                  type="text" 
                  value={enrichIP} 
                  onChange={(e) => setEnrichIP(e.target.value)}
                  placeholder="e.g., 192.168.1.100"
                />
              </div>
              <button onClick={runEnrichment} disabled={loading}>
                {loading ? 'Enriching...' : '📊 Run Enrichment'}
              </button>
            </div>

            {enrichmentResult && (
              <div className="enrichment-result">
                <div className="risk-score" style={{ borderColor: getRiskColor(enrichmentResult.risk_level) }}>
                  <span className="score">{enrichmentResult.risk_score}/100</span>
                  <span className="level" style={{ color: getRiskColor(enrichmentResult.risk_level) }}>
                    {enrichmentResult.risk_level?.toUpperCase()}
                  </span>
                </div>

                <div className="enrichment-section">
                  <h4>👤 User Context</h4>
                  <p><strong>Department:</strong> {enrichmentResult.enrichments?.user_context?.department}</p>
                  <p><strong>Role:</strong> {enrichmentResult.enrichments?.user_context?.role}</p>
                  <p><strong>Device:</strong> {enrichmentResult.enrichments?.user_context?.device}</p>
                </div>

                <div className="enrichment-section">
                  <h4>📜 User History</h4>
                  <p><strong>Previous Alerts:</strong> {enrichmentResult.enrichments?.user_history?.previous_alerts}</p>
                  <p><strong>Repeat Offender:</strong> {enrichmentResult.enrichments?.user_history?.is_repeat_offender ? '⚠️ Yes' : '✅ No'}</p>
                </div>

                <div className="enrichment-section">
                  <h4>🌐 IP Intelligence</h4>
                  <p><strong>Reputation:</strong> {enrichmentResult.enrichments?.ip_intel?.reputation}</p>
                  <p><strong>Category:</strong> {enrichmentResult.enrichments?.ip_intel?.category}</p>
                  <p><strong>Source:</strong> {enrichmentResult.enrichments?.ip_intel?.source}</p>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'analyze' && (
          <div className="analyze-panel">
            <h2>AI Security Analysis</h2>
            <div className="form">
              <div className="form-group">
                <label>Enter IOC or Description</label>
                <input 
                  type="text" 
                  value={analyzeQuery} 
                  onChange={(e) => setAnalyzeQuery(e.target.value)}
                  placeholder="e.g., 192.168.1.100, suspicious-domain.com"
                />
              </div>
              <button onClick={runAnalysis} disabled={loading}>
                {loading ? 'Analyzing...' : '🧠 Analyze with AI'}
              </button>
            </div>

            {analysisResult && (
              <div className="analysis-result">
                <h3>🛡️ Security Analysis</h3>
                <div className="analysis-content">
                  {analysisResult.analysis}
                </div>
                <p className="timestamp">Analyzed at {analysisResult.timestamp}</p>
              </div>
            )}
          </div>
        )}
      </main>

      <footer className="footer">
        <p>SecDetect AI • GenAI-Powered Detection Engineering Platform</p>
      </footer>
    </div>
  );
}

export default App;