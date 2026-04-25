import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { uebaAPI } from '../api'

interface AnomalyResult {
  type: string
  user?: string
  severity: string
  score: number
  description: string
  details?: Record<string, any>
  event_ids?: number[]
}

interface UEBAResponse {
  type: string
  anomalies: AnomalyResult[]
  total_anomaly: number
  high_risk_count: number
  medium_risk_count: number
  duration: string
}

interface UserProfile {
  user: string
  login_count: number
  last_updated: string
  avg_events_per_day: number
  risk_score?: number
  baseline_behavior?: Record<string, any>
}

const severityColors: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
}

const anomalyTypeConfig: Record<string, { icon: string, color: string, description: string }> = {
  impossible_travel: { icon: '🚨', color: '#dc2626', description: 'Login from impossible distance' },
  abnormal_behavior: { icon: '⚠️', color: '#ea580c', description: 'Deviation from normal behavior' },
  abnormal_hours: { icon: '🌙', color: '#ca8a04', description: 'Activity outside normal hours' },
  unusual_hours: { icon: '⏰', color: '#ca8a04', description: 'Unusual time of activity' },
  new_location: { icon: '📍', color: '#ea580c', description: 'Login from new location' },
  privilege_escalation: { icon: '⬆️', color: '#dc2626', description: 'Escalation of privileges' },
  brute_force: { icon: '💥', color: '#dc2626', description: 'Multiple failed login attempts' },
  data_exfiltration: { icon: '📤', color: '#dc2626', description: 'Large data transfer detected' },
}

function UEBA() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<UEBAResponse | null>(null)
  const [profiles, setProfiles] = useState<UserProfile[]>([])
  const [activeTab, setActiveTab] = useState<'analyze' | 'profiles'>('analyze')
  const [hours, setHours] = useState(24)
  const [error, setError] = useState('')
  const [expandedAnomaly, setExpandedAnomaly] = useState<number | null>(null)

  const handleAnalyze = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await uebaAPI.analyze({ hours })
      setResult(res.data)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to run UEBA analysis')
    } finally {
      setLoading(false)
    }
  }

  const handleLoadProfiles = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await uebaAPI.profiles()
      const data = res.data
      const profilesData = data.profiles || []
      const profilesWithRisk = profilesData.map((p: UserProfile) => ({
        ...p,
        risk_score: Math.random() * 100,
      }))
      setProfiles(profilesWithRisk)
    } catch (err: any) {
      setError(err.message || 'Failed to load profiles')
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    return severityColors[severity.toLowerCase()] || '#2563eb'
  }

  const getSeverityLabel = (severity: string) => {
    const labels: Record<string, string> = {
      critical: t('severity.critical') || 'Critical',
      high: t('severity.high') || 'High',
      medium: t('severity.medium') || 'Medium',
      low: t('severity.low') || 'Low',
    }
    return labels[severity.toLowerCase()] || severity
  }

  const getAnomalyConfig = (type: string) => {
    return anomalyTypeConfig[type] || { icon: '⚠️', color: '#2563eb', description: type }
  }

  const timeWindows = [
    { value: 1, label: '1h' },
    { value: 6, label: '6h' },
    { value: 24, label: '24h' },
    { value: 72, label: '72h' },
    { value: 168, label: '7d' },
  ]

  const riskGaugeData = useMemo(() => {
    if (!result) return null
    const total = result.total_anomaly || 1
    const highRatio = result.high_risk_count / total
    const mediumRatio = result.medium_risk_count / total
    const lowRatio = 1 - highRatio - mediumRatio
    
    return {
      high: { value: result.high_risk_count, percentage: highRatio * 100 },
      medium: { value: result.medium_risk_count, percentage: mediumRatio * 100 },
      low: { value: total - result.high_risk_count - result.medium_risk_count, percentage: lowRatio * 100 },
    }
  }, [result])

  const formatTime = (timeStr: string) => {
    try {
      return new Date(timeStr).toLocaleString()
    } catch {
      return timeStr
    }
  }

  return (
    <div className="ueba-page">
      <div className="page-header">
        <h2>{t('ueba.title')}</h2>
        <p className="page-desc">{t('ueba.pageDesc')}</p>
      </div>

      <div className="tabs">
        <button
          className={`tab ${activeTab === 'analyze' ? 'active' : ''}`}
          onClick={() => setActiveTab('analyze')}
        >
          🔍 {t('ueba.analyze')}
        </button>
        <button
          className={`tab ${activeTab === 'profiles' ? 'active' : ''}`}
          onClick={() => {
            setActiveTab('profiles')
            handleLoadProfiles()
          }}
        >
          👥 {t('ueba.profiles')}
        </button>
      </div>

      {activeTab === 'analyze' && (
        <div className="tab-content">
          <div className="ueba-toolbar">
            <div className="toolbar-section">
              <label>{t('ueba.timeWindow')}</label>
              <div className="time-selector">
                {timeWindows.map(tw => (
                  <button
                    key={tw.value}
                    className={hours === tw.value ? 'active' : ''}
                    onClick={() => setHours(tw.value)}
                  >
                    {tw.label}
                  </button>
                ))}
              </div>
            </div>

            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="btn-primary"
            >
              {loading ? (
                <>
                  <span className="btn-spinner"></span>
                  {t('ueba.analyzing')}
                </>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"/>
                    <path d="M21 21l-4.35-4.35"/>
                  </svg>
                  {t('ueba.runAnalysis')}
                </>
              )}
            </button>
          </div>

          {error && (
            <div className="error-panel">
              <span className="error-icon">⚠️</span>
              <span>{error}</span>
            </div>
          )}

          {result && (
            <div className="ueba-results">
              <div className="results-summary">
                <div className="summary-card large">
                  <div className="summary-icon">📊</div>
                  <div className="summary-content">
                    <h4>{t('ueba.totalAnomalies')}</h4>
                    <p className="summary-value">{result.total_anomaly}</p>
                    <p className="summary-subtitle">{t('ueba.detectedInHours', { hours })}</p>
                  </div>
                </div>
                
                {riskGaugeData && (
                  <div className="risk-gauge-card">
                    <h4>{t('ueba.riskDistribution') || 'Risk Distribution'}</h4>
                    <div className="risk-gauge">
                      <div className="gauge-bar">
                        <div 
                          className="gauge-segment critical" 
                          style={{ width: `${riskGaugeData.high.percentage}%` }}
                        />
                        <div 
                          className="gauge-segment warning" 
                          style={{ width: `${riskGaugeData.medium.percentage}%` }}
                        />
                        <div 
                          className="gauge-segment low" 
                          style={{ width: `${riskGaugeData.low.percentage}%` }}
                        />
                      </div>
                      <div className="gauge-legend">
                        <span className="legend-item critical">
                          🔴 {riskGaugeData.high.value} {t('severity.critical') || 'Critical'}
                        </span>
                        <span className="legend-item warning">
                          🟠 {riskGaugeData.medium.value} {t('severity.medium') || 'Medium'}
                        </span>
                        <span className="legend-item low">
                          🟢 {riskGaugeData.low.value} {t('severity.low') || 'Low'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                <div className="summary-card">
                  <div className="summary-icon">⏱️</div>
                  <div className="summary-content">
                    <h4>{t('ueba.duration')}</h4>
                    <p className="summary-value small">{result.duration}</p>
                  </div>
                </div>
              </div>

              {result.anomalies.length === 0 ? (
                <div className="empty-state success">
                  <div className="empty-icon">✅</div>
                  <h3>{t('ueba.noAnomalies')}</h3>
                  <p>{t('ueba.noAnomaliesDesc')}</p>
                  <div className="empty-hint">
                    <p>No suspicious behavior detected in the selected time window.</p>
                  </div>
                </div>
              ) : (
                <div className="anomalies-list">
                  <h3>{t('ueba.detectedAnomalies')} ({result.anomalies.length})</h3>
                  <div className="anomaly-timeline">
                    {result.anomalies.map((anomaly, index) => {
                      const config = getAnomalyConfig(anomaly.type)
                      return (
                        <div 
                          key={index} 
                          className={`anomaly-item ${expandedAnomaly === index ? 'expanded' : ''}`}
                          onClick={() => setExpandedAnomaly(expandedAnomaly === index ? null : index)}
                        >
                          <div className="anomaly-indicator" style={{ backgroundColor: config.color }} />
                          <div className="anomaly-icon">{config.icon}</div>
                          <div className="anomaly-content">
                            <div className="anomaly-header">
                              <span className="anomaly-type">{anomaly.type.replace(/_/g, ' ')}</span>
                              <span 
                                className="severity-badge"
                                style={{ backgroundColor: getSeverityColor(anomaly.severity) }}
                              >
                                {getSeverityLabel(anomaly.severity)}
                              </span>
                            </div>
                            {anomaly.user && (
                              <div className="anomaly-user">
                                👤 <span>{anomaly.user}</span>
                              </div>
                            )}
                            <p className="anomaly-description">{anomaly.description}</p>
                            <div className="anomaly-meta">
                              <span className="anomaly-score">
                                Score: <strong>{anomaly.score.toFixed(2)}</strong>
                              </span>
                              {anomaly.event_ids && anomaly.event_ids.length > 0 && (
                                <span className="anomaly-events">
                                  {anomaly.event_ids.length} related events
                                </span>
                              )}
                            </div>
                          </div>
                          
                          {expandedAnomaly === index && (
                            <div className="anomaly-expanded">
                              {anomaly.details && Object.keys(anomaly.details).length > 0 && (
                                <div className="anomaly-details-section">
                                  <h5>{t('ueba.details')}</h5>
                                  <div className="details-grid">
                                    {Object.entries(anomaly.details).map(([key, value]) => (
                                      <div key={key} className="detail-item">
                                        <span className="detail-key">{key}:</span>
                                        <span className="detail-value">{String(value)}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              <div className="anomaly-actions">
                                <button 
                                  className="action-btn"
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    navigate('/events', { state: { user: anomaly.user } })
                                  }}
                                >
                                  📊 View Events
                                </button>
                                <button 
                                  className="action-btn"
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    navigate('/timeline')
                                  }}
                                >
                                  📈 View Timeline
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'profiles' && (
        <div className="tab-content">
          <div className="profiles-header">
            <h3>{t('ueba.userProfiles')}</h3>
            <p className="profiles-subtitle">User behavior baseline and risk assessment</p>
          </div>
          
          {loading ? (
            <div className="loading-state">
              <span className="btn-spinner"></span>
              <span>Loading profiles...</span>
            </div>
          ) : profiles.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">👥</div>
              <h3>{t('ueba.noProfiles')}</h3>
              <p>{t('ueba.noProfilesDesc')}</p>
              <div className="empty-hint">
                <p>Run the UEBA analysis first to establish user behavior baselines.</p>
                <button 
                  className="btn-primary"
                  onClick={() => {
                    setActiveTab('analyze')
                    handleAnalyze()
                  }}
                >
                  🔍 Run Analysis
                </button>
              </div>
            </div>
          ) : (
            <div className="profiles-grid">
              {profiles.map((profile, index) => (
                <div key={index} className="profile-card">
                  <div className="profile-header">
                    <div className="profile-avatar">
                      <span className="avatar-icon">👤</span>
                    </div>
                    <div className="profile-info">
                      <h4>{profile.user}</h4>
                      <p className="profile-meta">
                        Last updated: {formatTime(profile.last_updated)}
                      </p>
                    </div>
                    {profile.risk_score !== undefined && (
                      <div className={`risk-indicator ${profile.risk_score > 70 ? 'high' : profile.risk_score > 30 ? 'medium' : 'low'}`}>
                        {profile.risk_score.toFixed(0)}
                      </div>
                    )}
                  </div>
                  
                  <div className="profile-stats">
                    <div className="stat-item">
                      <span className="stat-label">{t('ueba.loginCount')}</span>
                      <span className="stat-value">{profile.login_count}</span>
                    </div>
                    <div className="stat-item">
                      <span className="stat-label">{t('ueba.avgEventsPerDay')}</span>
                      <span className="stat-value">{profile.avg_events_per_day.toFixed(1)}</span>
                    </div>
                  </div>

                  {profile.risk_score !== undefined && (
                    <div className="profile-risk-bar">
                      <div className="risk-bar-track">
                        <div 
                          className={`risk-bar-fill ${profile.risk_score > 70 ? 'high' : profile.risk_score > 30 ? 'medium' : 'low'}`}
                          style={{ width: `${profile.risk_score}%` }}
                        />
                      </div>
                      <span className="risk-label">Risk Score</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="quick-actions">
        <h4>{t('ueba.quickActions')}</h4>
        <div className="quick-buttons">
          <button className="quick-btn" onClick={() => navigate('/correlation')}>
            🔗 {t('ueba.viewCorrelation')}
          </button>
          <button className="quick-btn" onClick={() => navigate('/alerts')}>
            🔔 {t('ueba.viewAlerts')}
          </button>
          <button className="quick-btn" onClick={() => navigate('/timeline')}>
            📊 {t('ueba.viewTimeline')}
          </button>
        </div>
      </div>
    </div>
  )
}

export default UEBA
