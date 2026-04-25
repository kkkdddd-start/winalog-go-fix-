import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { correlationAPI, CorrelationResult } from '../api'

const severityColors: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  info: '#2563eb',
}

const tacticIcons: Record<string, string> = {
  ' Lateral Movement': '🔄',
  ' Privilege Escalation': '⬆️',
  ' Credential Access': '🔑',
  ' Execution': '⚡',
  ' Persistence': '📌',
  ' Defense Evasion': '🛡️',
  ' Collection': '📂',
  ' Exfiltration': '📤',
  ' Impact': '💥',
}

function Correlation() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<CorrelationResult[]>([])
  const [timeWindow, setTimeWindow] = useState('24h')
  const [error, setError] = useState('')
  const [hasRun, setHasRun] = useState(false)
  const [expandedCard, setExpandedCard] = useState<number | null>(null)

  const timeWindows = [
    { value: '1h', label: '1h' },
    { value: '6h', label: '6h' },
    { value: '24h', label: '24h' },
    { value: '72h', label: '72h' },
    { value: '168h', label: '7d' },
  ]

  const handleAnalyze = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await correlationAPI.analyze({ time_window: timeWindow })
      setResults(res.data.results || [])
      setHasRun(true)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to run correlation analysis')
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    return severityColors[severity.toLowerCase()] || severityColors.info
  }

  const getSeverityLabel = (severity: string) => {
    const labels: Record<string, string> = {
      critical: t('severity.critical') || 'Critical',
      high: t('severity.high') || 'High',
      medium: t('severity.medium') || 'Medium',
      low: t('severity.low') || 'Low',
      info: t('severity.info') || 'Info',
    }
    return labels[severity.toLowerCase()] || severity
  }

  const getTacticIcon = (description: string) => {
    for (const [key, icon] of Object.entries(tacticIcons)) {
      if (description.includes(key)) return icon
    }
    return '🎯'
  }

  const formatTime = (timeStr: string) => {
    try {
      return new Date(timeStr).toLocaleString()
    } catch {
      return timeStr
    }
  }

  const formatDuration = (start: string, end: string) => {
    try {
      const startTime = new Date(start).getTime()
      const endTime = new Date(end).getTime()
      const durationMs = endTime - startTime
      const seconds = Math.floor(durationMs / 1000)
      const minutes = Math.floor(seconds / 60)
      const hours = Math.floor(minutes / 60)
      
      if (hours > 0) return `${hours}h ${minutes % 60}m`
      if (minutes > 0) return `${minutes}m ${seconds % 60}s`
      return `${seconds}s`
    } catch {
      return 'N/A'
    }
  }

  const stats = useMemo(() => {
    if (results.length === 0) return null
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
    results.forEach(r => {
      const s = r.severity.toLowerCase()
      if (severityCounts.hasOwnProperty(s)) severityCounts[s as keyof typeof severityCounts]++
    })
    return {
      totalEvents: results.reduce((sum, r) => sum + r.event_count, 0),
      severityCounts,
      avgEventsPerRule: Math.round(results.reduce((sum, r) => sum + r.event_count, 0) / results.length),
    }
  }, [results])

  const attackChainVisual = useMemo(() => {
    if (results.length === 0) return []
    const maxEvents = Math.max(...results.map(r => r.event_count))
    return results.map(r => {
      const barLength = Math.round((r.event_count / maxEvents) * 20)
      return {
        ...r,
        bar: '█'.repeat(barLength) + '░'.repeat(20 - barLength),
      }
    })
  }, [results])

  return (
    <div className="correlation-page">
      <div className="page-header">
        <h2>{t('correlation.title')}</h2>
        <p className="page-desc">{t('correlation.pageDesc')}</p>
      </div>

      <div className="correlation-toolbar">
        <div className="toolbar-section">
          <label>{t('correlation.timeWindow')}</label>
          <div className="time-selector">
            {timeWindows.map(tw => (
              <button
                key={tw.value}
                className={timeWindow === tw.value ? 'active' : ''}
                onClick={() => setTimeWindow(tw.value)}
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
              {t('correlation.analyzing')}
            </>
          ) : (
            <>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <path d="M21 21l-4.35-4.35"/>
              </svg>
              {t('correlation.runAnalysis')}
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

      {hasRun && !loading && results.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <h3>{t('correlation.noResults')}</h3>
          <p>{t('correlation.noResultsDesc')}</p>
        </div>
      )}

      {stats && (
        <div className="correlation-stats">
          <div className="stat-card">
            <span className="stat-icon">📊</span>
            <div className="stat-content">
              <span className="stat-value">{results.length}</span>
              <span className="stat-label">{t('correlation.rulesTriggered')}</span>
            </div>
          </div>
          <div className="stat-card">
            <span className="stat-icon">📝</span>
            <div className="stat-content">
              <span className="stat-value">{stats.totalEvents.toLocaleString()}</span>
              <span className="stat-label">{t('correlation.totalEvents')}</span>
            </div>
          </div>
          <div className="stat-card critical">
            <span className="stat-icon">🔴</span>
            <div className="stat-content">
              <span className="stat-value">{stats.severityCounts.critical}</span>
              <span className="stat-label">{t('severity.critical')}</span>
            </div>
          </div>
          <div className="stat-card high">
            <span className="stat-icon">🟠</span>
            <div className="stat-content">
              <span className="stat-value">{stats.severityCounts.high}</span>
              <span className="stat-label">{t('severity.high')}</span>
            </div>
          </div>
        </div>
      )}

      {attackChainVisual.length > 0 && (
        <div className="attack-chain-visual">
          <h3>{t('correlation.attackChainTimeline')}</h3>
          <div className="chain-bars">
            {attackChainVisual.map((item, index) => (
              <div key={index} className="chain-bar-item">
                <div className="chain-bar-header">
                  <span className="chain-icon">{getTacticIcon(item.description)}</span>
                  <span className="chain-name">{item.rule_name}</span>
                  <span 
                    className="chain-severity-dot"
                    style={{ backgroundColor: getSeverityColor(item.severity) }}
                  />
                </div>
                <div className="chain-bar-track">
                  <span className="chain-bar-fill" 
                    style={{ 
                      width: `${(item.event_count / stats!.totalEvents) * 100}%`,
                      backgroundColor: getSeverityColor(item.severity)
                    }}
                  />
                </div>
                <div className="chain-bar-meta">
                  <span className="chain-events">{item.event_count} events</span>
                  <span className="chain-duration">{formatDuration(item.start_time, item.end_time)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className="correlation-results">
          <div className="results-header">
            <h3>{t('correlation.results')}</h3>
            <span className="results-count">{results.length} {t('correlation.rulesTriggered')}</span>
          </div>

          <div className="results-grid">
            {results.map((result, index) => (
              <div 
                key={index} 
                className={`correlation-card ${expandedCard === index ? 'expanded' : ''}`}
                onClick={() => setExpandedCard(expandedCard === index ? null : index)}
              >
                <div className="card-header">
                  <div className="rule-info">
                    <span 
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(result.severity) }}
                    >
                      {getSeverityLabel(result.severity)}
                    </span>
                    <h4>{result.rule_name}</h4>
                  </div>
                  <div className="event-count">
                    <span className="count-value">{result.event_count}</span>
                    <span className="count-label">{t('correlation.events')}</span>
                  </div>
                </div>

                <div className="card-icon">{getTacticIcon(result.description)}</div>
                <p className="rule-description">{result.description}</p>

                <div className="card-footer">
                  <div className="time-info">
                    <div className="time-range">
                      <span className="time-label">{t('correlation.startTime')}:</span>
                      <span className="time-value">{formatTime(result.start_time)}</span>
                    </div>
                    <div className="time-range">
                      <span className="time-label">{t('correlation.endTime')}:</span>
                      <span className="time-value">{formatTime(result.end_time)}</span>
                    </div>
                  </div>
                  <div className="duration-badge">
                    ⏱️ {formatDuration(result.start_time, result.end_time)}
                  </div>
                </div>

                {expandedCard === index && (
                  <div className="card-expanded">
                    <div className="expanded-section">
                      <h5>{t('correlation.attackPattern')}</h5>
                      <div className="pattern-visual">
                        <span className="pattern-icon">🎯</span>
                        <span className="pattern-text">{result.rule_name}</span>
                        <span className="pattern-arrow">→</span>
                        <span className="pattern-target">{getSeverityLabel(result.severity)} Risk</span>
                      </div>
                    </div>
                    <div className="expanded-actions">
                      <button 
                        className="action-btn"
                        onClick={(e) => {
                          e.stopPropagation()
                          navigate('/timeline')
                        }}
                      >
                        📊 {t('correlation.viewTimeline')}
                      </button>
                      <button 
                        className="action-btn"
                        onClick={(e) => {
                          e.stopPropagation()
                          navigate('/alerts')
                        }}
                      >
                        🔔 {t('correlation.viewAlerts')}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="correlation-info">
        <div className="section-header">
          <h3>{t('correlation.aboutCorrelation')}</h3>
        </div>
        <div className="info-content">
          <p>{t('correlation.aboutDesc')}</p>
        </div>
      </div>

      <div className="quick-actions">
        <h4>{t('correlation.quickActions')}</h4>
        <div className="quick-buttons">
          <button 
            className="quick-btn"
            onClick={() => navigate('/timeline')}
          >
            📊 {t('correlation.viewTimeline')}
          </button>
          <button 
            className="quick-btn"
            onClick={() => navigate('/alerts')}
          >
            🔔 {t('correlation.viewAlerts')}
          </button>
          <button 
            className="quick-btn"
            onClick={() => navigate('/analyze')}
          >
            ⚡ {t('correlation.runAnalyzers')}
          </button>
        </div>
      </div>
    </div>
  )
}

export default Correlation
