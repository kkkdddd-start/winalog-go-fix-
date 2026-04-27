import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { alertsAPI } from '../api'

interface Alert {
  id: number
  rule_name: string
  severity: string
  message: string
  count: number
  resolved: boolean
  first_seen: string
  last_seen: string
}

interface ListResponse {
  alerts: Alert[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

interface RunAnalysisResponse {
  success: boolean
  alerts_created: number
  events_analyzed: number
  rules_executed: number
  duration: string
  errors?: string[]
}

function Alerts() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [page, _setPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState('')
  const [selectedAlerts, setSelectedAlerts] = useState<number[]>([])
  const [showAnalyzeModal, setShowAnalyzeModal] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [analysisResult, setAnalysisResult] = useState<RunAnalysisResponse | null>(null)

  useEffect(() => {
    setLoading(true)
    alertsAPI.list(page, 100, severityFilter || undefined)
      .then(res => {
        const data = res.data as ListResponse
        setAlerts(data.alerts || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [page, severityFilter])

  const handleResolve = (id: number) => {
    alertsAPI.resolve(id, 'Resolved via Web UI')
      .then(() => {
        setAlerts(alerts.map(a => 
          a.id === id ? { ...a, resolved: true } : a
        ))
      })
  }

  const handleMarkFalsePositive = (id: number) => {
    const reason = window.prompt(t('alerts.falsePositiveReason') || 'Enter reason for marking as false positive:')
    if (!reason) return
    alertsAPI.markFalsePositive(id, reason)
      .then(() => {
        setAlerts(alerts.filter(a => a.id !== id))
        setSelectedAlerts(prev => prev.filter(i => i !== id))
      })
      .catch(err => {
        console.error('Failed to mark as false positive:', err)
      })
  }

  const handleDelete = (id: number) => {
    if (!confirm(t('alerts.confirmDelete'))) return
    alertsAPI.delete(id)
      .then(() => {
        setAlerts(alerts.filter(a => a.id !== id))
        setSelectedAlerts(prev => prev.filter(i => i !== id))
      })
      .catch(err => {
        console.error('Failed to delete alert:', err)
      })
  }

  const handleBatchAction = (action: string) => {
    if (selectedAlerts.length === 0) return
    alertsAPI.batchAction(selectedAlerts, action)
      .then(() => {
        if (action === 'resolve') {
          setAlerts(alerts.map(a => 
            selectedAlerts.includes(a.id) ? { ...a, resolved: true } : a
          ))
        } else if (action === 'delete') {
          setAlerts(alerts.filter(a => !selectedAlerts.includes(a.id)))
        }
        setSelectedAlerts([])
      })
      .catch(err => {
        console.error('Batch action failed:', err)
      })
  }

  const handleSelectAlert = (id: number) => {
    setSelectedAlerts(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    )
  }

  const handleSelectAll = () => {
    if (selectedAlerts.length === alerts.length) {
      setSelectedAlerts([])
    } else {
      setSelectedAlerts(alerts.map(a => a.id))
    }
  }

  const handleBatchResolve = async () => {
    try {
      await Promise.all(
        selectedAlerts.map(id =>
          alertsAPI.resolve(id, 'Batch resolved via Web UI')
        )
      )
      setAlerts(alerts.map(a =>
        selectedAlerts.includes(a.id) ? { ...a, resolved: true } : a
      ))
      setSelectedAlerts([])
    } catch (err) {
      console.error('Batch resolve failed:', err)
    }
  }

  const handleRunAnalysis = () => {
    setAnalyzing(true)
    setAnalysisResult(null)
    alertsAPI.runAnalysis()
      .then(res => {
        const data = res.data as RunAnalysisResponse
        setAnalysisResult(data)
        setAnalyzing(false)
      })
      .catch(err => {
        console.error('Analysis failed:', err)
        setAnalyzing(false)
        setAnalysisResult({
          success: false,
          alerts_created: 0,
          events_analyzed: 0,
          rules_executed: 0,
          duration: '0s',
          errors: [err.response?.data?.error || 'Analysis failed']
        })
      })
  }

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'critical': return 'severity-critical'
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      case 'low': return 'severity-low'
      default: return ''
    }
  }

  const stats = {
    total: alerts.length,
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
    medium: alerts.filter(a => a.severity === 'medium').length,
    low: alerts.filter(a => a.severity === 'low').length,
  }

  return (
    <div className="alerts-page">
      <div className="page-header">
        <div className="header-left">
          <h2>{t('alerts.title')}</h2>
          <p className="header-desc">{t('alerts.pageDesc')}</p>
        </div>
        <div className="header-actions">
          <button 
            className="btn-analyze"
            onClick={() => setShowAnalyzeModal(true)}
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.35-4.35"/>
              <path d="M11 8v6M8 11h6"/>
            </svg>
            {t('alerts.runAnalysis')}
          </button>
        </div>
      </div>

      <div className="alerts-stats-grid">
        <div className="stat-card" onClick={() => setSeverityFilter('')}>
          <span className="stat-icon">📊</span>
          <div className="stat-info">
            <span className="stat-value">{stats.total}</span>
            <span className="stat-label">{t('alerts.total')}</span>
          </div>
        </div>
        <div className="stat-card critical" onClick={() => setSeverityFilter('critical')}>
          <span className="stat-icon">🔴</span>
          <div className="stat-info">
            <span className="stat-value">{stats.critical}</span>
            <span className="stat-label">{t('dashboard.critical')}</span>
          </div>
        </div>
        <div className="stat-card high" onClick={() => setSeverityFilter('high')}>
          <span className="stat-icon">🟠</span>
          <div className="stat-info">
            <span className="stat-value">{stats.high}</span>
            <span className="stat-label">{t('dashboard.high')}</span>
          </div>
        </div>
        <div className="stat-card medium" onClick={() => setSeverityFilter('medium')}>
          <span className="stat-icon">🟡</span>
          <div className="stat-info">
            <span className="stat-value">{stats.medium}</span>
            <span className="stat-label">{t('dashboard.medium')}</span>
          </div>
        </div>
        <div className="stat-card low" onClick={() => setSeverityFilter('low')}>
          <span className="stat-icon">🟢</span>
          <div className="stat-info">
            <span className="stat-value">{stats.low}</span>
            <span className="stat-label">{t('dashboard.low')}</span>
          </div>
        </div>
      </div>

      <div className="alerts-toolbar">
        <div className="toolbar-left">
          <select 
            className="severity-select"
            value={severityFilter} 
            onChange={e => setSeverityFilter(e.target.value)}
          >
            <option value="">{t('alerts.allSeverities')}</option>
            <option value="critical">{t('dashboard.critical')}</option>
            <option value="high">{t('dashboard.high')}</option>
            <option value="medium">{t('dashboard.medium')}</option>
            <option value="low">{t('dashboard.low')}</option>
          </select>
        </div>
        <div className="toolbar-right">
          {selectedAlerts.length > 0 && (
            <div className="batch-actions">
              <span className="selected-count">{selectedAlerts.length} {t('alerts.selected')}</span>
              <button className="btn-batch-resolve" onClick={handleBatchResolve}>
                {t('alerts.resolveSelected')}
              </button>
              <button className="btn-batch-falsepositive" onClick={() => handleBatchAction('false-positive')}>
                {t('alerts.markFalsePositive')}
              </button>
              <button className="btn-batch-delete" onClick={() => handleBatchAction('delete')}>
                {t('common.delete')}
              </button>
            </div>
          )}
        </div>
      </div>

      {loading ? (
        <div className="loading-state">
          <div className="loading-spinner"></div>
          <p>{t('common.loading')}</p>
        </div>
      ) : (
        <div className="alerts-table-container">
          <table className="alerts-table">
            <thead>
              <tr>
                <th className="checkbox-col">
                  <input 
                    type="checkbox" 
                    checked={selectedAlerts.length === alerts.length && alerts.length > 0}
                    onChange={handleSelectAll}
                  />
                </th>
                <th>ID</th>
                <th>{t('alerts.severity')}</th>
                <th>{t('alerts.rule')}</th>
                <th>{t('alerts.message')}</th>
                <th>{t('alerts.count')}</th>
                <th>{t('alerts.status')}</th>
                <th>{t('alerts.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map(alert => (
                <tr key={alert.id} className={selectedAlerts.includes(alert.id) ? 'selected' : ''}>
                  <td className="checkbox-col">
                    <input 
                      type="checkbox" 
                      checked={selectedAlerts.includes(alert.id)}
                      onChange={() => handleSelectAlert(alert.id)}
                    />
                  </td>
                  <td className="id-col">{alert.id}</td>
                  <td>
                    <span className={`badge ${getSeverityClass(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="rule-col">{alert.rule_name}</td>
                  <td className="message-col">{alert.message?.substring(0, 100)}...</td>
                  <td className="count-col">{alert.count}</td>
                  <td>
                    <span className={`status-badge ${alert.resolved ? 'resolved' : 'active'}`}>
                      {alert.resolved ? t('alerts.resolved') : t('alerts.active')}
                    </span>
                  </td>
                  <td className="actions-col">
                    <button 
                      className="btn-action btn-detail"
                      onClick={() => navigate(`/alerts/${alert.id}`)}
                    >
                      {t('alerts.detail')}
                    </button>
                    {!alert.resolved && (
                      <button 
                        className="btn-action btn-resolve"
                        onClick={() => handleResolve(alert.id)}
                      >
                        {t('alerts.resolve')}
                      </button>
                    )}
                    <button 
                      className="btn-action btn-falsepositive"
                      onClick={() => handleMarkFalsePositive(alert.id)}
                    >
                      {t('alerts.falsePositive')}
                    </button>
                    <button 
                      className="btn-action btn-delete"
                      onClick={() => handleDelete(alert.id)}
                    >
                      {t('common.delete')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {alerts.length === 0 && (
            <div className="empty-state">
              <span className="empty-icon">🛡️</span>
              <p>{t('alerts.noAlerts')}</p>
            </div>
          )}
        </div>
      )}

      {showAnalyzeModal && (
        <div className="modal-overlay" onClick={() => { setShowAnalyzeModal(false); setAnalysisResult(null); }}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{t('alerts.runAnalysis')}</h3>
              <button className="close-btn" onClick={() => { setShowAnalyzeModal(false); setAnalysisResult(null); }}>×</button>
            </div>
            <div className="modal-body">
              {!analyzing && !analysisResult && (
                <>
                  <p className="modal-desc">{t('alerts.analysisDesc')}</p>
                  <div className="analysis-summary">
                    <h4>{t('alerts.analysisSummary')}</h4>
                    <ul>
                      <li>{t('alerts.analysisTarget')}: {t('alerts.allEvents')}</li>
                      <li>{t('alerts.analysisScope')}: {t('alerts.allEnabledRules')}</li>
                    </ul>
                  </div>
                  <div className="modal-actions">
                    <button className="btn-cancel" onClick={() => { setShowAnalyzeModal(false); setAnalysisResult(null); }}>
                      {t('common.cancel')}
                    </button>
                    <button className="btn-primary" onClick={handleRunAnalysis}>
                      <>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <polygon points="5 3 19 12 5 21 5 3"/>
                        </svg>
                        {t('alerts.startAnalysis')}
                      </>
                    </button>
                  </div>
                </>
              )}

              {analyzing && (
                <div className="analyzing-state">
                  <div className="analyzing-spinner"></div>
                  <p>{t('alerts.analyzing')}</p>
                  <p className="analyzing-hint">{t('alerts.analyzingHint')}</p>
                </div>
              )}

              {analysisResult && (
                <div className="analysis-result">
                  <div className={`result-header ${analysisResult.success ? 'success' : 'error'}`}>
                    {analysisResult.success ? '✓' : '✗'} {analysisResult.success ? t('alerts.analysisComplete') : t('alerts.analysisFailed')}
                  </div>
                  <div className="result-stats">
                    <div className="result-stat">
                      <span className="stat-label">{t('alerts.alertsCreated')}</span>
                      <span className="stat-value">{analysisResult.alerts_created}</span>
                    </div>
                    <div className="result-stat">
                      <span className="stat-label">{t('alerts.eventsAnalyzed')}</span>
                      <span className="stat-value">{analysisResult.events_analyzed}</span>
                    </div>
                    <div className="result-stat">
                      <span className="stat-label">{t('alerts.rulesExecuted')}</span>
                      <span className="stat-value">{analysisResult.rules_executed}</span>
                    </div>
                    <div className="result-stat">
                      <span className="stat-label">{t('alerts.duration')}</span>
                      <span className="stat-value">{analysisResult.duration}</span>
                    </div>
                  </div>
                  {analysisResult.errors && analysisResult.errors.length > 0 && (
                    <div className="result-errors">
                      <h4>{t('alerts.errors')}:</h4>
                      <ul>
                        {analysisResult.errors.map((err, i) => (
                          <li key={i}>{err}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="modal-actions">
                    <button className="btn-primary" onClick={() => { setShowAnalyzeModal(false); setAnalysisResult(null); navigate('/alerts'); }}>
                      {t('common.done')}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Alerts