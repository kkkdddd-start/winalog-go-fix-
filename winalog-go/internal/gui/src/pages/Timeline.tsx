import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { timelineAPI, TimelineEntry, TimelineResponse } from '../api'

function Timeline() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [entries, setEntries] = useState<TimelineEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'events' | 'alerts'>('all')
  const [startDate, setStartDate] = useState('')
  const [startTime, setStartTime] = useState('')
  const [endDate, setEndDate] = useState('')
  const [endTime, setEndTime] = useState('')

  const fetchTimeline = () => {
    setLoading(true)
    
    let startTimeISO: string | undefined
    let endTimeISO: string | undefined
    
    if (startDate && startTime) {
      startTimeISO = new Date(`${startDate}T${startTime}:00Z`).toISOString()
    } else if (startDate) {
      startTimeISO = new Date(`${startDate}T00:00:00Z`).toISOString()
    }
    
    if (endDate && endTime) {
      endTimeISO = new Date(`${endDate}T${endTime}:59Z`).toISOString()
    } else if (endDate) {
      endTimeISO = new Date(`${endDate}T23:59:59Z`).toISOString()
    }
    
    timelineAPI.get(1000, startTimeISO, endTimeISO)
      .then(res => {
        const data = res.data as TimelineResponse
        setEntries(data.entries || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  useEffect(() => {
    fetchTimeline()
  }, [])

  const handleApplyFilter = () => {
    fetchTimeline()
  }

  const handleClearFilter = () => {
    setStartDate('')
    setStartTime('')
    setEndDate('')
    setEndTime('')
    fetchTimeline()
  }

  const getTypeIcon = (type_: string, severity?: string) => {
    if (type_ === 'alert') {
      switch (severity) {
        case 'critical': return '🔴'
        case 'high': return '🟠'
        case 'medium': return '🟡'
        case 'low': return '🟢'
        default: return '⚪'
      }
    }
    return '📋'
  }

  const getTypeColor = (type_: string, severity?: string) => {
    if (type_ === 'alert') {
      switch (severity) {
        case 'critical': return '#ef4444'
        case 'high': return '#f97316'
        case 'medium': return '#eab308'
        case 'low': return '#22c55e'
        default: return '#888'
      }
    }
    return '#00d9ff'
  }

  const getTypeLabel = (type_: string) => {
    return type_ === 'alert' ? 'ALERT' : 'EVENT'
  }

  const filteredEntries = entries.filter(entry => {
    if (filter === 'all') return true
    if (filter === 'events') return entry.type === 'event'
    if (filter === 'alerts') return entry.type === 'alert'
    return true
  })

  const filteredStats = {
    eventCount: filteredEntries.filter(e => e.type === 'event').length,
    alertCount: filteredEntries.filter(e => e.type === 'alert').length,
  }

  const handleDeleteAlert = (id: number) => {
    timelineAPI.deleteAlert(id)
      .then(() => {
        setEntries(entries.filter(e => !(e.type === 'alert' && e.alert_id === id)))
      })
      .catch(err => console.error('Failed to delete alert:', err))
  }

  if (loading) {
    return (
      <div className="timeline-page">
        <div className="loading-state">
          <div className="loading-spinner"></div>
          <p>{t('common.loading')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="timeline-page">
      <div className="page-header">
        <div className="header-left">
          <h2>{t('timeline.title')}</h2>
          <p className="header-desc">{t('timeline.pageDesc')}</p>
        </div>
        <div className="header-actions">
          <button className="btn-secondary" onClick={() => navigate('/analyze')}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.35-4.35"/>
            </svg>
            {t('timeline.runAnalysis')}
          </button>
        </div>
      </div>

      <div className="timeline-stats-cards">
        <div className="stat-card events">
          <div className="stat-icon">📋</div>
          <div className="stat-content">
            <span className="stat-value">{filteredStats.eventCount}</span>
            <span className="stat-label">{t('timeline.totalEvents')}</span>
          </div>
          <div className="stat-bar">
            <div 
              className="stat-bar-fill events" 
              style={{ width: `${filteredStats.eventCount + filteredStats.alertCount > 0 ? (filteredStats.eventCount / (filteredStats.eventCount + filteredStats.alertCount)) * 100 : 0}%` }}
            />
          </div>
        </div>
        <div className="stat-card alerts">
          <div className="stat-icon">🚨</div>
          <div className="stat-content">
            <span className="stat-value">{filteredStats.alertCount}</span>
            <span className="stat-label">{t('timeline.totalAlerts')}</span>
          </div>
          <div className="stat-bar">
            <div 
              className="stat-bar-fill alerts" 
              style={{ width: `${filteredStats.alertCount > 0 ? (filteredStats.alertCount / (filteredStats.eventCount + filteredStats.alertCount)) * 100 : 0}%` }}
            />
          </div>
        </div>
        <div className="stat-card ratio">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <span className="stat-value">
              {filteredStats.eventCount + filteredStats.alertCount > 0 
                ? ((filteredStats.alertCount / (filteredStats.eventCount + filteredStats.alertCount)) * 100).toFixed(1)
                : 0}%
            </span>
            <span className="stat-label">{t('timeline.alertRatio')}</span>
          </div>
        </div>
      </div>

      <div className="timeline-toolbar">
        <div className="toolbar-left">
          <div className="filter-tabs">
            <button 
              className={`filter-tab ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
            >
              {t('timeline.all')}
              <span className="count">{filteredStats.eventCount + filteredStats.alertCount}</span>
            </button>
            <button 
              className={`filter-tab ${filter === 'events' ? 'active' : ''}`}
              onClick={() => setFilter('events')}
            >
              {t('timeline.eventsOnly')}
              <span className="count events">{filteredStats.eventCount}</span>
            </button>
            <button 
              className={`filter-tab ${filter === 'alerts' ? 'active' : ''}`}
              onClick={() => setFilter('alerts')}
            >
              {t('timeline.alertsOnly')}
              <span className="count alerts">{filteredStats.alertCount}</span>
            </button>
          </div>
        </div>
        <div className="toolbar-right">
          <div className="datetime-filter">
            <input
              type="date"
              value={startDate}
              onChange={e => setStartDate(e.target.value)}
              placeholder="Start date"
            />
            <input
              type="time"
              value={startTime}
              onChange={e => setStartTime(e.target.value)}
              placeholder="Start time"
            />
            <span className="datetime-separator">-</span>
            <input
              type="date"
              value={endDate}
              onChange={e => setEndDate(e.target.value)}
              placeholder="End date"
            />
            <input
              type="time"
              value={endTime}
              onChange={e => setEndTime(e.target.value)}
              placeholder="End time"
            />
            <button className="btn-apply-filter" onClick={handleApplyFilter}>
              {t('common.apply')}
            </button>
            <button className="btn-clear-filter" onClick={handleClearFilter}>
              {t('common.clear')}
            </button>
          </div>
        </div>
      </div>

      <div className="timeline-container">
        {filteredEntries.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">📭</span>
            <p>{t('timeline.noEntries')}</p>
          </div>
        ) : (
          <div className="timeline">
            {filteredEntries.map((entry, idx) => (
              <div 
                key={`${entry.type}-${entry.id}-${idx}`} 
                className={`timeline-item ${entry.type}`}
              >
                <div className="timeline-marker" style={{ '--marker-color': getTypeColor(entry.type, entry.severity) } as React.CSSProperties}>
                  <div className="marker-dot"></div>
                  <div className="marker-line"></div>
                </div>
                <div className="timeline-card">
                  <div className="card-header">
                    <div className="card-left">
                      <span className="card-icon">{getTypeIcon(entry.type, entry.severity)}</span>
                      <span 
                        className={`timeline-type ${entry.type}`}
                        style={{ color: getTypeColor(entry.type, entry.severity) }}
                      >
                        {getTypeLabel(entry.type)}
                      </span>
                      {entry.type === 'event' && entry.event_id && (
                        <span className="event-id-badge">Event {entry.event_id}</span>
                      )}
                      {entry.type === 'event' && entry.computer && (
                        <span className="computer-badge">{entry.computer}</span>
                      )}
                      {entry.type === 'alert' && entry.severity && (
                        <span 
                          className={`severity-badge ${entry.severity}`}
                          style={{ background: `${getTypeColor(entry.type, entry.severity)}20`, color: getTypeColor(entry.type, entry.severity) }}
                        >
                          {entry.severity.toUpperCase()}
                        </span>
                      )}
                    </div>
                    <span className="card-time">
                      {new Date(entry.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <p className="card-message">{entry.message}</p>
                  {entry.type === 'alert' && entry.rule_name && (
                    <div className="card-meta">
                      <span className="rule-badge">
                        <span className="rule-icon">📌</span>
                        {entry.rule_name}
                      </span>
                      {entry.mitre_attack && entry.mitre_attack.length > 0 && (
                        <span className="mitre-badge">
                          <span className="mitre-icon">🎯</span>
                          {entry.mitre_attack.join(', ')}
                        </span>
                      )}
                    </div>
                  )}
                  {entry.type === 'alert' && entry.alert_id && (
                    <div className="card-actions">
                      <button 
                        className="btn-detail"
                        onClick={() => navigate(`/alerts/${entry.alert_id}`)}
                      >
                        {t('timeline.viewDetails')}
                      </button>
                      <button 
                        className="btn-delete"
                        onClick={() => entry.alert_id && handleDeleteAlert(entry.alert_id)}
                      >
                        {t('timeline.delete')}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default Timeline