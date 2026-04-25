import { useState, useEffect, useCallback } from 'react'
import { useI18n } from '../locales/I18n'
import { monitorAPI } from '../api'
import { message } from 'antd'

interface MonitorStats {
  is_running: boolean
  process_enabled: boolean
  network_enabled: boolean
  process_count: number
  network_count: number
  alert_count: number
  start_time?: string
}

interface MonitorEvent {
  id: string
  type: 'process' | 'network'
  timestamp: string
  severity: string
  data: Record<string, any>
}

interface MonitorConfig {
  process_enabled?: boolean
  network_enabled?: boolean
  poll_interval?: number
}

const ProcessIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="4" y="4" width="16" height="16" rx="2"/>
    <path d="M9 9h6M9 12h6M9 15h4"/>
  </svg>
)

const NetworkIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10"/>
    <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
  </svg>
)

const AlertIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
    <line x1="12" y1="9" x2="12" y2="13"/>
    <line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
)

const PlayIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <polygon points="5,3 19,12 5,21"/>
  </svg>
)

const StopIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <rect x="4" y="4" width="16" height="16" rx="2"/>
  </svg>
)

const LoadingSpinner = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="spinner">
    <circle cx="12" cy="12" r="10" strokeOpacity="0.3"/>
    <path d="M12 2a10 10 0 0 1 10 10" strokeLinecap="round"/>
  </svg>
)

function Monitor() {
  const { t } = useI18n()
  const [stats, setStats] = useState<MonitorStats | null>(null)
  const [events, setEvents] = useState<MonitorEvent[]>([])
  const [config, setConfig] = useState<MonitorConfig>({
    process_enabled: false,
    network_enabled: false,
    poll_interval: 5,
  })
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'all' | 'process' | 'network'>('all')
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null)
  const [statsError, setStatsError] = useState<string | null>(null)
  const [eventsError, setEventsError] = useState<string | null>(null)

  const fetchStats = useCallback(async () => {
    try {
      const response = await monitorAPI.getStats()
      const backendStats = response.data.stats
      console.log('[MONITOR] fetchStats:', backendStats)
      setStats(backendStats)
      setStatsError(null)
      setConfig({
        process_enabled: backendStats.process_enabled,
        network_enabled: backendStats.network_enabled,
        poll_interval: 5,
      })
    } catch (error: any) {
      const msg = error.response?.status === 404 
        ? 'Monitor stats not available (Windows only feature)' 
        : error.message || 'Failed to fetch stats'
      setStatsError(msg)
      console.error('Failed to fetch stats:', error)
    }
  }, [])

  const fetchEvents = useCallback(async () => {
    try {
      const filter: { type?: string; limit?: number } = { limit: 100 }
      if (activeTab !== 'all') {
        filter.type = activeTab
      }
      const response = await monitorAPI.getEvents(filter)
      setEvents(response.data.events || [])
      setEventsError(null)
    } catch (error: any) {
      const msg = error.response?.status === 404 
        ? 'Monitor events not available (Windows only feature)' 
        : error.message || 'Failed to fetch events'
      setEventsError(msg)
      console.error('Failed to fetch events:', error)
    }
  }, [activeTab])

  useEffect(() => {
    fetchStats()
    const interval = setInterval(fetchStats, 5000)
    return () => clearInterval(interval)
  }, [fetchStats])

  useEffect(() => {
    fetchEvents()
    const interval = setInterval(fetchEvents, 5000)
    return () => clearInterval(interval)
  }, [fetchEvents])

  const handleToggle = async (key: keyof MonitorConfig) => {
    console.log('[MONITOR] handleToggle called:', key, 'current is_running:', stats?.is_running)
    if (!stats?.is_running) {
      console.warn('Cannot toggle: monitor is not running, need to start monitor first')
      message.warning('请先启动监控')
      return
    }
    const newConfig = { ...config, [key]: !config[key as keyof MonitorConfig] }
    const oldConfig = { ...config }
    console.log('[MONITOR] Toggling', key, 'from', oldConfig[key as keyof MonitorConfig], 'to', newConfig[key as keyof MonitorConfig])
    setConfig(newConfig)
    try {
      const response = await monitorAPI.updateConfig(newConfig)
      console.log('[MONITOR] updateConfig success:', response.data)
      fetchStats()
    } catch (error) {
      console.error('Failed to update config:', error)
      setConfig(oldConfig)
      message.error('配置更新失败')
    }
  }

  const handleStartStop = async () => {
    setLoading(true)
    try {
      if (stats?.is_running) {
        await monitorAPI.updateConfig({
          process_enabled: false,
          network_enabled: false,
        })
      }
      await monitorAPI.startStop(stats?.is_running ? 'stop' : 'start')
      fetchStats()
      fetchEvents()
    } catch (error) {
      console.error('Failed to start/stop monitor:', error)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return { bg: 'rgba(239, 68, 68, 0.15)', color: '#ef4444', border: '#ef4444' }
      case 'high': return { bg: 'rgba(249, 115, 22, 0.15)', color: '#f97316', border: '#f97316' }
      case 'medium': return { bg: 'rgba(234, 179, 8, 0.15)', color: '#eab308', border: '#eab308' }
      case 'low': return { bg: 'rgba(34, 197, 94, 0.15)', color: '#22c55e', border: '#22c55e' }
      default: return { bg: 'rgba(107, 114, 128, 0.15)', color: '#6b7280', border: '#6b7280' }
    }
  }

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'process': return <ProcessIcon />
      case 'network': return <NetworkIcon />
      default: return <AlertIcon />
    }
  }

  const filteredEvents = events.filter(event => {
    if (activeTab === 'all') return true
    return event.type === activeTab
  })

  const renderEventSummary = (event: MonitorEvent) => {
    switch (event.type) {
      case 'process':
        return (
          <div className="event-summary-content">
            <span className="event-main">
              {event.data.process_name || 'Unknown Process'}
              {event.data.is_new && <span className="new-badge">NEW</span>}
            </span>
            <span className="event-sub">PID: {event.data.pid || 'N/A'} | PPID: {event.data.ppid || 'N/A'}</span>
          </div>
        )
      case 'network':
        return (
          <div className="event-summary-content">
            <span className="event-main">
              {event.data.protocol} Connection
              {event.data.is_new && <span className="new-badge">NEW</span>}
            </span>
            <span className="event-sub">
              {event.data.source_ip}:{event.data.source_port} → {event.data.dest_ip}:{event.data.dest_port}
            </span>
          </div>
        )
      default:
        return <span>Unknown event type</span>
    }
  }

  return (
    <div className="monitor-page">
      <div className="page-header">
        <div className="header-content">
          <h2>{t('monitor.title')}</h2>
          <p className="page-desc">{t('monitor.pageDesc')}</p>
        </div>
        <div className={`status-badge ${stats?.is_running ? 'running' : 'stopped'}`}>
          <span className="status-dot-animated"></span>
          {stats?.is_running ? t('monitor.running') : t('monitor.stopped')}
        </div>
      </div>

      {(statsError || eventsError) && (
        <div className="monitor-errors">
          {statsError && <div className="error-banner error">{statsError}</div>}
          {eventsError && <div className="error-banner error">{eventsError}</div>}
        </div>
      )}

      <div className="monitor-grid">
        <div className="stats-row">
          <div className="stat-card-monitor">
            <div className="stat-icon-wrapper process">
              <ProcessIcon />
            </div>
            <div className="stat-info">
              <span className="stat-value">{stats?.process_count || 0}</span>
              <span className="stat-label">{t('monitor.processCount')}</span>
            </div>
            <div className={`stat-toggle ${config.process_enabled ? 'active' : ''}`}>
              <label className="toggle-switch-small">
                <input
                  type="checkbox"
                  checked={config.process_enabled}
                  onChange={() => handleToggle('process_enabled')}
                  disabled={!stats?.is_running}
                />
                <span className="toggle-slider-small"></span>
              </label>
            </div>
          </div>

          <div className="stat-card-monitor">
            <div className="stat-icon-wrapper network">
              <NetworkIcon />
            </div>
            <div className="stat-info">
              <span className="stat-value">{stats?.network_count || 0}</span>
              <span className="stat-label">{t('monitor.networkCount')}</span>
            </div>
            <div className={`stat-toggle ${config.network_enabled ? 'active' : ''}`}>
              <label className="toggle-switch-small">
                <input
                  type="checkbox"
                  checked={config.network_enabled}
                  onChange={() => handleToggle('network_enabled')}
                  disabled={!stats?.is_running}
                />
                <span className="toggle-slider-small"></span>
              </label>
            </div>
          </div>

          <div className="stat-card-monitor alert">
            <div className="stat-icon-wrapper alert">
              <AlertIcon />
            </div>
            <div className="stat-info">
              <span className="stat-value">{stats?.alert_count || 0}</span>
              <span className="stat-label">{t('monitor.alertCount')}</span>
            </div>
          </div>
        </div>

        <div className="control-section">
          <div className="control-card">
            <div className="control-card-header">
              <h3>{t('monitor.title')}</h3>
              {stats?.start_time && (
                <span className="start-time">
                  {t('monitor.startTime')}: {new Date(stats.start_time).toLocaleString()}
                </span>
              )}
            </div>

            <div className="monitor-toggles">
              <div className="toggle-item">
                <div className="toggle-info">
                  <div className="toggle-icon process"><ProcessIcon /></div>
                  <div className="toggle-text">
                    <span className="toggle-title">{t('monitor.processMonitoring')}</span>
                    <span className="toggle-desc">{t('monitor.processMonitoringDesc')}</span>
                  </div>
                </div>
                <label className="toggle-switch">
                  <input
                    type="checkbox"
                    checked={config.process_enabled}
                    onChange={() => handleToggle('process_enabled')}
                    disabled={!stats?.is_running}
                  />
                  <span className="toggle-slider"></span>
                </label>
              </div>

              <div className="toggle-item">
                <div className="toggle-info">
                  <div className="toggle-icon network"><NetworkIcon /></div>
                  <div className="toggle-text">
                    <span className="toggle-title">{t('monitor.networkMonitoring')}</span>
                    <span className="toggle-desc">{t('monitor.networkMonitoringDesc')}</span>
                  </div>
                </div>
                <label className="toggle-switch">
                  <input
                    type="checkbox"
                    checked={config.network_enabled}
                    onChange={() => handleToggle('network_enabled')}
                    disabled={!stats?.is_running}
                  />
                  <span className="toggle-slider"></span>
                </label>
              </div>
            </div>

            <button
              className={`btn-monitor-action ${stats?.is_running ? 'btn-stop' : 'btn-start'}`}
              onClick={handleStartStop}
              disabled={loading}
            >
              {loading ? (
                <LoadingSpinner />
              ) : stats?.is_running ? (
                <>
                  <StopIcon />
                  {t('monitor.stop')}
                </>
              ) : (
                <>
                  <PlayIcon />
                  {t('monitor.start')}
                </>
              )}
            </button>
          </div>

          <div className="about-card">
            <h4>{t('monitor.aboutMonitor')}</h4>
            <p>{t('monitor.aboutDesc')}</p>
          </div>
        </div>
      </div>

      <div className="events-container">
        <div className="events-header-section">
          <h3>{t('monitor.events')}</h3>
          <div className="filter-tabs">
            <button
              className={`filter-tab ${activeTab === 'all' ? 'active' : ''}`}
              onClick={() => setActiveTab('all')}
            >
              <span className="tab-label">All</span>
              <span className="tab-count">{events.length}</span>
            </button>
            <button
              className={`filter-tab process ${activeTab === 'process' ? 'active' : ''}`}
              onClick={() => setActiveTab('process')}
            >
              <ProcessIcon />
              <span className="tab-label">Process</span>
              <span className="tab-count">{events.filter(e => e.type === 'process').length}</span>
            </button>
            <button
              className={`filter-tab network ${activeTab === 'network' ? 'active' : ''}`}
              onClick={() => setActiveTab('network')}
            >
              <NetworkIcon />
              <span className="tab-label">Network</span>
              <span className="tab-count">{events.filter(e => e.type === 'network').length}</span>
            </button>
          </div>
        </div>

        <div className="events-list-modern">
          {filteredEvents.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                </svg>
              </div>
              <h4>{t('monitor.noEvents')}</h4>
              <p>{t('monitor.noEventsDesc')}</p>
            </div>
          ) : (
            filteredEvents.map(event => (
              <div
                key={event.id}
                className={`event-card ${expandedEvent === event.id ? 'expanded' : ''}`}
                onClick={() => setExpandedEvent(expandedEvent === event.id ? null : event.id)}
              >
                <div className="event-card-main">
                  <div className={`event-type-icon ${event.type}`}>
                    {getEventIcon(event.type)}
                  </div>
                  <div className="event-info">
                    <div className="event-header-row">
                      <span
                        className="severity-pill"
                        style={{
                          backgroundColor: getSeverityColor(event.severity).bg,
                          color: getSeverityColor(event.severity).color,
                          borderColor: getSeverityColor(event.severity).border
                        }}
                      >
                        {event.severity.toUpperCase()}
                      </span>
                      <span className="event-time">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                    {renderEventSummary(event)}
                  </div>
                  <div className={`type-indicator ${event.type}`}>
                    {event.type.toUpperCase()}
                  </div>
                </div>

                {expandedEvent === event.id && (
                  <div className="event-details-panel">
                    <div className="details-grid">
                      <div className="detail-item">
                        <span className="detail-label">{t('monitor.eventType')}</span>
                        <span className="detail-value">{event.id}</span>
                      </div>
                      <div className="detail-item">
                        <span className="detail-label">{t('monitor.timestamp')}</span>
                        <span className="detail-value">{new Date(event.timestamp).toLocaleString()}</span>
                      </div>
                      {event.type === 'process' && (
                        <>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.pid')}</span>
                            <span className="detail-value">{event.data.pid || 'N/A'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.ppid')}</span>
                            <span className="detail-value">{event.data.ppid || 'N/A'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.isNew')}</span>
                            <span className="detail-value">{event.data.is_new ? 'Yes' : 'No'}</span>
                          </div>
                          <div className="detail-item full-width">
                            <span className="detail-label">{t('monitor.path')}</span>
                            <span className="detail-value code">{event.data.path || 'N/A'}</span>
                          </div>
                          <div className="detail-item full-width">
                            <span className="detail-label">{t('monitor.commandLine')}</span>
                            <span className="detail-value code">{event.data.command_line || 'N/A'}</span>
                          </div>
                        </>
                      )}
                      {event.type === 'network' && (
                        <>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.protocol')}</span>
                            <span className="detail-value">{event.data.protocol || 'N/A'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.state')}</span>
                            <span className="detail-value">{event.data.state || 'N/A'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.isNew')}</span>
                            <span className="detail-value">{event.data.is_new ? 'Yes' : 'No'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.sourceIp')}</span>
                            <span className="detail-value">{event.data.source_ip || 'N/A'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.sourcePort')}</span>
                            <span className="detail-value">{event.data.source_port || 'N/A'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.destIp')}</span>
                            <span className="detail-value">{event.data.dest_ip || 'N/A'}</span>
                          </div>
                          <div className="detail-item">
                            <span className="detail-label">{t('monitor.destPort')}</span>
                            <span className="detail-value">{event.data.dest_port || 'N/A'}</span>
                          </div>
                          </>
                        )}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

export default Monitor
