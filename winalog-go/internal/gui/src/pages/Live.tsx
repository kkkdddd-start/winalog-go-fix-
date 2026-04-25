import { useState } from 'react'
import { useI18n } from '../locales/I18n'
import { useLiveEvents } from '../hooks/useLiveEvents'

function Live() {
  const { t } = useI18n()
  const [filter, setFilter] = useState<string>('all')
  const [error, setError] = useState<string | null>(null)

  const { events, isConnected, isConnecting, enabled, setEnabled, clearEvents } = useLiveEvents({
    channels: ['Security', 'System', 'Application'],
    maxEvents: 100,
    onError: (err) => setError(err),
    onConnected: () => setError(null),
    onDisconnected: () => {},
  })

  const filteredEvents = events.filter(event => {
    if (filter === 'all') return true
    return event.level?.toLowerCase() === filter
  })

  const getLevelColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return '#ef4444'
      case 'error': return '#f97316'
      case 'warning': return '#eab308'
      case 'info': return '#3b82f6'
      case 'verbose': return '#6b7280'
      default: return '#888'
    }
  }

  const getLogSourceStats = () => {
    const stats: Record<string, number> = {}
    filteredEvents.forEach(event => {
      const source = event.log_name || 'Unknown'
      stats[source] = (stats[source] || 0) + 1
    })
    return stats
  }

  const logSourceStats = getLogSourceStats()
  const logSourceEntries = Object.entries(logSourceStats).sort((a, b) => b[1] - a[1])

  const exportToCSV = () => {
    if (events.length === 0) return
    const headers = ['ID', 'Timestamp', 'Level', 'Event ID', 'Source', 'Log Name', 'Computer', 'User', 'Message']
    const csvContent = [
      headers.join(','),
      ...filteredEvents.map(event => [
        event.id,
        event.timestamp,
        event.level,
        event.event_id,
        `"${(event.source || '').replace(/"/g, '""')}"`,
        `"${(event.log_name || '').replace(/"/g, '""')}"`,
        `"${(event.computer || '').replace(/"/g, '""')}"`,
        `"${(event.user || '').replace(/"/g, '""')}"`,
        `"${(event.message || '').replace(/"/g, '""')}"`
      ].join(','))
    ].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `live_events_${new Date().toISOString().slice(0,10)}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  const formatTime = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString()
    } catch {
      return timestamp
    }
  }

  return (
    <div className="live-page">
      <div className="page-header">
        <div className="header-left">
          <h2>{t('live.title')}</h2>
          <div className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {isConnected ? 'Connected' : isConnecting ? 'Connecting...' : 'Disconnected'}
          </div>
        </div>
        <div className="header-actions">
          <label className="toggle-switch">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span className="toggle-slider"></span>
          </label>
          <span style={{ marginRight: '12px', fontSize: '14px' }}>
            {isConnected ? 'Live Monitoring ON' : 'Live Monitoring OFF'}
          </span>
          <select
            className="filter-select"
            value={filter}
            onChange={e => setFilter(e.target.value)}
          >
            <option value="all">All Levels</option>
            <option value="critical">Critical</option>
            <option value="error">Error</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
            <option value="verbose">Verbose</option>
          </select>
          <button className="btn-secondary" onClick={clearEvents}>
            Clear
          </button>
          <button className="btn-secondary" onClick={exportToCSV} disabled={events.length === 0}>
            Export CSV ({events.length})
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      <div className="stats-bar">
        <div className="stat-item">
          <span className="stat-label">Total Events</span>
          <span className="stat-value">{events.length}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Filtered</span>
          <span className="stat-value">{filteredEvents.length}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Buffered</span>
          <span className="stat-value">{events.length}/100</span>
        </div>
        <div className="stat-item log-sources">
          <span className="stat-label">Sources</span>
          <div className="log-source-list">
            {logSourceEntries.slice(0, 3).map(([source, count]) => (
              <span key={source} className="log-source-badge">
                {source}: {count}
              </span>
            ))}
            {logSourceEntries.length > 3 && (
              <span className="log-source-more">+{logSourceEntries.length - 3} more</span>
            )}
          </div>
        </div>
      </div>

      <div className="events-container">
        {filteredEvents.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📡</div>
            <div className="empty-text">
              {isConnected ? 'Waiting for events...' : 'Enable monitoring to start collecting events'}
            </div>
          </div>
        ) : (
          <div className="events-list">
            {filteredEvents.map((event, index) => (
              <div
                key={`${event.id}-${index}`}
                className="event-card"
                style={{ borderLeftColor: getLevelColor(event.level) }}
              >
                <div className="event-header">
                  <span className="event-time">{formatTime(event.timestamp)}</span>
                  <span
                    className="event-level"
                    style={{ color: getLevelColor(event.level) }}
                  >
                    {event.level || 'UNKNOWN'}
                  </span>
                  <span className="event-id">Event #{event.event_id}</span>
                  <span className="event-source">{event.source || event.log_name}</span>
                </div>
                <div className="event-body">
                  <div className="event-message">{event.message || '(No message)'}</div>
                </div>
                <div className="event-footer">
                  <span className="event-computer">{event.computer}</span>
                  {event.user && <span className="event-user">{event.user}</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default Live
