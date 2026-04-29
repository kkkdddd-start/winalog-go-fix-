import { useState, useEffect } from 'react'
import { useLiveEvents, ChannelConfig, EventFilters } from '../hooks/useLiveEvents'
import { ChannelSelector } from '../components/ChannelSelector'
import { EventFilters as EventFiltersComponent } from '../components/EventFilters'

function Live() {
  const [levelFilter, setLevelFilter] = useState<string>('all')
  const [error, setError] = useState<string | null>(null)
  const [channels, setChannels] = useState<ChannelConfig[]>([])
  const [saving, setSaving] = useState(false)
  const [showConfig, setShowConfig] = useState(false)

  const {
    events,
    isConnected,
    isConnecting,
    enabled,
    setEnabled,
    clearEvents,
    stats,
    filters,
    fetchChannels,
    updateChannels,
    applyFilters,
    clearFilters,
  } = useLiveEvents({
    maxEvents: 100,
    onError: (err) => setError(err),
    onConnected: () => setError(null),
    onDisconnected: () => {},
  })

  useEffect(() => {
    const loadChannels = async () => {
      const data = await fetchChannels()
      if (data.length > 0) {
        setChannels(data)
      } else {
        setChannels([
          { name: 'Security', description: '安全日志', event_ids: '4624,4625,4672,4688,4698', enabled: true },
          { name: 'System', description: '系统日志', event_ids: '6005,6006,7045', enabled: false },
          { name: 'Application', description: '应用程序', event_ids: '1000,1001', enabled: false },
          { name: 'Microsoft-Windows-Sysmon/Operational', description: 'Sysmon', event_ids: '1,3,6,7,8,11', enabled: false },
          { name: 'Microsoft-Windows-PowerShell/Operational', description: 'PowerShell', event_ids: '4103,4104', enabled: false },
        ])
      }
    }
    loadChannels()
  }, [fetchChannels])

  const handleSaveChannels = async () => {
    setSaving(true)
    const success = await updateChannels(channels)
    setSaving(false)
    if (success) {
      setShowConfig(false)
    }
  }

  const handleApplyFilters = (newFilters: EventFilters) => {
    applyFilters(newFilters)
  }

  const handleClearFilters = () => {
    clearFilters()
  }

  const filteredEvents = events.filter(event => {
    if (levelFilter === 'all') return true
    return event.level_name?.toLowerCase() === levelFilter
  })

  const getLevelColor = (levelName: string) => {
    switch (levelName?.toLowerCase()) {
      case 'critical': return '#ef4444'
      case 'error': return '#f97316'
      case 'warning': return '#eab308'
      case 'info': return '#3b82f6'
      case 'verbose': return '#6b7280'
      default: return '#888'
    }
  }

  const getLevelName = (levelName: string) => {
    switch (levelName?.toLowerCase()) {
      case 'critical': return '严重'
      case 'error': return '错误'
      case 'warning': return '警告'
      case 'info': return '信息'
      case 'verbose': return '详细'
      default: return levelName || '未知'
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
    const headers = ['ID', '时间戳', '级别', '事件ID', '来源', '日志源', '计算机', '用户', '消息']
    const csvContent = [
      headers.join(','),
      ...filteredEvents.map(event => [
        event.id,
        event.timestamp,
        event.level_name,
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
      return new Date(timestamp).toLocaleString('zh-CN')
    } catch {
      return timestamp
    }
  }

  const handleClearEvents = async () => {
    if (window.confirm('确定要清空所有事件吗？')) {
      await clearEvents()
    }
  }

  return (
    <div className="live-page">
      <div className="page-header">
        <div className="header-left">
          <h2>实时事件监控</h2>
          <div className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {isConnected ? '已连接' : isConnecting ? '连接中...' : '已断开'}
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
          <span style={{ marginRight: '12px', fontSize: '14px', color: '#888' }}>
            {enabled ? (isConnected ? '监控中' : '监控已开启') : '监控已关闭'}
          </span>
          <button className="btn-secondary" onClick={() => setShowConfig(!showConfig)}>
            {showConfig ? '隐藏配置' : '订阅配置'}
          </button>
          <select
            className="filter-select"
            value={levelFilter}
            onChange={e => setLevelFilter(e.target.value)}
          >
            <option value="all">全部级别</option>
            <option value="critical">严重</option>
            <option value="error">错误</option>
            <option value="warning">警告</option>
            <option value="info">信息</option>
            <option value="verbose">详细</option>
          </select>
          <button className="btn-secondary" onClick={handleClearEvents}>
            清空
          </button>
          <button className="btn-secondary" onClick={exportToCSV} disabled={events.length === 0}>
            导出 CSV ({events.length})
          </button>
        </div>
      </div>

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      {showConfig && (
        <div className="config-section">
          <ChannelSelector
            channels={channels}
            onChannelsChange={setChannels}
            onSave={handleSaveChannels}
            saving={saving}
          />
        </div>
      )}

      <EventFiltersComponent
        filters={filters}
        onFiltersChange={handleApplyFilters}
        onApply={handleApplyFilters}
        onClear={handleClearFilters}
      />

      <div className="stats-bar">
        <div className="stat-item">
          <span className="stat-label">总事件数</span>
          <span className="stat-value">{events.length}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">已过滤</span>
          <span className="stat-value">{filteredEvents.length}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">缓冲上限</span>
          <span className="stat-value">{events.length}/100</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">数据库总计</span>
          <span className="stat-value">{stats.total}</span>
        </div>
        <div className="stat-item log-sources">
          <span className="stat-label">日志源分布</span>
          <div className="log-source-list">
            {logSourceEntries.slice(0, 3).map(([source, count]) => (
              <span key={source} className="log-source-badge">
                {source}: {count}
              </span>
            ))}
            {logSourceEntries.length > 3 && (
              <span className="log-source-more">+{logSourceEntries.length - 3} 更多</span>
            )}
          </div>
        </div>
      </div>

      <div className="events-container">
        {filteredEvents.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📡</div>
            <div className="empty-text">
              {enabled ? '等待接收事件...' : '开启监控以开始收集事件'}
            </div>
          </div>
        ) : (
          <div className="events-list">
            {filteredEvents.map((event, index) => (
              <div
                key={`${event.id}-${index}`}
                className="event-card"
                style={{ borderLeftColor: getLevelColor(event.level_name) }}
              >
                <div className="event-header">
                  <span className="event-time">{formatTime(event.timestamp)}</span>
                  <span
                    className="event-level"
                    style={{ color: getLevelColor(event.level_name) }}
                  >
                    {getLevelName(event.level_name)}
                  </span>
                  <span className="event-id">事件 #{event.event_id}</span>
                  <span className="event-source">{event.source || event.log_name}</span>
                </div>
                <div className="event-body">
                  <div className="event-message">{event.message || '(无消息)'}</div>
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
