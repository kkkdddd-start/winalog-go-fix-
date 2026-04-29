import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { timelineAPI, TimelineEntry, TimelineResponse } from '../api'

function Timeline() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [entries, setEntries] = useState<TimelineEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [hasMore, setHasMore] = useState(false)
  const [totalCount, setTotalCount] = useState(0)
  const [backendEventCount, setBackendEventCount] = useState(0)
  const [backendAlertCount, setBackendAlertCount] = useState(0)
  const [filter, setFilter] = useState<'all' | 'events' | 'alerts'>('all')
  const [startDate, setStartDate] = useState('')
  const [startTime, setStartTime] = useState('')
  const [endDate, setEndDate] = useState('')
  const [endTime, setEndTime] = useState('')
  const [eventIds, setEventIds] = useState('')
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc')
  const [alertStatus, setAlertStatus] = useState<string>('')
  const [showEventIdList, setShowEventIdList] = useState(false)
  const [showExportMenu, setShowExportMenu] = useState(false)
  const PAGE_SIZE = 500
  const offsetRef = useRef(0)

  const STORAGE_KEY = 'winalog-timeline-settings'

  const loadSettings = () => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY)
      if (saved) {
        const settings = JSON.parse(saved)
        if (settings.eventIds) setEventIds(settings.eventIds)
        if (settings.sortOrder) setSortOrder(settings.sortOrder)
        if (settings.alertStatus) setAlertStatus(settings.alertStatus)
      }
    } catch (e) {
      console.error('Failed to load timeline settings:', e)
    }
  }

  const saveSettings = (ids: string, order: string, status: string) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        eventIds: ids,
        sortOrder: order,
        alertStatus: status
      }))
    } catch (e) {
      console.error('Failed to save timeline settings:', e)
    }
  }

  useEffect(() => {
    loadSettings()
  }, [])

  const eventIdCategories = {
    'Authentication': [
      { id: '4624', name: 'Logon Success', desc: 'Successful logon' },
      { id: '4625', name: 'Logon Failure', desc: 'Failed logon' },
      { id: '4768', name: 'TGT Request', desc: 'Kerberos TGT requested' },
      { id: '4769', name: 'TGS Request', desc: 'Kerberos TGS requested' },
      { id: '4776', name: 'NTLM Auth', desc: 'NTLM authentication' },
    ],
    'Authorization': [
      { id: '4672', name: 'Special Privilege', desc: 'Special privileges assigned' },
    ],
    'Process': [
      { id: '4688', name: 'Process Create', desc: 'New process created' },
      { id: '4689', name: 'Process Exit', desc: 'Process terminated' },
    ],
    'Persistence': [
      { id: '4698', name: 'Scheduled Task', desc: 'Scheduled task created' },
      { id: '4697', name: 'Service Install', desc: 'Service installed' },
    ],
    'Script': [
      { id: '4104', name: 'PowerShell Exec', desc: 'PowerShell execution' },
    ],
    'Defense Evasion': [
      { id: '1102', name: 'Audit Cleared', desc: 'Audit log cleared' },
      { id: '4719', name: 'Audit Policy', desc: 'Audit policy changed' },
    ],
    'Collection': [
      { id: '5145', name: 'Share Access', desc: 'Network share access' },
    ],
    'Account Management': [
      { id: '4720', name: 'Account Created', desc: 'User account created' },
      { id: '4722', name: 'Account Enabled', desc: 'User account enabled' },
      { id: '4723', name: 'Password Change', desc: 'Password change attempt' },
      { id: '4724', name: 'Password Reset', desc: 'Password reset attempt' },
      { id: '4725', name: 'Account Disabled', desc: 'User account disabled' },
      { id: '4726', name: 'Account Deleted', desc: 'User account deleted' },
      { id: '4732', name: 'Member Added', desc: 'Member added to security group' },
      { id: '4733', name: 'Member Removed', desc: 'Member removed from group' },
      { id: '4740', name: 'Account Locked', desc: 'Account locked out' },
      { id: '4767', name: 'Account Unlocked', desc: 'Account unlocked' },
    ],
    'Logoff': [
      { id: '4634', name: 'Logoff', desc: 'User logoff' },
      { id: '4648', name: 'Explicit Creds', desc: 'Explicit credentials logon' },
    ],
  }

  const [collapsedCategories, setCollapsedCategories] = useState<Record<string, boolean>>({})
  const [searchQuery, setSearchQuery] = useState('')

  const fetchTimeline = (append = false) => {
    if (append) {
      setLoadingMore(true)
    } else {
      setLoading(true)
      offsetRef.current = 0
    }

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

    const currentOffset = append ? offsetRef.current : 0
    timelineAPI.get(PAGE_SIZE, startTimeISO, endTimeISO, currentOffset, eventIds, sortOrder, alertStatus)
      .then(res => {
        const data = res.data as TimelineResponse
        if (append) {
          setEntries(prev => [...prev, ...(data.entries || [])])
        } else {
          setEntries(data.entries || [])
        }
        setTotalCount(data.total_count || 0)
        setBackendEventCount(data.event_count || 0)
        setBackendAlertCount(data.alert_count || 0)
        setHasMore(data.has_more || false)
        offsetRef.current = currentOffset + (data.entries?.length || 0)
        setLoading(false)
        setLoadingMore(false)
      })
      .catch(() => {
        setLoading(false)
        setLoadingMore(false)
      })
  }

  const handleLoadMore = () => {
    if (!loadingMore && hasMore) {
      fetchTimeline(true)
    }
  }

  useEffect(() => {
    fetchTimeline()
  }, [])

  useEffect(() => {
    saveSettings(eventIds, sortOrder, alertStatus)
  }, [eventIds, sortOrder, alertStatus])

  const handleApplyFilter = () => {
    fetchTimeline()
  }

  const handleClearFilter = () => {
    setStartDate('')
    setStartTime('')
    setEndDate('')
    setEndTime('')
    setEventIds('')
    setSortOrder('desc')
    setAlertStatus('')
    fetchTimeline()
  }

  const toggleCategory = (category: string) => {
    setCollapsedCategories(prev => ({
      ...prev,
      [category]: !prev[category]
    }))
  }

  const handleSelectEventId = (id: string) => {
    const currentIds = eventIds ? eventIds.split(',').map(e => e.trim()).filter(e => e) : []
    if (currentIds.includes(id)) {
      setEventIds(currentIds.filter(e => e !== id).join(','))
    } else {
      setEventIds([...currentIds, id].join(','))
    }
  }

  const handleClearEventIds = () => {
    setEventIds('')
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

  const displayStats = {
    eventCount: filter === 'events' ? backendEventCount : (filter === 'all' ? backendEventCount : filteredEntries.filter(e => e.type === 'event').length),
    alertCount: filter === 'alerts' ? backendAlertCount : (filter === 'all' ? backendAlertCount : filteredEntries.filter(e => e.type === 'alert').length),
  }

  const handleDeleteAlert = (id: number) => {
    timelineAPI.deleteAlert(id)
      .then(() => {
        setEntries(entries.filter(e => !(e.type === 'alert' && e.alert_id === id)))
      })
      .catch(err => console.error('Failed to delete alert:', err))
  }

  const handleExport = (format: 'csv' | 'json' | 'html') => {
    setShowExportMenu(false)

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

    timelineAPI.export(format, startTimeISO, endTimeISO, eventIds)
      .then(res => {
        const blob = new Blob([res.data], { type: format === 'csv' ? 'text/csv' : format === 'html' ? 'text/html' : 'application/json' })
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `timeline.${format}`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        window.URL.revokeObjectURL(url)
      })
      .catch(err => console.error('Failed to export:', err))
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
        <div className="header-right">
          <div className="timeline-stats-mini">
            <div className="stat-mini events">
              <span className="stat-mini-icon">📋</span>
              <span className="stat-mini-value">{backendEventCount}</span>
              <span className="stat-mini-label">{t('timeline.events')}</span>
            </div>
            <div className="stat-mini alerts">
              <span className="stat-mini-icon">🚨</span>
              <span className="stat-mini-value">{backendAlertCount}</span>
              <span className="stat-mini-label">{t('timeline.alerts')}</span>
            </div>
            <div className="stat-mini ratio">
              <span className="stat-mini-value">
                {backendEventCount + backendAlertCount > 0
                  ? ((backendAlertCount / (backendEventCount + backendAlertCount)) * 100).toFixed(1)
                  : 0}%
              </span>
              <span className="stat-mini-label">{t('timeline.alertRatio')}</span>
            </div>
          </div>
          <div className="export-dropdown">
            <button className="btn-export" onClick={() => setShowExportMenu(!showExportMenu)}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              {t('timeline.export')}
            </button>
            {showExportMenu && (
              <div className="export-menu">
                <button onClick={() => handleExport('csv')}>CSV</button>
                <button onClick={() => handleExport('json')}>JSON</button>
                <button onClick={() => handleExport('html')}>HTML</button>
              </div>
            )}
          </div>
          <button className="btn-secondary" onClick={() => navigate('/analyze')}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.35-4.35"/>
            </svg>
            {t('timeline.runAnalysis')}
          </button>
        </div>
      </div>

      <div className="timeline-toolbar">
        <div className="toolbar-row filter-tabs-row">
          <div className="filter-tabs">
            <button
              className={`filter-tab ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
            >
              {t('timeline.all')}
              <span className="count">{displayStats.eventCount + displayStats.alertCount}</span>
            </button>
            <button
              className={`filter-tab ${filter === 'events' ? 'active' : ''}`}
              onClick={() => setFilter('events')}
            >
              {t('timeline.eventsOnly')}
              <span className="count events">{displayStats.eventCount}</span>
            </button>
            <button
              className={`filter-tab ${filter === 'alerts' ? 'active' : ''}`}
              onClick={() => setFilter('alerts')}
            >
              {t('timeline.alertsOnly')}
              <span className="count alerts">{displayStats.alertCount}</span>
            </button>
          </div>
        </div>
        <div className="toolbar-row filter-controls-row">
          <div className="event-id-selector" style={{ position: 'relative' }}>
            <button
              className="btn-event-id-list"
              onClick={() => setShowEventIdList(!showEventIdList)}
              title="Common Security Event IDs"
            >
              📋 {t('timeline.suspiciousEvents')}
            </button>
            {showEventIdList && (
              <div className="event-id-popover">
                <div className="popover-header">
                  <span>{t('timeline.eventIdSelector')}</span>
                  <input
                    type="text"
                    className="popover-search"
                    placeholder={t('timeline.search')}
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                  />
                </div>
                <div className="popover-list">
                  {Object.entries(eventIdCategories).map(([category, events]) => {
                    const filteredEvents = events.filter(e =>
                      e.id.includes(searchQuery) ||
                      e.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                      e.desc.toLowerCase().includes(searchQuery.toLowerCase())
                    )
                    if (filteredEvents.length === 0) return null
                    const selectedCount = filteredEvents.filter(e => {
                      const currentIds = eventIds.split(',').map(id => id.trim())
                      return currentIds.includes(e.id)
                    }).length
                    const isCollapsed = collapsedCategories[category]
                    return (
                      <div key={category} className="event-category">
                        <div
                          className="category-header"
                          onClick={() => toggleCategory(category)}
                        >
                          <span className="category-toggle">{isCollapsed ? '▶' : '▼'}</span>
                          <span className="category-name">{category}</span>
                          <span className="category-count">({selectedCount}/{filteredEvents.length})</span>
                        </div>
                        {!isCollapsed && filteredEvents.map(e => {
                          const isSelected = eventIds.split(',').map(id => id.trim()).includes(e.id)
                          return (
                          <div
                            key={e.id}
                            className={`popover-item ${isSelected ? 'selected' : ''}`}
                            onClick={() => handleSelectEventId(e.id)}
                          >
                            <span className={`checkbox ${isSelected ? 'checked' : ''}`}>
                              {isSelected ? '✓' : ''}
                            </span>
                            <span className="event-id">{e.id}</span>
                            <span className="event-name">{e.name}</span>
                            <span className="event-desc">{e.desc}</span>
                          </div>
                          )
                        })}
                      </div>
                    )
                  })}
                </div>
                <div className="popover-footer">
                  <div className="custom-eventid-input">
                    <input
                      type="text"
                      placeholder={t('timeline.customEventId')}
                      onKeyDown={e => {
                        if (e.key === 'Enter') {
                          const input = e.target as HTMLInputElement
                          if (input.value.trim()) {
                            handleSelectEventId(input.value.trim())
                            input.value = ''
                          }
                        }
                      }}
                    />
                    <button
                      onClick={e => {
                        const input = (e.target as HTMLElement).previousElementSibling as HTMLInputElement
                        if (input.value.trim()) {
                          handleSelectEventId(input.value.trim())
                          input.value = ''
                        }
                      }}
                    >+</button>
                  </div>
                  <div className="popover-footer-actions">
                    <span className="selected-ids">
                      {eventIds ? eventIds : t('timeline.noneSelected')}
                    </span>
                    <div className="footer-buttons">
                      <button className="btn-clear-ids" onClick={handleClearEventIds}>{t('timeline.reset')}</button>
                      <button className="btn-apply-ids" onClick={() => { setShowEventIdList(false); fetchTimeline(); }}>{t('timeline.apply')}</button>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
          <select
            value={sortOrder}
            onChange={e => {
              setSortOrder(e.target.value as 'desc' | 'asc')
              fetchTimeline()
            }}
            style={{ width: '120px' }}
          >
            <option value="desc">{t('timeline.sortNewToOld')}</option>
            <option value="asc">{t('timeline.sortOldToNew')}</option>
          </select>
          <div className="datetime-range">
            <input
              type="date"
              value={startDate}
              onChange={e => setStartDate(e.target.value)}
              placeholder={t('timeline.startDate')}
            />
            <input
              type="time"
              value={startTime}
              onChange={e => setStartTime(e.target.value)}
              placeholder={t('timeline.startTime')}
            />
            <span className="datetime-separator">-</span>
            <input
              type="date"
              value={endDate}
              onChange={e => setEndDate(e.target.value)}
              placeholder={t('timeline.endDate')}
            />
            <input
              type="time"
              value={endTime}
              onChange={e => setEndTime(e.target.value)}
              placeholder={t('timeline.endTime')}
            />
          </div>
          <button className="btn-apply-filter" onClick={handleApplyFilter}>
            {t('common.apply')}
          </button>
          <button className="btn-clear-filter" onClick={handleClearFilter}>
            {t('common.clear')}
          </button>
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
                  {entry.type === 'event' && (entry.level || entry.source) && (
                    <div className="card-meta">
                      {entry.level && (
                        <span className="info-badge">
                          <span className="info-icon">📋</span>
                          {entry.level}
                        </span>
                      )}
                      {entry.source && (
                        <span className="info-badge source">
                          <span className="info-icon">💻</span>
                          {entry.source}
                        </span>
                      )}
                    </div>
                  )}
                  <div className="card-divider"></div>
                  {entry.type === 'alert' && entry.rule_name && (
                    <div className="card-meta">
                      <span className="rule-badge">
                        <span className="rule-icon">📌</span>
                        {entry.rule_name}
                      </span>
                      {entry.mitre_attack && entry.mitre_attack.length > 0 && (
                        <span className="mitre-badge">
                          <span className="mitre-icon">🎯</span>
                          MITRE: {entry.mitre_attack.join(', ')}
                        </span>
                      )}
                      {entry.event_db_ids && entry.event_db_ids.length > 0 && (
                        <span className="related-events-badge">
                          <span className="related-icon">🔗</span>
                          {t('timeline.relatedEvents')}: {entry.event_db_ids.length > 3
                            ? `${entry.event_db_ids.slice(0, 3).join(', ')} ×${entry.event_db_ids.length}`
                            : entry.event_db_ids.map(id => `Event ${id}`).join(', ')}
                        </span>
                      )}
                    </div>
                  )}
                  <div className="card-actions">
                    {entry.type === 'event' && (
                      <button
                        className="btn-detail"
                        onClick={() => navigate(`/events?eventId=${entry.event_id}&computer=${entry.computer || ''}`)}
                      >
                        {t('timeline.viewDetails')}
                      </button>
                    )}
                    {entry.type === 'alert' && entry.alert_id && (
                      <>
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
                      </>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {entries.length > 0 && (
        <div className="timeline-footer">
          <div className="timeline-count">
            {t('timeline.showing')} {entries.length} / {totalCount} {t('timeline.entries')}
          </div>
          {hasMore && (
            <button
              className="btn-load-more"
              onClick={handleLoadMore}
              disabled={loadingMore}
            >
              {loadingMore ? t('timeline.loading') : t('timeline.loadMore')}
            </button>
          )}
        </div>
      )}
    </div>
  )
}

export default Timeline