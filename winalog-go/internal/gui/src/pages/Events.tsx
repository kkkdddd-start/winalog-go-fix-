import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { eventsAPI, ExportParams, SearchParams, dashboardAPI } from '../api'

interface Event {
  id: number
  timestamp: string
  import_time?: string
  event_id: number
  level: string
  source: string
  log_name: string
  computer: string
  message: string
  raw_xml?: string
}

interface ListResponse {
  events: Event[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

interface SearchResponse {
  events: Event[]
  total: number
  page: number
  page_size: number
  total_pages: number
  query_time_ms: number
}

function Events() {
  const location = useLocation()
  const [events, setEvents] = useState<Event[]>([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [pageInput, setPageInput] = useState('')
  const [totalPages, setTotalPages] = useState(1)
  const [totalCount, setTotalCount] = useState(0)
  const [exportLoading, setExportLoading] = useState(false)
  const [searchMode, setSearchMode] = useState(false)
  const [queryTime, setQueryTime] = useState(0)
  const [showFilters, setShowFilters] = useState(false)
  const [selectedLevels, setSelectedLevels] = useState<string[]>([])
  const [useRegex, setUseRegex] = useState(false)
  const [sortBy, setSortBy] = useState('timestamp')
  const [sortOrder, setSortOrder] = useState('desc')
  const [sources, setSources] = useState('')
  const [users, setUsers] = useState('')
  const [computers, setComputers] = useState('')
  const [eventIdsInput, setEventIdsInput] = useState('')
  const [hoveredEvent, setHoveredEvent] = useState<Event | null>(null)
  const [hoverPosition, setHoverPosition] = useState({ x: 0, y: 0 })
  const [keywordMode, setKeywordMode] = useState<'AND' | 'OR'>('AND')
  const [availableLogNames, setAvailableLogNames] = useState<string[]>([])
  const [showRawModal, setShowRawModal] = useState(false)

  const [filters, setFilters] = useState<ExportParams['filters']>({
    event_ids: [],
    levels: [],
    log_names: [],
    start_time: '',
    end_time: '',
    keywords: '',
    limit: 10000,
  })

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const eventIdsParam = params.get('event_ids')
    const keywordsParam = params.get('keywords')
    
    if (eventIdsParam || keywordsParam) {
      setSearchMode(true)
      setFilters(prev => ({
        ...prev,
        event_ids: eventIdsParam ? eventIdsParam.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n)) : [],
        keywords: keywordsParam || '',
      }))
      if (eventIdsParam) {
        setEventIdsInput(eventIdsParam)
      }
    }
  }, [location.search])

  const doSearch = (pageNum: number = 1) => {
    setLoading(true)
    const levelMap: Record<string, number> = {
      'Critical': 1,
      'Error': 2,
      'Warning': 3,
      'Info': 4,
      'Debug': 5,
    }

    const eventIds = eventIdsInput
      .split(',')
      .map(s => parseInt(s.trim(), 10))
      .filter(n => !isNaN(n))

    const sourcesList = sources
      .split(',')
      .map(s => s.trim())
      .filter(s => s.length > 0)

    const usersList = users
      .split(',')
      .map(s => s.trim())
      .filter(s => s.length > 0)

    const computersList = computers
      .split(',')
      .map(s => s.trim())
      .filter(s => s.length > 0)

    const searchParams: SearchParams = {
      keywords: filters?.keywords || '',
      keyword_mode: keywordMode,
      regex: useRegex,
      page: pageNum,
      page_size: pageSize,
      sort_by: sortBy,
      sort_order: sortOrder,
      start_time: filters?.start_time || undefined,
      end_time: filters?.end_time || undefined,
      levels: selectedLevels.map(l => levelMap[l]).filter(l => l),
      event_ids: eventIds.length > 0 ? eventIds : undefined,
      log_names: filters?.log_names && filters.log_names.length > 0 ? filters.log_names : undefined,
      sources: sourcesList.length > 0 ? sourcesList : undefined,
      users: usersList.length > 0 ? usersList : undefined,
      computers: computersList.length > 0 ? computersList : undefined,
    }
    
    eventsAPI.search(searchParams)
      .then(res => {
        const data = res.data as SearchResponse
        setEvents(data.events || [])
        setTotalCount(data.total || 0)
        const pages = Math.ceil((data.total || 0) / pageSize)
        setTotalPages(pages || 1)
        setQueryTime(data.query_time_ms || 0)
        setSearchMode(true)
        setLoading(false)
      })
      .catch(() => {
        eventsAPI.list(pageNum, pageSize)
          .then(res => {
            const data = res.data as ListResponse
            setEvents(data.events || [])
            setTotalCount(data.total || 0)
            setTotalPages(data.total_pages || 1)
            setSearchMode(false)
            setLoading(false)
          })
          .catch(() => setLoading(false))
      })
  }

  const handleSearch = () => {
    setPage(1)
    doSearch(1)
  }

  const handleClearSearch = () => {
    setFilters({
      event_ids: [],
      levels: [],
      log_names: [],
      start_time: '',
      end_time: '',
      keywords: '',
      limit: 10000,
    })
    setSelectedLevels([])
    setUseRegex(false)
    setSortBy('timestamp')
    setSortOrder('desc')
    setSources('')
    setUsers('')
    setComputers('')
    setEventIdsInput('')
    setSearchMode(false)
    setKeywordMode('AND')
    setPage(1)
  }

  useEffect(() => {
    setLoading(true)
    const hasFilters = filters && (
      (filters.log_names && filters.log_names.length > 0) ||
      (filters.levels && filters.levels.length > 0) ||
      (filters.event_ids && filters.event_ids.length > 0) ||
      filters.start_time ||
      filters.end_time
    )
    
    if (filters?.keywords && filters.keywords.trim() !== '') {
      eventsAPI.search({
        keywords: filters.keywords,
        keyword_mode: keywordMode,
        regex: useRegex,
        page: page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
        levels: selectedLevels.map(l => ({'Critical': 1, 'Error': 2, 'Warning': 3, 'Info': 4, 'Debug': 5}[l] || 0)).filter(l => l > 0),
        start_time: filters.start_time,
        end_time: filters.end_time,
      })
        .then(res => {
          const data = res.data as SearchResponse
          setEvents(data.events || [])
          setTotalCount(data.total || 0)
          const pages = Math.ceil((data.total || 0) / pageSize)
          setTotalPages(pages || 1)
          setLoading(false)
        })
        .catch(() => setLoading(false))
    } else if (hasFilters) {
      eventsAPI.list(page, pageSize, {
        log_names: filters.log_names,
        levels: filters.levels,
        event_ids: filters.event_ids,
        start_time: filters.start_time,
        end_time: filters.end_time,
        sort_by: sortBy,
        sort_order: sortOrder,
      })
        .then(res => {
          const data = res.data as ListResponse
          setEvents(data.events || [])
          setTotalCount(data.total || 0)
          setTotalPages(data.total_pages || 1)
          setLoading(false)
        })
        .catch(() => setLoading(false))
    } else {
      eventsAPI.list(page, pageSize, {
        sort_by: sortBy,
        sort_order: sortOrder,
      })
        .then(res => {
          const data = res.data as ListResponse
          setEvents(data.events || [])
          setTotalCount(data.total || 0)
          setTotalPages(data.total_pages || 1)
          setLoading(false)
        })
        .catch(() => setLoading(false))
    }
  }, [page, filters, sortBy, sortOrder, pageSize, selectedLevels, keywordMode, useRegex])

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize)
    setPage(1)
  }

  const handlePageInputSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const targetPage = parseInt(pageInput, 10)
    if (!isNaN(targetPage) && targetPage >= 1 && targetPage <= totalPages) {
      setPage(targetPage)
      setPageInput('')
    }
  }

  useEffect(() => {
    dashboardAPI.getLogNames()
      .then(res => {
        const data = res.data as { log_names: string[] }
        setAvailableLogNames(data.log_names || [])
      })
      .catch(() => {})
  }, [])

  const handleExport = async (format: 'csv' | 'excel' | 'json') => {
    setExportLoading(true)
    try {
      const response = await eventsAPI.export({ format, filters })
      
      if (format === 'json') {
        const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' })
        downloadBlob(blob, `events_export.${format}`)
      } else {
        const blob = new Blob([response.data], { type: format === 'csv' ? 'text/csv' : 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })
        downloadBlob(blob, `events_export.${format === 'excel' ? 'xlsx' : format}`)
      }
    } catch (error) {
      console.error('Export failed:', error)
    } finally {
      setExportLoading(false)
    }
  }

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getLevelClass = (level: string | number) => {
    const l = String(level).toLowerCase()
    if (l === '1' || l === 'critical' || l === 'crit') return 'level-critical'
    if (l === '2' || l === 'error') return 'level-error'
    if (l === '3' || l === 'warning' || l === 'warn') return 'level-warning'
    if (l === '4' || l === 'info') return 'level-info'
    if (l === '5' || l === 'debug') return 'level-debug'
    return ''
  }

  const getLevelLabel = (level: string | number) => {
    const l = String(level)
    if (l === '1' || l === 'critical') return 'Critical'
    if (l === '2' || l === 'error') return 'Error'
    if (l === '3' || l === 'warning' || l === 'warn') return 'Warning'
    if (l === '4' || l === 'info') return 'Info'
    if (l === '5' || l === 'debug') return 'Debug'
    return l
  }

  return (
    <div className="events-page">
      <div className="page-header">
        <h2>Events</h2>
        <div className="header-actions">
          <button className="btn-secondary" onClick={() => setShowFilters(!showFilters)}>
            {showFilters ? 'Hide Filters' : 'Show Filters'}
          </button>
          <div className="export-dropdown">
            <button className="btn-secondary" disabled={exportLoading}>
              {exportLoading ? '...' : 'Export'}
            </button>
            <div className="export-menu">
              <button onClick={() => handleExport('csv')}>CSV</button>
              <button onClick={() => handleExport('json')}>JSON</button>
              <button onClick={() => handleExport('excel')}>Excel</button>
            </div>
          </div>
        </div>
      </div>

      <div className="search-bar">
        <div className="search-input-wrapper">
          <input
            type="text"
            placeholder="Search events by keyword..."
            value={filters?.keywords || ''}
            onChange={e => setFilters({...filters!, keywords: e.target.value})}
            onKeyDown={e => e.key === 'Enter' && handleSearch()}
          />
          <button className="search-btn" onClick={handleSearch}>Search</button>
        </div>
        <div className="keyword-mode-toggle">
          <span className="mode-label">Keywords:</span>
          <button
            className={`mode-btn ${keywordMode === 'AND' ? 'active' : ''}`}
            onClick={() => setKeywordMode('AND')}
            title="All keywords must match"
          >
            AND
          </button>
          <button
            className={`mode-btn ${keywordMode === 'OR' ? 'active' : ''}`}
            onClick={() => setKeywordMode('OR')}
            title="Any keyword can match"
          >
            OR
          </button>
        </div>
      </div>

      {showFilters && (
        <div className="filters-panel">
          <div className="filter-row">
            <div className="filter-group">
              <label>Start Time</label>
              <input
                type="datetime-local"
                value={filters?.start_time || ''}
                onChange={e => setFilters({...filters!, start_time: e.target.value})}
              />
            </div>
            <div className="filter-group">
              <label>End Time</label>
              <input
                type="datetime-local"
                value={filters?.end_time || ''}
                onChange={e => setFilters({...filters!, end_time: e.target.value})}
              />
            </div>
            <div className="filter-group">
              <label>Event IDs</label>
              <input
                type="text"
                placeholder="4624,4625,4672"
                value={eventIdsInput}
                onChange={e => setEventIdsInput(e.target.value)}
                className="text-input"
              />
            </div>
            <div className="filter-group">
              <label>Log Names</label>
              <select
                value={filters?.log_names?.[0] || ''}
                onChange={e => {
                  const val = e.target.value
                  setFilters({...filters!, log_names: val ? [val] : []})
                }}
                className="select-input"
              >
                <option value="">All Log Names</option>
                {availableLogNames.map(name => (
                  <option key={name} value={name}>{name}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="filter-row">
            <div className="filter-group">
              <label>Sources</label>
              <input
                type="text"
                placeholder="Microsoft-Windows-Security-Auditing"
                value={sources}
                onChange={e => setSources(e.target.value)}
                className="text-input"
              />
            </div>
            <div className="filter-group">
              <label>Users</label>
              <input
                type="text"
                placeholder="DOMAIN\User1,DOMAIN\Admin"
                value={users}
                onChange={e => setUsers(e.target.value)}
                className="text-input"
              />
            </div>
            <div className="filter-group">
              <label>Computers</label>
              <input
                type="text"
                placeholder="WORKSTATION1,SRV01"
                value={computers}
                onChange={e => setComputers(e.target.value)}
                className="text-input"
              />
            </div>
          </div>
          <div className="filter-row">
            <div className="filter-group">
              <label>Level</label>
              <div className="level-checkboxes">
                {['Critical', 'Error', 'Warning', 'Info', 'Debug'].map(level => (
                  <label key={level} className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={selectedLevels.includes(level)}
                      onChange={e => {
                        if (e.target.checked) {
                          setSelectedLevels([...selectedLevels, level])
                        } else {
                          setSelectedLevels(selectedLevels.filter(l => l !== level))
                        }
                      }}
                    />
                    {level}
                  </label>
                ))}
              </div>
            </div>
            <div className="filter-group">
              <label>Sort By</label>
              <select value={sortBy} onChange={e => setSortBy(e.target.value)} className="select-input">
                <option value="timestamp">Timestamp</option>
                <option value="event_id">Event ID</option>
                <option value="level">Level</option>
                <option value="source">Source</option>
                <option value="log_name">Log Name</option>
              </select>
            </div>
            <div className="filter-group">
              <label>Sort Order</label>
              <select value={sortOrder} onChange={e => setSortOrder(e.target.value)} className="select-input">
                <option value="desc">Descending</option>
                <option value="asc">Ascending</option>
              </select>
            </div>
            <div className="filter-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={useRegex}
                  onChange={e => setUseRegex(e.target.checked)}
                />
                Use Regex
              </label>
            </div>
          </div>
          <div className="filter-actions">
            <button onClick={handleSearch} className="btn-primary">Apply Filters</button>
            {searchMode && (
              <button onClick={handleClearSearch} className="btn-secondary">Clear All</button>
            )}
          </div>
        </div>
      )}

      {searchMode && (
        <div className="search-info">
          <span className="search-count">Found <strong>{totalCount.toLocaleString()}</strong> events</span>
          {queryTime > 0 && <span className="query-time">Query time: {queryTime}ms</span>}
        </div>
      )}

      <div className="stats-bar">
        <div className="stat-item">
          <span className="stat-label">Total Events</span>
          <span className="stat-value">{totalCount.toLocaleString()}</span>
        </div>
        <div className="stat-item">
          <span className="stat-label">Current Page</span>
          <span className="stat-value">{page} / {totalPages}</span>
        </div>
      </div>

      {loading ? (
        <div className="loading-state">
          <div className="spinner"></div>
          <div>Loading events...</div>
        </div>
      ) : events.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📋</div>
          <div>No events found</div>
        </div>
      ) : (
        <>
          <div className="table-container">
            <table className="events-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Time</th>
                  <th>Level</th>
                  <th>Event ID</th>
                  <th>Source</th>
                  <th>Computer</th>
                  <th>Message</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {events.map(event => (
                  <tr key={event.id}>
                    <td className="id-cell">{event.id}</td>
                    <td className="time-cell">
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className={`level-badge ${getLevelClass(event.level)}`}>
                        {getLevelLabel(event.level)}
                      </span>
                    </td>
                    <td className="event-id">{event.event_id}</td>
                    <td 
                      className="source-cell"
                      title={event.source || ''}
                    >
                      <span className="cell-content">{event.source || '-'}</span>
                      <button 
                        className="cell-btn"
                        onClick={(e) => {
                          e.stopPropagation()
                          setHoveredEvent(event)
                          setHoverPosition({ x: e.clientX - 200, y: e.clientY + 20 })
                        }}
                        title="View details"
                      >
                        ...
                      </button>
                    </td>
                    <td className="computer-cell">{event.computer || '-'}</td>
                    <td 
                      className="message-cell"
                      title={event.message || ''}
                    >
                      <span className="cell-content" style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'inline-block' }}>
                        {event.message ? (event.message.length > 50 ? event.message.substring(0, 50) + '...' : event.message) : '-'}
                      </span>
                      <button 
                        className="cell-btn"
                        onClick={(e) => {
                          e.stopPropagation()
                          setHoveredEvent(event)
                          setHoverPosition({ x: e.clientX - 200, y: e.clientY + 20 })
                        }}
                        title="View details"
                      >
                        ...
                      </button>
                    </td>
                    <td className="action-cell">
                      <button 
                        className="action-copy-btn" 
                        onClick={() => {
                          navigator.clipboard.writeText(JSON.stringify(event, null, 2))
                        }}
                        title="Copy all event data"
                      >
                        Copy
                      </button>
                      <button 
                        className="action-detail-btn" 
                        onClick={(e) => {
                          setHoveredEvent(event)
                          setHoverPosition({ x: e.clientX - 200, y: e.clientY + 20 })
                        }}
                        title="View details"
                      >
                        ...
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <div className="page-size-selector">
              <span>Show:</span>
              <select 
                value={pageSize} 
                onChange={e => handlePageSizeChange(Number(e.target.value))}
                className="select-input"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
              </select>
              <span>per page</span>
            </div>

            <div className="page-nav">
              <button 
                className="page-btn" 
                disabled={page <= 1} 
                onClick={() => { setPage(1); window.scrollTo({top: 0, behavior: 'smooth'}) }}
              >
                First
              </button>
              <button 
                className="page-btn" 
                disabled={page <= 1} 
                onClick={() => { setPage(p => p - 1); window.scrollTo({top: 0, behavior: 'smooth'}) }}
              >
                Prev
              </button>
              
              <form onSubmit={handlePageInputSubmit} className="page-input-form">
                <input
                  type="number"
                  min={1}
                  max={totalPages}
                  value={pageInput}
                  onChange={e => setPageInput(e.target.value)}
                  placeholder={`1-${totalPages}`}
                  className="page-input"
                />
                <button type="submit" className="page-btn go-btn">Go</button>
              </form>
              
              <span className="page-info">
                Page <strong>{page}</strong> of <strong>{totalPages}</strong>
                ({totalCount} total)
              </span>
              
              <button 
                className="page-btn" 
                disabled={page >= totalPages} 
                onClick={() => { setPage(p => p + 1); window.scrollTo({top: 0, behavior: 'smooth'}) }}
              >
                Next
              </button>
              <button 
                className="page-btn" 
                disabled={page >= totalPages} 
                onClick={() => { setPage(totalPages); window.scrollTo({top: 0, behavior: 'smooth'}) }}
              >
                Last
              </button>
            </div>
          </div>

          {hoveredEvent && (
            <>
              <div 
                className="message-float-panel"
                style={{ 
                  left: hoverPosition.x, 
                  top: hoverPosition.y,
                  position: 'fixed'
                }}
              >
                <div className="float-panel-header">
                  <span>Event Details</span>
                  <div className="float-panel-actions">
                    <button 
                      className="float-panel-copy"
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(hoveredEvent, null, 2))
                      }}
                    >
                      Copy
                    </button>
                    {hoveredEvent.raw_xml && (
                      <button 
                        className="float-panel-formatted"
                        onClick={() => {
                          const formatted = (() => {
                            try {
                              return JSON.stringify(JSON.parse(hoveredEvent.raw_xml!), null, 2)
                            } catch {
                              return hoveredEvent.raw_xml || ''
                            }
                          })()
                          navigator.clipboard.writeText(formatted)
                        }}
                      >
                        Copy JSON
                      </button>
                    )}
                    {hoveredEvent.raw_xml && (
                      <button 
                        className="float-panel-view"
                        onClick={() => setShowRawModal(true)}
                      >
                        View JSON
                      </button>
                    )}
                    <button 
                      className="float-panel-close"
                      onClick={() => { setHoveredEvent(null); setShowRawModal(false); }}
                    >
                      ×
                    </button>
                  </div>
                </div>
                <div className="float-panel-content">
                  <div><strong>ID:</strong> {hoveredEvent.id}</div>
                  <div><strong>Time:</strong> {new Date(hoveredEvent.timestamp).toLocaleString()}</div>
                  <div><strong>Level:</strong> {hoveredEvent.level}</div>
                  <div><strong>Event ID:</strong> {hoveredEvent.event_id}</div>
                  <div><strong>Source:</strong> {hoveredEvent.source || '-'}</div>
                  <div><strong>Computer:</strong> {hoveredEvent.computer || '-'}</div>
                  <div><strong>Log Name:</strong> {hoveredEvent.log_name}</div>
                  <div style={{marginTop: '8px'}}><strong>Message:</strong></div>
                  <div>{hoveredEvent.message || '-'}</div>
                </div>
              </div>

              {showRawModal && hoveredEvent.raw_xml && (
                <div className="modal-overlay" onClick={() => setShowRawModal(false)}>
                  <div className="modal-content modal-large" onClick={e => e.stopPropagation()}>
                    <div className="modal-header">
                      <span>Raw JSON - Event #{hoveredEvent.id}</span>
                      <button className="modal-close" onClick={() => setShowRawModal(false)}>×</button>
                    </div>
                    <div className="modal-body">
                      <pre className="json-large">{(() => {
                        try {
                          return JSON.stringify(JSON.parse(hoveredEvent.raw_xml!), null, 2)
                        } catch {
                          return hoveredEvent.raw_xml
                        }
                      })()}</pre>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}

      <style>{`
        .events-page {
          padding: 20px;
          height: 100%;
          display: flex;
          flex-direction: column;
        }
        
        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }
        
        .events-page h2 {
          font-size: 1.8rem;
          color: #00d9ff;
          margin: 0;
        }
        
        .header-actions {
          display: flex;
          gap: 10px;
        }
        
        .btn-secondary {
          padding: 8px 16px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .btn-secondary:hover {
          background: rgba(255, 255, 255, 0.1);
          border-color: #00d9ff;
        }
        
        .export-dropdown {
          position: relative;
        }
        
        .export-menu {
          display: none;
          position: absolute;
          top: 100%;
          right: 0;
          background: #1a1a2e;
          border: 1px solid #333;
          border-radius: 6px;
          overflow: hidden;
          z-index: 100;
        }
        
        .export-dropdown:hover .export-menu {
          display: block;
        }
        
        .export-menu button {
          display: block;
          width: 100%;
          padding: 10px 20px;
          background: none;
          border: none;
          color: #fff;
          text-align: left;
          cursor: pointer;
        }
        
        .export-menu button:hover {
          background: rgba(0, 217, 255, 0.1);
        }
        
        .search-bar {
          margin-bottom: 16px;
        }
        
        .search-input-wrapper {
          display: flex;
          gap: 8px;
        }
        
        .search-input-wrapper input {
          flex: 1;
          padding: 12px 16px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 8px;
          color: #fff;
          font-size: 14px;
        }
        
        .search-input-wrapper input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .search-btn {
          padding: 12px 24px;
          background: #00d9ff;
          border: none;
          border-radius: 8px;
          color: #000;
          font-weight: 600;
          cursor: pointer;
        }
        
        .keyword-mode-toggle {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-left: 12px;
        }
        
        .mode-label {
          color: #888;
          font-size: 13px;
        }
        
        .mode-btn {
          padding: 6px 12px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 4px;
          color: #888;
          font-size: 12px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .mode-btn:hover {
          border-color: #00d9ff;
          color: #00d9ff;
        }
        
        .mode-btn.active {
          background: rgba(0, 217, 255, 0.1);
          border-color: #00d9ff;
          color: #00d9ff;
        }
        
        .filters-panel {
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid #333;
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 16px;
        }
        
        .filter-row {
          display: flex;
          gap: 20px;
          flex-wrap: wrap;
        }
        
        .filter-group {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        
        .filter-group label {
          font-size: 12px;
          color: #888;
          text-transform: uppercase;
        }
        
        .filter-group input[type="datetime-local"] {
          padding: 8px 12px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
        }
        
        .filter-group .text-input {
          padding: 8px 12px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          font-size: 13px;
          min-width: 150px;
        }
        
        .filter-group .text-input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .filter-group .select-input {
          padding: 8px 12px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          font-size: 13px;
          cursor: pointer;
        }
        
        .filter-group .select-input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .filter-group .select-input option {
          background: #16213e;
          color: #eee;
        }
        
        .page-size-selector .select-input option {
          background: #16213e;
          color: #eee;
        }
        
        .select-input option {
          background: #16213e;
          color: #eee;
        }
        
        .level-checkboxes {
          display: flex;
          gap: 12px;
        }
        
        .checkbox-label {
          display: flex;
          align-items: center;
          gap: 4px;
          font-size: 13px;
          color: #ddd;
          cursor: pointer;
        }
        
        .filter-actions {
          display: flex;
          gap: 10px;
          margin-top: 16px;
          padding-top: 16px;
          border-top: 1px solid #333;
        }
        
        .btn-primary {
          padding: 8px 20px;
          background: #00d9ff;
          border: none;
          border-radius: 6px;
          color: #000;
          font-weight: 600;
          cursor: pointer;
        }
        
        .search-info {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 12px 16px;
          background: rgba(0, 217, 255, 0.1);
          border-radius: 8px;
          margin-bottom: 16px;
        }
        
        .search-count {
          color: #00d9ff;
        }
        
        .query-time {
          color: #888;
          font-size: 13px;
        }
        
        .stats-bar {
          display: flex;
          gap: 20px;
          margin-bottom: 16px;
        }
        
        .stat-item {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        
        .stat-label {
          font-size: 11px;
          color: #888;
          text-transform: uppercase;
        }
        
        .stat-value {
          font-size: 18px;
          font-weight: 600;
          color: #fff;
        }
        
        .loading-state, .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 300px;
          gap: 16px;
          color: #888;
        }
        
        .spinner {
          width: 40px;
          height: 40px;
          border: 3px solid #16213e;
          border-top: 3px solid #00d9ff;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        
        .empty-icon {
          font-size: 48px;
        }
        
        .table-container {
          flex: 1;
          overflow: auto;
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          border: 1px solid #333;
        }
        
        .events-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 13px;
        }
        
        .events-table th {
          background: rgba(0, 217, 255, 0.1);
          color: #00d9ff;
          padding: 14px 12px;
          text-align: left;
          font-weight: 600;
          position: sticky;
          top: 0;
          white-space: nowrap;
        }
        
        .events-table td {
          padding: 12px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
          color: #ddd;
        }
        
        .events-table tr:hover td {
          background: rgba(255, 255, 255, 0.02);
        }
        
        .id-cell {
          color: #888;
          font-family: monospace;
          font-size: 12px;
        }
        
        .time-cell {
          white-space: nowrap;
          color: #888;
          font-size: 12px;
        }
        
        .level-badge {
          display: inline-block;
          padding: 3px 8px;
          border-radius: 4px;
          font-size: 11px;
          font-weight: 600;
          text-transform: uppercase;
        }
        
        .level-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .level-error { background: rgba(239, 68, 68, 0.15); color: #f87171; }
        .level-warning { background: rgba(245, 158, 11, 0.2); color: #f59e0b; }
        .level-info { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
        .level-debug { background: rgba(107, 114, 128, 0.2); color: #9ca3af; }
        
        .event-id {
          font-family: monospace;
          color: #00d9ff;
        }
        
        .source-cell, .computer-cell {
          max-width: 120px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        
        .message-cell {
          max-width: 400px;
        }
        
        .cell-btn {
          background: transparent;
          border: none;
          color: #555;
          cursor: pointer;
          font-size: 14px;
          font-weight: bold;
          padding: 0 4px;
          margin-left: 4px;
        }
        
        .cell-btn:hover {
          color: #00d9ff;
        }
        
        .message-float-panel {
          position: fixed;
          width: 400px;
          max-height: 500px;
          overflow: hidden;
          background: #0a0a1a;
          border: 1px solid #00d9ff;
          border-radius: 8px;
          padding: 0;
          z-index: 1000;
          box-shadow: 0 4px 20px rgba(0, 217, 255, 0.3);
        }
        
        .float-panel-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 8px 12px;
          background: rgba(0, 217, 255, 0.1);
          border-bottom: 1px solid #00d9ff;
        }
        
        .float-panel-header span {
          font-weight: bold;
          color: #00d9ff;
        }
        
        .float-panel-actions {
          display: flex;
          gap: 8px;
          align-items: center;
        }
        
        .float-panel-close {
          background: none;
          border: none;
          color: #888;
          cursor: pointer;
          font-size: 16px;
          padding: 0 4px;
          margin-left: 8px;
        }
        
        .float-panel-close:hover {
          color: #fff;
        }
        
        .float-panel-copy {
          background: #444;
          border: 1px solid #555;
          color: #fff;
          cursor: pointer;
          font-size: 12px;
          padding: 2px 8px;
          border-radius: 3px;
        }
        
        .float-panel-copy:hover {
          background: #555;
          border-color: #666;
        }
        
        .float-panel-formatted {
          background: #1a4d1a;
          border: 1px solid #2e7d32;
          color: #fff;
          cursor: pointer;
          font-size: 12px;
          padding: 2px 8px;
          border-radius: 3px;
        }
        
        .float-panel-formatted:hover {
          background: #2e7d32;
        }
        
        .float-panel-view {
          background: #1a3d5c;
          border: 1px solid #00d9ff;
          color: #00d9ff;
          cursor: pointer;
          font-size: 12px;
          padding: 2px 8px;
          border-radius: 3px;
        }
        
        .float-panel-view:hover {
          background: #00d9ff;
          color: #0a0a1a;
        }
        
        .float-panel-content {
          padding: 12px;
          max-height: 540px;
          overflow: auto;
          white-space: pre-wrap;
          word-break: break-all;
          margin: 0;
          font-size: 12px;
          color: #ccc;
        }
        
        .timestamp-toggle.active {
          color: #00d9ff;
          background: rgba(0, 217, 255, 0.1);
        }
        
        .pagination {
          display: flex;
          align-items: center;
          justify-content: space-between;
          flex-wrap: wrap;
          gap: 16px;
          padding: 16px;
          margin-top: 16px;
        }
        
        .page-size-selector {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #888;
        }
        
        .page-size-selector .select-input {
          padding: 6px 10px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          cursor: pointer;
        }
        
        .page-nav {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        
        .page-btn {
          padding: 8px 14px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .page-btn:hover:not(:disabled) {
          background: rgba(0, 217, 255, 0.1);
          border-color: #00d9ff;
        }
        
        .page-btn:disabled {
          opacity: 0.3;
          cursor: not-allowed;
        }
        
        .page-input-form {
          display: flex;
          align-items: center;
          gap: 4px;
        }
        
        .page-input {
          width: 70px;
          padding: 8px 10px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          text-align: center;
        }
        
        .page-input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .page-input::-webkit-inner-spin-button,
        .page-input::-webkit-outer-spin-button {
          -webkit-appearance: none;
          margin: 0;
        }
        
        .go-btn {
          padding: 8px 12px;
          background: rgba(0, 217, 255, 0.1);
          border-color: #00d9ff;
        }
        
        .page-info {
          padding: 0 16px;
          color: #888;
        }
        
        .page-info strong {
          color: #00d9ff;
        }
        
        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.85);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 2000;
        }
        
        .modal-content {
          background: #0a0a1a;
          border: 1px solid #00d9ff;
          border-radius: 8px;
          max-width: 90vw;
          max-height: 90vh;
          overflow: hidden;
        }
        
        .modal-large {
          width: 90vw;
          height: 85vh;
        }
        
        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 15px 20px;
          background: #1a1a2e;
          border-bottom: 1px solid #333;
        }
        
        .modal-header span {
          font-weight: bold;
          color: #00d9ff;
        }
        
        .modal-close {
          background: none;
          border: none;
          color: #e0e0e0;
          font-size: 24px;
          cursor: pointer;
          padding: 0;
          line-height: 1;
        }
        
        .modal-close:hover {
          color: #00d9ff;
        }
        
        .modal-body {
          padding: 20px;
          overflow: auto;
          max-height: calc(85vh - 60px);
        }
        
        .json-large {
          margin: 0;
          font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
          font-size: 13px;
          line-height: 1.5;
          color: #e0e0e0;
          white-space: pre-wrap;
          word-break: break-all;
        }
      `}</style>
    </div>
  )
}

export default Events
