import { useEffect, useState } from 'react'
import { useI18n } from '../locales/I18n'
import { logsAPI, LogEntry, LogFileInfo } from '../api'

function Logs() {
  const { t } = useI18n()
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [files, setFiles] = useState<LogFileInfo[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [limit] = useState(100)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [filterType, setFilterType] = useState<string>('all')
  const [keyword, setKeyword] = useState<string>('')

  useEffect(() => {
    fetchLogFiles()
    fetchLogs()
  }, [])

  const fetchLogFiles = () => {
    logsAPI.getLogFiles()
      .then(res => res.data)
      .then(data => {
        setFiles(data.files || [])
      })
      .catch(console.error)
  }

  const fetchLogs = (newOffset = 0) => {
    setLoading(true)
    setError(null)

    const { level, category } = getFilterParams(filterType)

    logsAPI.getLogs({
      offset: newOffset,
      limit: limit,
      keyword: keyword,
      level,
      category,
    })
      .then(res => res.data)
      .then(data => {
        setLogs(data.entries || [])
        setTotal(data.total || 0)
        setOffset(newOffset)
        setLoading(false)
      })
      .catch(err => {
        setError(err.message || t('common.error'))
        setLoading(false)
      })
  }

  const handleRefresh = () => {
    fetchLogs(offset)
  }

  const getFilterParams = (filter: string): { level: string; category: string } => {
    switch (filter) {
      case 'all': return { level: 'all', category: 'all' }
      case 'debug': return { level: 'debug', category: 'all' }
      case 'info': return { level: 'info', category: 'all' }
      case 'warn': return { level: 'warn', category: 'all' }
      case 'error': return { level: 'error', category: 'all' }
      case 'metrics': return { level: 'all', category: 'metrics' }
      case 'api': return { level: 'all', category: 'api' }
      case 'startup': return { level: 'all', category: 'startup' }
      case 'panic': return { level: 'all', category: 'panic' }
      case 'general': return { level: 'all', category: 'general' }
      default: return { level: 'all', category: 'all' }
    }
  }

  const handleFilter = (filter: string) => {
    setFilterType(filter)
    setOffset(0)
    fetchLogs(0)
  }

  const handleKeywordSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setOffset(0)
    fetchLogs(0)
  }

  const handleClearKeyword = () => {
    setKeyword('')
    setOffset(0)
    fetchLogs(0)
  }

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'debug': return '#888'
      case 'info': return '#00d9ff'
      case 'warn': return '#f59e0b'
      case 'error': return '#ef4444'
      case 'fatal': return '#dc2626'
      default: return '#888'
    }
  }

  const filteredLogs = logs.filter(log => {
    const { level, category } = getFilterParams(filterType)
    const levelMatch = level === 'all' || log.level.toLowerCase() === level.toLowerCase()
    const categoryMatch = category === 'all' || log.category === category ||
      (category === 'metrics' && (log.message === '[METRICS]' || log.category === 'metrics')) ||
      (category === 'startup' && (log.message === '[STARTUP]' || log.category === 'startup')) ||
      (category === 'api' && (log.message === '[API]' || log.category === 'api')) ||
      (category === 'error' && (log.message === '[ERROR]' || log.category === 'error')) ||
      (category === 'panic' && (log.message === '[PANIC]' || log.message === '[FATAL]' || log.category === 'panic')) ||
      (category === 'general' && (log.category === 'general' || !log.category || log.category === 'undefined'))
    return levelMatch && categoryMatch
  })

  const isMetricsEntry = (log: LogEntry) => log.message === '[METRICS]' || log.category === 'metrics'
  const isStartupEntry = (log: LogEntry) => log.message === '[STARTUP]' || log.category === 'startup'
  const isPanicEntry = (log: LogEntry) => log.message === '[PANIC]' || log.message === '[FATAL]' || log.category === 'panic'
  const isApiEntry = (log: LogEntry) => log.message === '[API]' || log.category === 'api'

  const formatTime = (timestamp: string) => {
    try {
      const date = new Date(timestamp)
      return date.toLocaleString()
    } catch {
      return timestamp
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const totalPages = Math.ceil(total / limit)
  const currentPage = Math.floor(offset / limit) + 1

  return (
    <div className="logs-page">
      <div className="page-header">
        <h2>{t('logs.title')}</h2>
        <button onClick={handleRefresh} className="btn-secondary" disabled={loading}>
          {loading ? t('common.loading') : t('logs.refresh')}
        </button>
      </div>

      <div className="logs-info">
        <div className="info-card">
          <span className="info-label">{t('logs.totalEntries')}:</span>
          <span className="info-value">{total}</span>
        </div>
        <div className="info-card">
          <span className="info-label">{t('logs.currentPage')}:</span>
          <span className="info-value">{currentPage} / {totalPages}</span>
        </div>
        <div className="info-card">
          <span className="info-label">{t('logs.logFiles')}:</span>
          <span className="info-value">{files.length}</span>
        </div>
      </div>

      <div className="logs-filters">
        <div className="filter-group">
          <span className="filter-label">{t('logs.filterByLevel')}:</span>
          <button
            className={`filter-btn ${filterType === 'all' ? 'active' : ''}`}
            onClick={() => handleFilter('all')}
          >
            {t('logs.all')}
          </button>
          <button
            className={`filter-btn ${filterType === 'debug' ? 'active' : ''}`}
            onClick={() => handleFilter('debug')}
          >
            {t('settings.debug')}
          </button>
          <button
            className={`filter-btn ${filterType === 'info' ? 'active' : ''}`}
            onClick={() => handleFilter('info')}
          >
            {t('settings.info')}
          </button>
          <button
            className={`filter-btn ${filterType === 'warn' ? 'active' : ''}`}
            onClick={() => handleFilter('warn')}
          >
            {t('settings.warn')}
          </button>
          <button
            className={`filter-btn ${filterType === 'error' ? 'active' : ''}`}
            onClick={() => handleFilter('error')}
          >
            {t('settings.error')}
          </button>
          <button
            className={`filter-btn ${filterType === 'metrics' ? 'active' : ''}`}
            onClick={() => handleFilter('metrics')}
          >
            {t('logs.metrics')}
          </button>
          <button
            className={`filter-btn ${filterType === 'api' ? 'active' : ''}`}
            onClick={() => handleFilter('api')}
          >
            {t('logs.api')}
          </button>
          <button
            className={`filter-btn ${filterType === 'startup' ? 'active' : ''}`}
            onClick={() => handleFilter('startup')}
          >
            {t('logs.startup')}
          </button>
          <button
            className={`filter-btn ${filterType === 'panic' ? 'active' : ''}`}
            onClick={() => handleFilter('panic')}
          >
            {t('logs.panic')}
          </button>
          <button
            className={`filter-btn ${filterType === 'general' ? 'active' : ''}`}
            onClick={() => handleFilter('general')}
          >
            {t('logs.general')}
          </button>
        </div>
        <div className="filter-group search-group">
          <form onSubmit={handleKeywordSearch} className="search-form">
            <input
              type="text"
              className="search-input"
              placeholder={t('events.searchPlaceholder')}
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
            />
            <button type="submit" className="filter-btn">{t('events.search')}</button>
            {keyword && (
              <button type="button" className="filter-btn" onClick={handleClearKeyword}>
                {t('logs.clearSearch')}
              </button>
            )}
          </form>
        </div>
      </div>

      <div className="logs-files">
        <h3>{t('logs.logFiles')}</h3>
        <div className="files-list">
          {files.map((file, idx) => (
            <div key={idx} className="file-item">
              <span className="file-name">{file.name}</span>
              <span className="file-size">{formatSize(file.size)}</span>
              <span className="file-time">{new Date(file.mod_time).toLocaleString()}</span>
              {file.is_main && <span className="file-badge">{t('logs.current')}</span>}
            </div>
          ))}
        </div>
      </div>

      <div className="logs-viewer">
        <h3>{t('logs.viewer')}</h3>
        {error && <div className="error-message">{error}</div>}
        
        <div className="logs-container">
          {loading ? (
            <div className="loading-state">{t('common.loading')}</div>
          ) : filteredLogs.length === 0 ? (
            <div className="empty-state">{t('logs.noLogs')}</div>
          ) : (
            <table className="logs-table">
              <thead>
                <tr>
                  <th>{t('logs.timestamp')}</th>
                  <th>{t('logs.level')}</th>
                  <th>{t('logs.category')}</th>
                  <th>{t('logs.message')}</th>
                  <th>{t('logs.details')}</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log, idx) => (
                  <tr key={idx} className={`log-entry log-level-${log.level.toLowerCase()}`}>
                    <td className="log-time">{formatTime(log.timestamp)}</td>
                    <td className="log-level" style={{ color: getLevelColor(log.level) }}>
                      {log.level.toUpperCase()}
                    </td>
                    <td className="log-category">
                      {isMetricsEntry(log) && <span className="log-badge metrics">{t('logs.metrics')}</span>}
                      {isStartupEntry(log) && <span className="log-badge startup">{t('logs.startup')}</span>}
                      {isPanicEntry(log) && <span className="log-badge panic">{t('logs.panic')}</span>}
                      {isApiEntry(log) && <span className="log-badge api">API</span>}
                      {!isMetricsEntry(log) && !isStartupEntry(log) && !isPanicEntry(log) && !isApiEntry(log) && (
                        <span className="log-badge general">{log.category || 'general'}</span>
                      )}
                    </td>
                    <td className="log-message">
                      {log.message}
                    </td>
                    <td className="log-details">
                      {isMetricsEntry(log) && (
                        <div className="metrics-details">
                          <span className="metric-item">Mem Alloc: <b>{log.mem_alloc_mb?.toFixed(2)} MB</b></span>
                          <span className="metric-item">Total: <b>{log.mem_total_mb?.toFixed(2)} MB</b></span>
                          <span className="metric-item">Sys: <b>{log.mem_sys_mb?.toFixed(2)} MB</b></span>
                          <span className="metric-item">Goroutines: <b>{log.num_goroutine}</b></span>
                          <span className="metric-item">CPU: <b>{log.num_cpu}</b></span>
                          <span className="metric-item">Heap Objects: <b>{log.heap_objects?.toLocaleString()}</b></span>
                        </div>
                      )}
                      {isApiEntry(log) && (
                        <div className="api-details">
                          <span className="api-method">{log.method}</span>
                          <span className="api-path">{log.path}</span>
                          <span className="api-status" style={{ color: log.status && log.status >= 400 ? '#ef4444' : '#22c55e' }}>{log.status}</span>
                          <span className="api-latency">{log.latency}</span>
                          <span className="api-ip">{log.client_ip}</span>
                        </div>
                      )}
                      {isStartupEntry(log) && (
                        <span className="startup-reason">Reason: {log.reason}</span>
                      )}
                      {isPanicEntry(log) && (
                        <div className="panic-details">
                          <span className="panic-error">{log.error}</span>
                          <span className="panic-path">Path: {log.path}</span>
                        </div>
                      )}
                      {!isMetricsEntry(log) && !isStartupEntry(log) && !isPanicEntry(log) && !isApiEntry(log) && log.error && (
                        <div className="error-details">
                          <span className="error-module"> Module: {log.module}</span>
                          <span className="error-msg">{log.error}</span>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="pagination">
          <button 
            onClick={() => fetchLogs(0)} 
            disabled={offset === 0 || loading}
          >
            {t('logs.first')}
          </button>
          <button 
            onClick={() => fetchLogs(Math.max(0, offset - limit))}
            disabled={offset === 0 || loading}
          >
            {t('events.previous')}
          </button>
          <span className="page-info">
            {t('events.page', { page: currentPage, total: totalPages })}
          </span>
          <button 
            onClick={() => fetchLogs(offset + limit)}
            disabled={offset + limit >= total || loading}
          >
            {t('events.next')}
          </button>
          <button 
            onClick={() => fetchLogs(Math.max(0, (totalPages - 1) * limit))}
            disabled={offset + limit >= total || loading}
          >
            {t('logs.last')}
          </button>
        </div>
      </div>

      <style>{`
        .logs-page {
          padding: 20px;
          height: 100%;
          display: flex;
          flex-direction: column;
          gap: 16px;
        }
        
        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        
        .page-header h2 {
          font-size: 1.8rem;
          color: #00d9ff;
          margin: 0;
        }
        
        .logs-info {
          display: flex;
          gap: 16px;
        }
        
        .info-card {
          background: rgba(255, 255, 255, 0.05);
          padding: 12px 20px;
          border-radius: 8px;
          display: flex;
          gap: 8px;
        }
        
        .info-label {
          color: #888;
        }
        
        .info-value {
          color: #fff;
          font-weight: 600;
        }
        
        .logs-filters {
          display: flex;
          gap: 16px;
          align-items: center;
        }
        
        .filter-group {
          display: flex;
          gap: 8px;
          align-items: center;
        }
        
        .filter-label {
          color: #888;
          margin-right: 8px;
        }
        
        .filter-btn {
          padding: 8px 16px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #888;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .filter-btn:hover {
          background: rgba(255, 255, 255, 0.1);
          color: #fff;
        }
        
        .filter-btn.active {
          background: rgba(0, 217, 255, 0.2);
          border-color: #00d9ff;
          color: #00d9ff;
        }
        
        .search-group {
          margin-left: auto;
        }
        
        .search-form {
          display: flex;
          gap: 8px;
          align-items: center;
        }
        
        .search-input {
          padding: 8px 12px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          font-size: 13px;
          min-width: 200px;
        }
        
        .search-input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .search-input::placeholder {
          color: #666;
        }
        
        .logs-files {
          background: rgba(255, 255, 255, 0.02);
          padding: 16px;
          border-radius: 8px;
          border: 1px solid #333;
        }
        
        .logs-files h3 {
          color: #fff;
          margin: 0 0 12px 0;
          font-size: 1rem;
        }
        
        .files-list {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        
        .file-item {
          display: flex;
          align-items: center;
          gap: 16px;
          padding: 8px 12px;
          background: rgba(255, 255, 255, 0.02);
          border-radius: 6px;
        }
        
        .file-name {
          color: #00d9ff;
          font-family: monospace;
          flex: 1;
        }
        
        .file-size {
          color: #888;
          font-size: 13px;
        }
        
        .file-time {
          color: #666;
          font-size: 12px;
        }
        
        .file-badge {
          background: rgba(0, 217, 255, 0.2);
          color: #00d9ff;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 11px;
        }
        
        .logs-viewer {
          flex: 1;
          display: flex;
          flex-direction: column;
          background: rgba(255, 255, 255, 0.02);
          border-radius: 8px;
          border: 1px solid #333;
          overflow: hidden;
        }
        
        .logs-viewer h3 {
          color: #fff;
          margin: 0;
          padding: 16px;
          border-bottom: 1px solid #333;
          font-size: 1rem;
        }
        
        .logs-container {
          flex: 1;
          overflow: auto;
          max-height: 500px;
        }
        
        .logs-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 13px;
        }
        
        .logs-table th {
          background: rgba(255, 255, 255, 0.05);
          color: #888;
          text-align: left;
          padding: 10px 12px;
          font-weight: 500;
          position: sticky;
          top: 0;
        }
        
        .logs-table td {
          padding: 8px 12px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .log-time {
          color: #888;
          font-family: monospace;
          white-space: nowrap;
          width: 180px;
        }
        
        .log-level {
          font-weight: 600;
          width: 80px;
        }
        
        .log-message {
          color: #e0e0e0;
          font-family: monospace;
          word-break: break-word;
        }
        
        .log-details {
          color: #888;
          font-size: 12px;
          font-family: monospace;
        }
        
        .log-badge {
          display: inline-block;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 10px;
          margin-right: 6px;
        }
        
        .log-badge.metrics {
          background: rgba(139, 92, 246, 0.2);
          color: #a78bfa;
        }
        
        .log-badge.startup {
          background: rgba(34, 197, 94, 0.2);
          color: #4ade80;
        }
        
        .log-badge.panic {
          background: rgba(239, 68, 68, 0.2);
          color: #ef4444;
        }
        
        .metrics-info {
          color: #a78bfa;
        }
        
        .api-info {
          color: #888;
        }
        
        .error-info {
          color: #ef4444;
        }
        
        .metrics-details {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }
        
        .metric-item {
          color: #a78bfa;
          font-size: 11px;
          background: rgba(139, 92, 246, 0.1);
          padding: 2px 6px;
          border-radius: 4px;
        }
        
        .metric-item b {
          color: #c4b5fd;
        }
        
        .api-details {
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
          align-items: center;
        }
        
        .api-method {
          color: #22c55e;
          font-weight: 600;
          font-size: 11px;
          background: rgba(34, 197, 94, 0.1);
          padding: 2px 6px;
          border-radius: 4px;
        }
        
        .api-path {
          color: #60a5fa;
          font-size: 11px;
          max-width: 200px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        
        .api-status {
          font-weight: 600;
          font-size: 11px;
        }
        
        .api-latency {
          color: #888;
          font-size: 11px;
        }
        
        .api-ip {
          color: #666;
          font-size: 10px;
        }
        
        .startup-reason {
          color: #4ade80;
          font-size: 12px;
        }
        
        .panic-details {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        
        .panic-error {
          color: #ef4444;
          font-size: 12px;
          font-weight: 500;
        }
        
        .panic-path {
          color: #888;
          font-size: 11px;
        }
        
        .error-details {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        
        .error-module {
          color: #f59e0b;
          font-size: 11px;
        }
        
        .error-msg {
          color: #ef4444;
          font-size: 12px;
        }
        
        .log-entry:hover {
          background: rgba(255, 255, 255, 0.02);
        }
        
        .pagination {
          display: flex;
          gap: 8px;
          align-items: center;
          padding: 12px 16px;
          border-top: 1px solid #333;
          background: rgba(255, 255, 255, 0.02);
        }
        
        .pagination button {
          padding: 8px 16px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #888;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .pagination button:hover:not(:disabled) {
          background: rgba(255, 255, 255, 0.1);
          color: #fff;
        }
        
        .pagination button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        
        .page-info {
          color: #888;
          margin: 0 auto;
        }
        
        .loading-state, .empty-state {
          padding: 40px;
          text-align: center;
          color: #888;
        }
        
        .error-message {
          padding: 12px;
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
          border-radius: 6px;
          color: #ef4444;
          margin: 16px;
        }
        
        .btn-secondary {
          padding: 10px 20px;
          background: transparent;
          border: 1px solid #333;
          border-radius: 8px;
          color: #888;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .btn-secondary:hover:not(:disabled) {
          border-color: #00d9ff;
          color: #00d9ff;
        }
      `}</style>
    </div>
  )
}

export default Logs
