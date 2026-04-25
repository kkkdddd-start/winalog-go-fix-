import { useState, useRef, useEffect } from 'react'
import { useI18n } from '../locales/I18n'
import { queryAPI } from '../api'

interface QueryResponse {
  columns: string[]
  rows: Record<string, any>[]
  count: number
  total: number
}

interface QueryHistoryItem {
  id: string
  sql: string
  timestamp: string
  success: boolean
  rowCount: number
  duration?: string
}

function Query() {
  const { t } = useI18n()
  const [sql, setSql] = useState('SELECT * FROM events LIMIT 10')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<QueryResponse | null>(null)
  const [error, setError] = useState('')
  const [history, setHistory] = useState<QueryHistoryItem[]>([])
  const [showHistory, setShowHistory] = useState(false)
  const [executionTime, setExecutionTime] = useState<string>('')
  const [dbStatus, setDbStatus] = useState<'unknown' | 'connected' | 'disconnected'>('unknown')
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const checkDbConnection = async () => {
    try {
      await queryAPI.execute({ sql: 'SELECT 1 as test', limit: 1 })
      setDbStatus('connected')
    } catch (err: any) {
      setDbStatus('disconnected')
    }
  }

  useEffect(() => {
    checkDbConnection()
  }, [])

  const handleExecute = async () => {
    if (!sql.trim()) {
      setError(t('query.sqlRequired'))
      return
    }

    setLoading(true)
    setError('')
    setResult(null)
    const startTime = performance.now()

    try {
      const res = await queryAPI.execute({ sql, limit: 100 })
      const duration = ((performance.now() - startTime) / 1000).toFixed(2)
      setExecutionTime(duration)
      setResult(res.data)
      addToHistory(sql, true, res.data.count, duration)
    } catch (err: any) {
      const duration = ((performance.now() - startTime) / 1000).toFixed(2)
      const statusCode = err.response?.status
      const backendError = err.response?.data?.error
      let errorMsg = 'Failed to execute query'
      if (statusCode === 400) {
        errorMsg = backendError || 'Invalid SQL query'
      } else if (statusCode === 500) {
        errorMsg = backendError || 'Database error'
      } else if (!err.response) {
        errorMsg = 'Cannot connect to server - is the API running?'
      } else {
        errorMsg = backendError || err.message
      }
      if (statusCode) {
        errorMsg = `[${statusCode}] ${errorMsg}`
      }
      setError(errorMsg)
      addToHistory(sql, false, 0, duration)
    } finally {
      setLoading(false)
    }
  }

  const addToHistory = (sqlQuery: string, success: boolean, rowCount: number, duration?: string) => {
    const newItem: QueryHistoryItem = {
      id: Date.now().toString(),
      sql: sqlQuery,
      timestamp: new Date().toISOString(),
      success,
      rowCount,
      duration,
    }
    setHistory(prev => [newItem, ...prev.slice(0, 49)])
  }

  const loadFromHistory = (item: QueryHistoryItem) => {
    setSql(item.sql)
    setShowHistory(false)
  }

  const clearHistory = () => {
    setHistory([])
  }

  const highlightSQL = (query: string): JSX.Element => {
    const keywords = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON', 'GROUP', 'BY', 'ORDER', 'HAVING', 'LIMIT', 'OFFSET', 'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE', 'CREATE', 'TABLE', 'DROP', 'ALTER', 'INDEX', 'AS', 'ASC', 'DESC', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'LIKE', 'IN', 'BETWEEN', 'IS', 'NULL', 'NOT', 'EXISTS', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'UNION', 'ALL', 'INTO', 'OUTFILE']
    const functions = ['COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'COALESCE', 'IFNULL', 'NULLIF', 'CAST', 'DATE', 'TIME', 'DATETIME', 'STRFTIME', 'SUBSTR', 'LENGTH', 'UPPER', 'LOWER', 'TRIM', 'REPLACE', 'GROUP_CONCAT']
    const operators = ['=', '!=', '<>', '<', '>', '<=', '>=', '+', '-', '*', '/', '%', '||']
    
    const parts: JSX.Element[] = []
    const regex = /('[^']*'|"[^"]*"|\b(?:[\w]+)\b|[=<>!+\-*/%,()]+|\S)/g
    const tokens = query.match(regex) || []
    
    let key = 0
    for (const token of tokens) {
      const upperToken = token.toUpperCase()
      
      if (token.startsWith("'") && token.endsWith("'")) {
        parts.push(<span key={key++} className="sql-string">{token}</span>)
      } else if (token.startsWith('"') && token.endsWith('"')) {
        parts.push(<span key={key++} className="sql-string">{token}</span>)
      } else if (operators.includes(token)) {
        parts.push(<span key={key++} className="sql-operator">{token}</span>)
      } else if (functions.includes(upperToken)) {
        parts.push(<span key={key++} className="sql-function">{token}</span>)
      } else if (keywords.includes(upperToken)) {
        parts.push(<span key={key++} className="sql-keyword">{token}</span>)
      } else if (/^\d+$/.test(token)) {
        parts.push(<span key={key++} className="sql-number">{token}</span>)
      } else {
        parts.push(<span key={key++} className="sql-identifier">{token}</span>)
      }
    }
    
    return <>{parts}</>
  }

  const presetQueries = [
    { label: t('query.presetEvents') || 'Top Events', sql: 'SELECT event_id, COUNT(*) as cnt FROM events GROUP BY event_id ORDER BY cnt DESC LIMIT 10' },
    { label: t('query.presetAlerts') || 'Recent Alerts', sql: 'SELECT * FROM alerts ORDER BY first_seen DESC LIMIT 10' },
    { label: t('query.presetAuth') || 'Auth Events', sql: 'SELECT * FROM events WHERE event_id IN (4624, 4625, 4648) ORDER BY timestamp DESC LIMIT 20' },
    { label: t('query.presetPowerShell') || 'PowerShell', sql: "SELECT * FROM events WHERE message LIKE '%PowerShell%' LIMIT 10" },
    { label: t('query.presetSchema') || 'DB Schema', sql: "SELECT name, type FROM sqlite_master WHERE type='table'" },
    { label: t('query.presetTimeline') || 'Event Timeline', sql: 'SELECT timestamp, event_id, computer, message FROM events ORDER BY timestamp DESC LIMIT 20' },
  ]

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      handleExecute()
    }
  }

  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    const highlight = document.querySelector('.sql-highlight') as HTMLElement
    if (highlight) {
      highlight.scrollTop = e.currentTarget.scrollTop
      highlight.scrollLeft = e.currentTarget.scrollLeft
    }
  }

  const exportResults = (format: 'json' | 'csv') => {
    if (!result) return
    
    let content: string
    let filename: string
    let mimeType: string

    if (format === 'json') {
      content = JSON.stringify(result, null, 2)
      filename = 'query_result.json'
      mimeType = 'application/json'
    } else {
      const header = result.columns.join(',')
      const rows = result.rows.map(row => 
        result.columns.map(col => {
          const val = row[col]
          if (val === null || val === undefined) return ''
          const str = String(val)
          return str.includes(',') || str.includes('"') ? `"${str.replace(/"/g, '""')}"` : str
        }).join(',')
      ).join('\n')
      content = header + '\n' + rows
      filename = 'query_result.csv'
      mimeType = 'text/csv'
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="query-page">
      <div className="page-header">
        <h2>{t('query.title')}</h2>
        <p className="page-desc">{t('query.pageDesc')}</p>
      </div>

      <div className="db-status-bar">
        <span className={`db-status-indicator ${dbStatus}`}>
          {dbStatus === 'connected' && t('query.dbConnected')}
          {dbStatus === 'disconnected' && t('query.dbDisconnected')}
          {dbStatus === 'unknown' && t('query.dbChecking')}
        </span>
        <button className="db-check-btn" onClick={checkDbConnection}>
          {t('query.checkConnection')}
        </button>
      </div>

      <div className="query-toolbar">
        <div className="preset-queries">
          <label>{t('query.presets')}</label>
          <div className="preset-buttons">
            {presetQueries.map((query, index) => (
              <button
                key={index}
                className="preset-btn"
                onClick={() => setSql(query.sql)}
                title={query.sql}
              >
                {query.label}
              </button>
            ))}
          </div>
        </div>
        <div className="toolbar-right">
          <button 
            className="history-btn" 
            onClick={() => setShowHistory(!showHistory)}
          >
            📜 {t('query.history')} ({history.length})
          </button>
        </div>
      </div>

      {showHistory && (
        <div className="query-history-panel">
          <div className="history-header">
            <h4>{t('query.recentQueries')}</h4>
            <button className="clear-btn" onClick={clearHistory}>
              🗑️ {t('query.clearHistory')}
            </button>
          </div>
          <div className="history-list">
            {history.length === 0 ? (
              <p className="empty-history">{t('query.noQueryHistory')}</p>
            ) : (
              history.map(item => (
                <div 
                  key={item.id} 
                  className={`history-item ${item.success ? 'success' : 'error'}`}
                  onClick={() => loadFromHistory(item)}
                >
                  <div className="history-sql">{item.sql}</div>
                  <div className="history-meta">
                    <span className="history-status">{item.success ? '✓' : '✗'}</span>
                    <span className="history-rows">{item.rowCount} {t('query.rows')}</span>
                    {item.duration && <span className="history-duration">{item.duration}s</span>}
                    <span className="history-time">{new Date(item.timestamp).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      <div className="query-editor">
        <div className="editor-header">
          <label>{t('query.sqlQuery')}</label>
          <div className="editor-actions">
            <button 
              className="format-btn" 
              onClick={() => {
                const formatted = sql
                  .replace(/\s+/g, ' ')
                  .replace(/,\s*/g, ',\n  ')
                  .replace(/\bSELECT\b/gi, 'SELECT\n  ')
                  .replace(/\bFROM\b/gi, '\nFROM')
                  .replace(/\bWHERE\b/gi, '\nWHERE')
                  .replace(/\bAND\b/gi, '  AND')
                  .replace(/\bOR\b/gi, '  OR')
                  .replace(/\bGROUP BY\b/gi, '\nGROUP BY')
                  .replace(/\bORDER BY\b/gi, '\nORDER BY')
                  .replace(/\bLIMIT\b/gi, '\nLIMIT')
                  .trim()
                setSql(formatted)
              }}
            >
              🎨 {t('query.format')}
            </button>
          </div>
        </div>
        <div className="editor-wrapper">
          <div className="sql-highlight">{highlightSQL(sql)}</div>
          <textarea
            ref={textareaRef}
            className="sql-input"
            value={sql}
            onChange={(e) => setSql(e.target.value)}
            onKeyDown={handleKeyDown}
            onScroll={handleScroll}
            placeholder={t('query.enterSQL')}
            rows={8}
            spellCheck={false}
          />
        </div>
        <div className="editor-hint">
          {t('query.editorHint')}
        </div>
      </div>

      <div className="query-actions">
        <button
          onClick={handleExecute}
          disabled={loading}
          className="btn-primary"
        >
          {loading ? (
            <>
              <span className="btn-spinner"></span>
              {t('query.executing')}
            </>
          ) : (
            <>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="5 3 19 12 5 21 5 3"/>
              </svg>
              {t('query.execute')}
            </>
          )}
        </button>
        {result && (
          <div className="result-actions">
            <button className="export-btn" onClick={() => exportResults('json')}>
              📥 {t('query.exportJson')}
            </button>
            <button className="export-btn" onClick={() => exportResults('csv')}>
              📥 {t('query.exportCsv')}
            </button>
          </div>
        )}
      </div>

      {error && (
        <div className="error-panel">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {result && (
        <div className="query-results">
          <div className="results-header">
            <h3>{t('query.results')}</h3>
            <div className="results-meta">
              <span className="results-count">
                {result.count} {t('query.rowsReturned')}
              </span>
              {executionTime && (
                <span className="execution-time">
                  ⏱️ {executionTime}s
                </span>
              )}
            </div>
          </div>

          {result.columns.length > 0 && result.rows.length > 0 ? (
            <div className="results-table-wrapper">
              <table className="results-table">
                <thead>
                  <tr>
                    <th className="row-num">#</th>
                    {result.columns.map((col, index) => (
                      <th key={index}>{col}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.rows.map((row, rowIndex) => (
                    <tr key={rowIndex}>
                      <td className="row-num">{rowIndex + 1}</td>
                      {result.columns.map((col, colIndex) => (
                        <td key={colIndex} className={row[col] === null ? 'null-value' : ''}>
                          {formatCellValue(row[col])}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-icon">📭</div>
              <h3>{t('query.noResults')}</h3>
              <p>{t('query.noResultsDesc')}</p>
            </div>
          )}
        </div>
      )}

      <div className="query-info">
        <div className="section-header">
          <h3>{t('query.aboutQuery')}</h3>
        </div>
        <div className="info-content">
          <p>{t('query.aboutDesc')}</p>
          <div className="example-queries">
            <h4>{t('query.exampleQueries')}</h4>
            <div className="example-item">
              <code>SELECT * FROM events WHERE event_id = 4624</code>
              <p>{t('query.example1Desc')}</p>
            </div>
            <div className="example-item">
              <code>SELECT computer, COUNT(*) as count FROM events GROUP BY computer</code>
              <p>{t('query.example2Desc')}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function formatCellValue(value: any): string {
  if (value === null || value === undefined) {
    return 'NULL'
  }
  if (typeof value === 'object') {
    return JSON.stringify(value)
  }
  const str = String(value)
  if (str.length > 200) {
    return str.substring(0, 200) + '...'
  }
  return str
}

export default Query
