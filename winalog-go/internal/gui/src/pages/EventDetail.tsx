import { useEffect, useState, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { eventsAPI } from '../api'

interface Event {
  id: number
  timestamp: string
  event_id: number
  level: number
  source: string
  log_name: string
  computer: string
  user?: string
  user_sid?: string
  message: string
  raw_xml?: string
  session_id?: string
  ip_address?: string
  import_time: string
}

interface JsonNodeProps {
  keyName: string
  value: unknown
  depth: number
  isLast: boolean
  collapsedPaths: Set<string>
  onToggleCollapse: (path: string) => void
}

function JsonNode({ keyName, value, depth, isLast, collapsedPaths, onToggleCollapse }: JsonNodeProps) {
  const indent = '  '.repeat(depth)
  const path = keyName.startsWith('[') ? keyName : `"${keyName}"`

  if (value && typeof value === 'object') {
    const isArray = Array.isArray(value)
    const entries: { key: string; value: unknown }[] = isArray 
      ? value.map((v, i) => ({ key: `[${i}]`, value: v }))
      : Object.entries(value as Record<string, unknown>).map(([k, v]) => ({ key: k, value: v }))
    const isEmpty = entries.length === 0
    const nodePath = `${path}`
    const isCollapsed = collapsedPaths.has(nodePath)

    if (isEmpty) {
      return (
        <div className="json-line">
          {indent}
          <span className="json-key">{keyName}</span>
          <span className="json-punct">{isArray ? '[]' : '{}'}</span>
          {!isLast && <span className="json-punct">,</span>}
        </div>
      )
    }

    return (
      <>
        <div className="json-line json-collapsible" onClick={() => onToggleCollapse(nodePath)}>
          {indent}
          <span className="json-key">{keyName}</span>
          <span className="json-punct">{isArray ? '[' : '{'}</span>
          <span className="json-collapse-hint">
            {isCollapsed ? ` ... ${entries.length} items }` : ''}
          </span>
          {!isLast && <span className="json-punct">,</span>}
          <span className="json-toggle">{isCollapsed ? '▶' : '▼'}</span>
        </div>
        {!isCollapsed && entries.map((entry, index) => (
          <JsonNode
            key={entry.key}
            keyName={entry.key}
            value={entry.value}
            depth={depth + 1}
            isLast={index === entries.length - 1}
            collapsedPaths={collapsedPaths}
            onToggleCollapse={onToggleCollapse}
          />
        ))}
        {!isCollapsed && (
          <div className="json-line">
            {indent}
            <span className="json-punct">{isArray ? ']' : '}'}</span>
            {!isLast && <span className="json-punct">,</span>}
          </div>
        )}
      </>
    )
  }

  let valueClass = 'json-string'
  let displayValue = typeof value === 'string' ? `"${value}"` : String(value)
  if (typeof value === 'number') valueClass = 'json-number'
  else if (typeof value === 'boolean') valueClass = 'json-boolean'
  else if (value === null) valueClass = 'json-null'

  return (
    <div className="json-line">
      {indent}
      <span className="json-key">{keyName}</span>
      <span className="json-punct">: </span>
      <span className={valueClass}>{displayValue}</span>
      {!isLast && <span className="json-punct">,</span>}
    </div>
  )
}

function formatLevel(level: number): string {
  const levels = ['Unknown', 'Critical', 'Error', 'Warning', 'Info']
  return levels[level] || 'Unknown'
}

function EventDetail() {
  const { id } = useParams<{ id: string }>()
  const [event, setEvent] = useState<Event | null>(null)
  const [loading, setLoading] = useState(true)
  const [collapsedPaths, setCollapsedPaths] = useState<Set<string>>(new Set())
  const [showRawModal, setShowRawModal] = useState(false)

  useEffect(() => {
    if (id) {
      setLoading(true)
      eventsAPI.get(Number(id))
        .then(res => {
          setEvent(res.data as Event)
          setLoading(false)
        })
        .catch(() => setLoading(false))
    }
  }, [id])

  const handleToggleCollapse = useCallback((path: string) => {
    setCollapsedPaths(prev => {
      const next = new Set(prev)
      if (next.has(path)) {
        next.delete(path)
      } else {
        next.add(path)
      }
      return next
    })
  }, [])

  const handleExpandAll = () => {
    setCollapsedPaths(new Set())
  }

  const handleCollapseAll = () => {
    if (!event?.raw_xml) return
    try {
      const parsed = JSON.parse(event.raw_xml)
      const collectPaths = (obj: unknown, prefix: string): string[] => {
        if (!obj || typeof obj !== 'object') return []
        const paths: string[] = []
        if (Array.isArray(obj)) {
          if (obj.length > 3) paths.push(prefix)
          obj.forEach((_, i) => {
            paths.push(...collectPaths(obj[i], `${prefix}[${i}]`))
          })
        } else {
          Object.values(obj as Record<string, unknown>).forEach((v, i) => {
            const key = Object.keys(obj as Record<string, unknown>)[i]
            paths.push(...collectPaths(v, `${prefix}"${key}"`))
          })
        }
        return paths
      }
      const allPaths = collectPaths(parsed, '')
      setCollapsedPaths(new Set(allPaths.filter(p => p.includes('[') || !p.startsWith('"'))))
    } catch {}
  }

  const copyFormattedJson = () => {
    if (event?.raw_xml) {
      try {
        const formatted = JSON.stringify(JSON.parse(event.raw_xml), null, 2)
        navigator.clipboard.writeText(formatted)
      } catch {
        navigator.clipboard.writeText(event.raw_xml)
      }
    }
  }

  if (loading) return <div>Loading...</div>
  if (!event) return <div>Event not found</div>

  let jsonContent = null
  if (event.raw_xml) {
    try {
      const parsed = JSON.parse(event.raw_xml)
      const entries = Object.entries(parsed)
      jsonContent = entries.map(([key, value], index) => (
        <JsonNode
          key={key}
          keyName={key}
          value={value}
          depth={0}
          isLast={index === entries.length - 1}
          collapsedPaths={collapsedPaths}
          onToggleCollapse={handleToggleCollapse}
        />
      ))
    } catch (e) {
      jsonContent = <pre className="xml-box">{event.raw_xml}</pre>
    }
  }

  return (
    <div className="event-detail">
      <Link to="/events">← Back to Events</Link>
      
      <div className="detail-panel">
        <h3>Event #{event.id}</h3>
        
        <div className="detail-layout">
          <div className="detail-fields">
            <div className="detail-field">
              <span className="field-label">Timestamp:</span>
              <span className="field-value">{new Date(event.timestamp).toLocaleString()}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">Level:</span>
              <span className="field-value">{formatLevel(event.level)}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">Event ID:</span>
              <span className="field-value">{event.event_id}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">Source:</span>
              <span className="field-value">{event.source}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">Log Name:</span>
              <span className="field-value">{event.log_name}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">Computer:</span>
              <span className="field-value">{event.computer}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">User:</span>
              <span className="field-value">{event.user || 'N/A'}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">User SID:</span>
              <span className="field-value">{event.user_sid || 'N/A'}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">Session ID:</span>
              <span className="field-value">{event.session_id || 'N/A'}</span>
            </div>
            <div className="detail-field">
              <span className="field-label">IP Address:</span>
              <span className="field-value">{event.ip_address || 'N/A'}</span>
            </div>
          </div>
          <div className="detail-actions">
            {event.raw_xml && (
              <button 
                className="btn-action"
                onClick={() => setShowRawModal(true)}
              >
                View JSON
              </button>
            )}
            {event.raw_xml && (
              <button 
                className="btn-action btn-copy"
                onClick={copyFormattedJson}
              >
                Copy JSON
              </button>
            )}
          </div>
        </div>

        <div className="detail-section">
          <label>Message:</label>
          <pre className="message-box">{event.message}</pre>
        </div>

        {event.raw_xml && (
          <div className="detail-section">
            <div className="raw-json-header">
              <label>Raw JSON:</label>
              <div className="raw-json-actions">
                <button className="btn-small" onClick={handleExpandAll}>Expand All</button>
                <button className="btn-small" onClick={handleCollapseAll}>Collapse All</button>
              </div>
            </div>
            <div className="json-tree">
              {jsonContent}
            </div>
          </div>
        )}
      </div>

      {showRawModal && event.raw_xml && (
        <div className="modal-overlay" onClick={() => setShowRawModal(false)}>
          <div className="modal-content modal-large" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <span>Raw JSON - Event #{event.id}</span>
              <div className="modal-header-actions">
                <button className="btn-small" onClick={copyFormattedJson}>Copy</button>
                <button className="modal-close" onClick={() => setShowRawModal(false)}>×</button>
              </div>
            </div>
            <div className="modal-body">
              <pre className="json-large">{JSON.stringify(JSON.parse(event.raw_xml), null, 2)}</pre>
            </div>
          </div>
        </div>
      )}

      <style>{`
        .detail-layout {
          display: flex;
          margin-bottom: 20px;
          gap: 20px;
        }
        .detail-fields {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        .detail-field {
          display: flex;
          gap: 15px;
          padding: 8px 0;
          border-bottom: 1px solid #333;
        }
        .field-label {
          width: 140px;
          font-weight: bold;
          color: #00d9ff;
          white-space: nowrap;
          flex-shrink: 0;
        }
        .field-value {
          color: #e0e0e0;
          word-break: break-all;
        }
        .detail-actions {
          display: flex;
          flex-direction: column;
          gap: 10px;
          padding: 10px;
          border-left: 1px solid #333;
          min-width: 140px;
        }
        .btn-action {
          padding: 10px 20px;
          background: #1a3d5c;
          color: #00d9ff;
          border: 1px solid #00d9ff;
          border-radius: 6px;
          cursor: pointer;
          font-size: 13px;
          font-weight: 500;
          text-align: center;
        }
        .btn-action:hover {
          background: #00d9ff;
          color: #0a0a1a;
        }
        .btn-action.btn-copy {
          background: #1a4d1a;
          border-color: #2e7d32;
          color: #4caf50;
        }
        .btn-action.btn-copy:hover {
          background: #2e7d32;
          color: #fff;
        }
        .detail-section {
          margin-top: 15px;
        }
        .detail-section label {
          display: block;
          font-weight: bold;
          color: #00d9ff;
          margin-bottom: 5px;
        }
        .message-box {
          background: #0a0a1a;
          padding: 15px;
          border-radius: 4px;
          overflow-x: auto;
          white-space: pre-wrap;
          word-break: break-all;
        }
        .raw-json-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 10px;
        }
        .raw-json-header label {
          margin-bottom: 0 !important;
        }
        .raw-json-actions {
          display: flex;
          gap: 8px;
        }
        .btn-small {
          padding: 4px 10px;
          font-size: 12px;
          background: #1a1a2e;
          color: #00d9ff;
          border: 1px solid #00d9ff;
          border-radius: 4px;
          cursor: pointer;
        }
        .btn-small:hover {
          background: #00d9ff;
          color: #0a0a1a;
        }
        .json-tree {
          background: #0a0a1a;
          padding: 15px;
          border-radius: 4px;
          overflow-x: auto;
          max-height: 500px;
          overflow-y: auto;
        }
        .json-line {
          font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
          font-size: 13px;
          line-height: 1.5;
          white-space: pre;
        }
        .json-collapsible {
          cursor: pointer;
          user-select: none;
        }
        .json-collapsible:hover {
          background: rgba(0, 217, 255, 0.1);
        }
        .json-key {
          color: #00d9ff;
        }
        .json-string {
          color: #a5d6a7;
        }
        .json-number {
          color: #ffcc02;
        }
        .json-boolean {
          color: #ce93d8;
        }
        .json-null {
          color: #78909c;
        }
        .json-punct {
          color: #e0e0e0;
        }
        .json-collapse-hint {
          color: #78909c;
          font-style: italic;
        }
        .json-toggle {
          color: #00d9ff;
          margin-left: 5px;
          font-size: 10px;
        }
        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.8);
          display: flex;
          justify-content: center;
          align-items: center;
          z-index: 1000;
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

export default EventDetail
