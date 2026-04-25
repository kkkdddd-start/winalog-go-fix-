import { useEffect, useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { alertsAPI } from '../api'

interface Event {
  id: number
  timestamp: string
  event_id: number
  level: string
  source: string
  log_name: string
  computer: string
  message: string
}

interface Alert {
  id: number
  rule_name: string
  severity: string
  message: string
  count: number
  resolved: boolean
  false_positive: boolean
  first_seen: string
  last_seen: string
  resolved_time?: string
  notes?: string
  mitre_attack?: string[]
  log_name: string
  rule_score: number
  event_ids: number[]
}

interface AlertWithDetails extends Alert {
  explanation: string
  recommendation: string
  real_case: string
  keywords: string
  matched_events: Event[]
}

function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [alert, setAlert] = useState<AlertWithDetails | null>(null)
  const [loading, setLoading] = useState(true)
  const [notes, setNotes] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (id) {
      setLoading(true)
      alertsAPI.get(Number(id))
        .then(res => {
          setAlert(res.data as AlertWithDetails)
          setLoading(false)
        })
        .catch(() => setLoading(false))
    }
  }, [id])

  const handleResolve = async () => {
    if (!alert) return
    setSaving(true)
    try {
      await alertsAPI.resolve(alert.id, notes)
      setAlert({ ...alert, resolved: true, resolved_time: new Date().toISOString(), notes })
    } catch (error) {
      console.error('Failed to resolve:', error)
    } finally {
      setSaving(false)
    }
  }

  const handleMarkFalsePositive = async () => {
    if (!alert) return
    setSaving(true)
    try {
      await alertsAPI.markFalsePositive(alert.id, notes)
      setAlert({ ...alert, false_positive: true, notes })
    } catch (error) {
      console.error('Failed to mark false positive:', error)
    } finally {
      setSaving(false)
    }
  }

  const handleSearchRelatedEvents = () => {
    if (!alert) return
    const params = new URLSearchParams()
    if (alert.event_ids && alert.event_ids.length > 0) {
      params.set('event_ids', alert.event_ids.join(','))
    }
    if (alert.keywords) {
      params.set('keywords', alert.keywords)
    }
    navigate(`/events?${params.toString()}`)
  }

  if (loading) return <div className="loading-state"><div className="loading-spinner"></div><p>Loading...</p></div>
  if (!alert) return <div className="alert-not-found">Alert not found</div>

  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'critical': return 'severity-critical'
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      case 'low': return 'severity-low'
      default: return ''
    }
  }

  return (
    <div className="alert-detail">
      <Link to="/alerts" className="back-link">← 返回告警列表</Link>
      
      <div className="detail-layout">
        <div className="detail-main">
          <div className="detail-panel">
            <div className="panel-header">
              <h3>告警 #{alert.id}</h3>
              <div className="status-badges">
                <span className={`badge ${getSeverityClass(alert.severity)}`}>
                  {alert.severity.toUpperCase()}
                </span>
                {alert.resolved && <span className="badge resolved">已解决</span>}
                {alert.false_positive && <span className="badge false-positive">误报</span>}
              </div>
            </div>
            
            <div className="detail-grid">
              <div className="detail-item">
                <label>规则名称:</label>
                <span className="rule-name">{alert.rule_name}</span>
              </div>
              <div className="detail-item">
                <label>威胁评分:</label>
                <span className="score-value">{alert.rule_score.toFixed(2)}</span>
              </div>
              <div className="detail-item">
                <label>日志名称:</label>
                <span>{alert.log_name}</span>
              </div>
              <div className="detail-item">
                <label>触发次数:</label>
                <span>{alert.count}</span>
              </div>
              <div className="detail-item">
                <label>首次出现:</label>
                <span>{new Date(alert.first_seen).toLocaleString()}</span>
              </div>
              <div className="detail-item">
                <label>最后出现:</label>
                <span>{new Date(alert.last_seen).toLocaleString()}</span>
              </div>
            </div>

            <div className="detail-section">
              <label>触发事件ID:</label>
              <div className="event-ids">
                {alert.event_ids && alert.event_ids.length > 0 ? (
                  alert.event_ids.map((eid, i) => (
                    <span key={i} className="event-id-badge">{eid}</span>
                  ))
                ) : (
                  <span className="no-data">无</span>
                )}
              </div>
            </div>

            {alert.keywords && (
              <div className="detail-section">
                <label>匹配关键字:</label>
                <div className="keywords">
                  {alert.keywords.split(' ').filter(k => k).map((keyword, i) => (
                    <span key={i} className="keyword-badge">{keyword}</span>
                  ))}
                </div>
              </div>
            )}

            <div className="detail-section">
              <label>告警消息:</label>
              <pre className="message-box">{alert.message}</pre>
            </div>

            {alert.mitre_attack && alert.mitre_attack.length > 0 && (
              <div className="detail-section">
                <label>MITRE ATT&CK:</label>
                <div className="mitre-tags">
                  {alert.mitre_attack.map((tactic, i) => (
                    <span key={i} className="mitre-tag">{tactic}</span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {alert.explanation && (
            <div className="detail-panel explanation-panel">
              <h4>规则解读</h4>
              <p className="explanation-text">{alert.explanation}</p>
            </div>
          )}

          {alert.recommendation && (
            <div className="detail-panel recommendation-panel">
              <h4>处置建议</h4>
              <div className="recommendation-text">
                {alert.recommendation.split('\n').filter(line => line).map((line, i) => (
                  <p key={i}>{line}</p>
                ))}
              </div>
            </div>
          )}

          {alert.real_case && (
            <div className="detail-panel case-panel">
              <h4>真实案例</h4>
              <p className="case-text">{alert.real_case}</p>
            </div>
          )}

          {alert.matched_events && alert.matched_events.length > 0 && (
            <div className="detail-panel events-panel">
              <h4>关联日志 ({alert.matched_events.length})</h4>
              <div className="events-list">
                {alert.matched_events.map(event => (
                  <div key={event.id} className="event-item">
                    <div className="event-header">
                      <span className="event-id">Event ID: {event.event_id}</span>
                      <span className="event-time">{new Date(event.timestamp).toLocaleString()}</span>
                      <span className={`event-level level-${event.level.toLowerCase()}`}>{event.level}</span>
                    </div>
                    <div className="event-source">来源: {event.source}</div>
                    <div className="event-computer">计算机: {event.computer}</div>
                    <div className="event-message">{event.message}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="detail-sidebar">
          <div className="sidebar-panel">
            <h4>操作</h4>
            {!alert.resolved && !alert.false_positive && (
              <>
                <textarea
                  placeholder="添加备注..."
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  rows={3}
                />
                <button onClick={handleResolve} disabled={saving} className="btn-action btn-resolve">
                  标记为已解决
                </button>
                <button onClick={handleMarkFalsePositive} disabled={saving} className="btn-action btn-falsepositive">
                  标记为误报
                </button>
              </>
            )}
            <button onClick={handleSearchRelatedEvents} className="btn-action btn-search">
              搜索关联事件
            </button>
            {alert.notes && (
              <div className="notes-section">
                <label>备注:</label>
                <pre className="notes-box">{alert.notes}</pre>
              </div>
            )}
          </div>
        </div>
      </div>

      <style>{`
        .alert-detail {
          padding: 20px;
        }
        .back-link {
          color: #00d9ff;
          text-decoration: none;
          margin-bottom: 20px;
          display: inline-block;
        }
        .back-link:hover {
          text-decoration: underline;
        }
        .detail-layout {
          display: flex;
          gap: 20px;
        }
        .detail-main {
          flex: 1;
        }
        .detail-sidebar {
          width: 280px;
        }
        .detail-panel {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 20px;
          border: 1px solid #333;
        }
        .panel-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }
        .panel-header h3 {
          margin: 0;
          color: #fff;
        }
        .status-badges {
          display: flex;
          gap: 8px;
        }
        .detail-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 12px;
          margin-bottom: 20px;
        }
        .detail-item {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        .detail-item label {
          font-size: 0.85em;
          color: #888;
        }
        .detail-item span {
          color: #fff;
        }
        .rule-name {
          color: #00d9ff !important;
          font-weight: bold;
        }
        .score-value {
          color: #f59e0b !important;
          font-weight: bold;
        }
        .detail-section {
          margin-top: 15px;
        }
        .detail-section label {
          display: block;
          font-weight: bold;
          color: #00d9ff;
          margin-bottom: 8px;
        }
        .event-ids, .keywords {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }
        .event-id-badge {
          background: #1f4068;
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 0.9em;
          color: #fff;
        }
        .keyword-badge {
          background: rgba(0, 217, 255, 0.2);
          border: 1px solid #00d9ff;
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 0.85em;
          color: #00d9ff;
        }
        .message-box {
          background: #0a0a1a;
          padding: 15px;
          border-radius: 8px;
          white-space: pre-wrap;
          color: #eee;
          font-size: 0.9em;
          max-height: 200px;
          overflow-y: auto;
        }
        .mitre-tags {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
        }
        .mitre-tag {
          background: #1f4068;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 0.85em;
          color: #fff;
        }
        .explanation-panel {
          border-left: 4px solid #00d9ff;
        }
        .explanation-panel h4 {
          color: #00d9ff;
          margin: 0 0 10px 0;
        }
        .explanation-text {
          color: #eee;
          line-height: 1.6;
          margin: 0;
        }
        .recommendation-panel {
          border-left: 4px solid #22c55e;
        }
        .recommendation-panel h4 {
          color: #22c55e;
          margin: 0 0 10px 0;
        }
        .recommendation-text {
          color: #eee;
        }
        .recommendation-text p {
          margin: 5px 0;
          padding-left: 15px;
          position: relative;
        }
        .recommendation-text p::before {
          content: "•";
          position: absolute;
          left: 0;
          color: #22c55e;
        }
        .case-panel {
          border-left: 4px solid #f59e0b;
        }
        .case-panel h4 {
          color: #f59e0b;
          margin: 0 0 10px 0;
        }
        .case-text {
          color: #eee;
          line-height: 1.6;
          margin: 0;
          font-style: italic;
        }
        .events-panel {
          border-left: 4px solid #8b5cf6;
        }
        .events-panel h4 {
          color: #8b5cf6;
          margin: 0 0 15px 0;
        }
        .events-list {
          display: flex;
          flex-direction: column;
          gap: 15px;
          max-height: 500px;
          overflow-y: auto;
        }
        .event-item {
          background: #0a0a1a;
          padding: 12px;
          border-radius: 8px;
          border: 1px solid #333;
        }
        .event-header {
          display: flex;
          gap: 10px;
          align-items: center;
          margin-bottom: 8px;
          flex-wrap: wrap;
        }
        .event-id {
          color: #00d9ff;
          font-weight: bold;
        }
        .event-time {
          color: #888;
          font-size: 0.85em;
        }
        .event-level {
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 0.8em;
        }
        .level-error, .level-warning {
          background: rgba(239, 68, 68, 0.2);
          color: #ef4444;
        }
        .level-info {
          background: rgba(59, 130, 246, 0.2);
          color: #3b82f6;
        }
        .event-source, .event-computer {
          color: #888;
          font-size: 0.85em;
          margin-bottom: 4px;
        }
        .event-message {
          color: #eee;
          font-size: 0.9em;
          white-space: pre-wrap;
          word-break: break-all;
        }
        .sidebar-panel {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          padding: 20px;
          border: 1px solid #333;
          position: sticky;
          top: 20px;
        }
        .sidebar-panel h4 {
          margin: 0 0 15px 0;
          color: #fff;
        }
        .sidebar-panel textarea {
          width: 100%;
          padding: 10px;
          border: 1px solid #333;
          border-radius: 8px;
          background: #16213e;
          color: #eee;
          margin-bottom: 10px;
          resize: vertical;
        }
        .btn-action {
          width: 100%;
          padding: 10px;
          border: none;
          border-radius: 8px;
          cursor: pointer;
          font-weight: bold;
          margin-bottom: 10px;
          transition: all 0.2s;
        }
        .btn-resolve {
          background: rgba(34, 197, 94, 0.2);
          border: 1px solid #22c55e;
          color: #22c55e;
        }
        .btn-resolve:hover {
          background: rgba(34, 197, 94, 0.3);
        }
        .btn-falsepositive {
          background: rgba(245, 158, 11, 0.2);
          border: 1px solid #f59e0b;
          color: #f59e0b;
        }
        .btn-falsepositive:hover {
          background: rgba(245, 158, 11, 0.3);
        }
        .btn-search {
          background: rgba(0, 217, 255, 0.2);
          border: 1px solid #00d9ff;
          color: #00d9ff;
        }
        .btn-search:hover {
          background: rgba(0, 217, 255, 0.3);
        }
        .notes-section {
          margin-top: 15px;
          padding-top: 15px;
          border-top: 1px solid #333;
        }
        .notes-section label {
          display: block;
          color: #888;
          font-size: 0.85em;
          margin-bottom: 5px;
        }
        .notes-box {
          background: #0a0a1a;
          padding: 10px;
          border-radius: 4px;
          color: #eee;
          white-space: pre-wrap;
          font-size: 0.9em;
        }
        .no-data {
          color: #666;
          font-style: italic;
        }
        .severity-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 4px 10px; border-radius: 4px; }
        .severity-high { background: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 4px 10px; border-radius: 4px; }
        .severity-medium { background: rgba(59, 130, 246, 0.2); color: #3b82f6; padding: 4px 10px; border-radius: 4px; }
        .severity-low { background: rgba(34, 197, 94, 0.2); color: #22c55e; padding: 4px 10px; border-radius: 4px; }
        .badge.resolved { background: #28a745; color: #fff; }
        .badge.false-positive { background: #6c757d; color: #fff; }
        .loading-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 60px;
          color: #888;
        }
        .alert-not-found {
          text-align: center;
          padding: 60px;
          color: #ef4444;
        }
        @media (max-width: 1024px) {
          .detail-layout {
            flex-direction: column;
          }
          .detail-sidebar {
            width: 100%;
          }
        }
      `}</style>
    </div>
  )
}

export default AlertDetail
