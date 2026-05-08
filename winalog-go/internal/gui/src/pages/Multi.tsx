import { useState, useMemo, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { multiAPI } from '../api'
import { DataSet } from 'vis-data/peer'
import { Network } from 'vis-network/peer'
import { QuestionCircleOutlined } from '@ant-design/icons'

interface MachineInfo {
  id: string
  name: string
  ip: string
  domain: string
  role: string
  os_version: string
  last_seen: string
}

interface CrossMachineActivity {
  user: string
  machine_count: number
  machines: string[]
  login_count: number
  suspicious: boolean
  severity: string
  recommendation: string
}

interface LateralMovement {
  source_machine: string
  target_machine: string
  user: string
  event_id: number
  timestamp: string
  ip_address: string
  severity: string
  description: string
  mitre_attack: string[]
}

interface MultiAnalyzeResponse {
  machines: MachineInfo[]
  cross_machine_activity: CrossMachineActivity[]
  lateral_movement: LateralMovement[]
  summary: string
  suspicious_count: number
  analysis_id: string
}

const severityColors: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
}

function Multi() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const networkRef = useRef<HTMLDivElement | null>(null)
  const networkInstance = useRef<Network | null>(null)
  
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<MultiAnalyzeResponse | null>(null)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState<'overview' | 'crossmachine' | 'lateral'>('overview')
  const [hours, setHours] = useState(24)
  const [useCustomDate, setUseCustomDate] = useState(false)
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [dataLimit, setDataLimit] = useState(5000)
  const [exporting, setExporting] = useState(false)
  const [showExportMenu, setShowExportMenu] = useState(false)
  const [showGuide, setShowGuide] = useState(true)

  const handleAnalyze = async () => {
    setLoading(true)
    setError('')
    try {
      const params: { hours?: number; start_time?: string; end_time?: string; limit?: number } = {}
      if (useCustomDate && startDate && endDate) {
        params.start_time = new Date(startDate).toISOString()
        params.end_time = new Date(endDate).toISOString()
      } else {
        params.hours = hours
      }
      params.limit = dataLimit
      const res = await multiAPI.analyze(params)
      setResult(res.data)
    } catch (err: any) {
      setError(err.response?.data?.error || t('multi.analysisFailed'))
    } finally {
      setLoading(false)
    }
  }

  const handleExport = (format: 'csv' | 'json') => {
    setExporting(true)
    setShowExportMenu(false)
    const h = useCustomDate && startDate && endDate
      ? Math.round((new Date(endDate).getTime() - new Date(startDate).getTime()) / (1000 * 60 * 60))
      : hours
    window.open(`/api/multi/export?format=${format}&hours=${h}`, '_blank')
    setTimeout(() => setExporting(false), 1000)
  }

  const getSeverityColor = (severity: string) => {
    return severityColors[severity.toLowerCase()] || severityColors.info
  }

  const getSeverityLabel = (severity: string) => {
    const labels: Record<string, string> = {
      critical: t('common.severity.critical'),
      high: t('common.severity.high'),
      medium: t('common.severity.medium'),
      low: t('common.severity.low'),
    }
    return labels[severity.toLowerCase()] || severity
  }

  const getRoleIcon = (role: string) => {
    if (role?.includes('DC') || role?.includes('Domain')) return '🌐'
    if (role?.includes('Server')) return '🖥️'
    if (role?.includes('Workstation')) return '💻'
    return '🖥️'
  }

  const graphData = useMemo(() => {
    if (!result || result.machines.length === 0) return { nodes: [], edges: [] }
    
    const nodes = result.machines.map(m => ({
      id: m.id,
      label: m.name,
      title: `${m.name}\nIP: ${m.ip || 'N/A'}\nRole: ${m.role || 'Unknown'}`,
      group: m.role?.toLowerCase() || 'unknown',
      shape: 'dot',
      size: 25,
      font: { color: '#ffffff', size: 14 },
    }))

    const edges = result.lateral_movement.map((lm, i) => {
      const sourceNode = nodes.find(n => n.label === lm.source_machine)
      const targetNode = nodes.find(n => n.label === lm.target_machine)
      return {
        id: `edge-${i}`,
        from: sourceNode?.id || lm.source_machine,
        to: targetNode?.id || lm.target_machine,
        label: lm.severity.toUpperCase(),
        color: { color: getSeverityColor(lm.severity) },
        width: 2,
        arrows: 'to',
        title: `User: ${lm.user}\nEvent: ${lm.event_id}\n${lm.description}`,
      }
    })

    return { nodes, edges }
  }, [result])

  // Initialize vis-network when result changes
  useEffect(() => {
    if (!networkRef.current || !result || graphData.nodes.length === 0) return

    // Destroy previous instance if exists
    if (networkInstance.current) {
      networkInstance.current.destroy()
    }

    const nodes = new DataSet(graphData.nodes)
    const edges = new DataSet(graphData.edges)

    const options = {
      physics: {
        enabled: true,
        barnesHut: {
          gravitationalConstant: -2000,
          centralGravity: 0.3,
          springLength: 150,
          springConstant: 0.04,
          damping: 0.09,
        },
        stabilization: { iterations: 100 },
      },
      groups: {
        dc: { color: { background: '#ef4444', border: '#b91c1c' }, shape: 'hexagon', size: 35 },
        server: { color: { background: '#f59e0b', border: '#b45309' }, shape: 'diamond', size: 30 },
        workstation: { color: { background: '#3b82f6', border: '#1d4ed8' }, shape: 'dot', size: 25 },
        unknown: { color: { background: '#6b7280', border: '#374151' }, shape: 'dot', size: 20 },
      },
      interaction: { hover: true, tooltipDelay: 100 },
      layout: { improvedLayout: true },
    }

    networkInstance.current = new Network(networkRef.current, { nodes, edges }, options)
    
    // Double click event
    networkInstance.current.on('doubleClick', (params: any) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0]
        const node = nodes.get(nodeId) as any
        if (node) {
          alert(`Machine Details:\nName: ${node.label}\nGroup: ${node.group}`)
        }
      }
    })

  }, [result, graphData])

  const formatTime = (timeStr: string) => {
    try {
      return new Date(timeStr).toLocaleString()
    } catch {
      return timeStr
    }
  }

  return (
    <div className="multi-page">
      <div className="page-header">
        <h2>{t('multi.title')}</h2>
        <p className="page-desc">{t('multi.pageDesc')}</p>
        <button className="guide-toggle-btn" onClick={() => setShowGuide(!showGuide)}>
          <QuestionCircleOutlined /> {showGuide ? '收起使用说明' : '使用说明'}
        </button>
      </div>

      {showGuide && (
        <div className="guide-panel">
          <div className="guide-header">
            <QuestionCircleOutlined className="guide-icon" />
            <h3>如何使用多机分析</h3>
          </div>
          <div className="guide-body">
            <p className="guide-intro">多机分析模块用于检测跨多台机器的可疑用户活动、横向移动行为和机器之间的异常关联。它从日志中提取主机名、IP 和用户登录信息，构建机器拓扑图并识别攻击链路。</p>
            <div className="guide-steps">
              <div className="guide-step">
                <div className="step-number">1</div>
                <div className="step-content">
                  <h4>准备数据</h4>
                  <p>确保已通过 <a onClick={() => navigate('/collect')}>日志采集</a> 导入多台机器的 Windows 事件日志。至少需要包含 4624 (登录成功) 事件。</p>
                </div>
              </div>
              <div className="guide-step">
                <div className="step-number">2</div>
                <div className="step-content">
                  <h4>配置分析参数</h4>
                  <p>选择时间窗口（默认 24 小时），或切换到"自定义日期"指定精确范围。数据限制控制最大处理事件数（默认 5000）。</p>
                </div>
              </div>
              <div className="guide-step">
                <div className="step-number">3</div>
                <div className="step-content">
                  <h4>运行分析</h4>
                  <p>点击"运行分析"按钮。引擎将执行：机器发现 → 跨机活动检测 → 横向移动识别。</p>
                </div>
              </div>
              <div className="guide-step">
                <div className="step-number">4</div>
                <div className="step-content">
                  <h4>查看结果</h4>
                  <p>三个标签页分别展示：机器概览（含拓扑图）→ 跨机活动（用户登录多台机器的异常行为）→ 横向移动（具体的机器间跳跃事件）。</p>
                </div>
              </div>
            </div>
            <div className="guide-tips">
              <h4>💡 提示</h4>
              <ul>
                <li>建议在 <a onClick={() => navigate('/assets')}>机器资产</a> 页面提前录入机器信息（角色、IP 等），可提升拓扑图准确度</li>
                <li>横向移动检测依赖 4624 事件中的 IpAddress 字段，确保日志包含此信息</li>
                <li>发现可疑活动时，点击拓扑图中的节点可查看机器详情</li>
                <li>分析结果可导出为 CSV 或 JSON 格式供进一步分析</li>
              </ul>
            </div>
          </div>
          <button className="guide-close" onClick={() => setShowGuide(false)}>
            我知道了
          </button>
        </div>
      )}

      <div className="multi-toolbar">
        <div className="toolbar-row">
          <div className="toolbar-group">
            <label className="toolbar-label">{t('multi.timeWindow') || '时间窗口'}:</label>
            <select
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
              disabled={useCustomDate}
              className="toolbar-select"
            >
              <option value={1}>1h</option>
              <option value={6}>6h</option>
              <option value={24}>24h</option>
              <option value={72}>72h</option>
              <option value={168}>7d</option>
            </select>
          </div>

          <div className="toolbar-group">
            <label className="toolbar-label">
              <input
                type="checkbox"
                checked={useCustomDate}
                onChange={(e) => setUseCustomDate(e.target.checked)}
              />
              {t('multi.customDate') || '自定义日期'}
            </label>
          </div>

          {useCustomDate && (
            <>
              <div className="toolbar-group">
                <label className="toolbar-label">{t('multi.startTime') || '开始时间'}:</label>
                <input
                  type="datetime-local"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="toolbar-input"
                />
              </div>
              <div className="toolbar-group">
                <label className="toolbar-label">{t('multi.endTime') || '结束时间'}:</label>
                <input
                  type="datetime-local"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="toolbar-input"
                />
              </div>
            </>
          )}

          <div className="toolbar-group">
            <label className="toolbar-label">{t('multi.dataLimit') || '数据限制'}:</label>
            <select
              value={dataLimit}
              onChange={(e) => setDataLimit(Number(e.target.value))}
              className="toolbar-select"
            >
              <option value={1000}>1000</option>
              <option value={5000}>5000</option>
              <option value={10000}>10000</option>
              <option value={50000}>50000</option>
            </select>
          </div>
        </div>

        <button
          onClick={handleAnalyze}
          disabled={loading || (useCustomDate && (!startDate || !endDate))}
          className="btn-primary"
        >
          {loading ? (
            <>
              <span className="btn-spinner"></span>
              {t('multi.analyzing')}
            </>
          ) : (
            <>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 6v6l4 2"/>
              </svg>
              {t('multi.runAnalysis')}
            </>
          )}
        </button>

        <div className="export-dropdown">
          <button className="btn-export" onClick={() => setShowExportMenu(!showExportMenu)} disabled={exporting}>
            {exporting ? '...' : 'Export'}
          </button>
          {showExportMenu && (
            <div className="export-menu">
              <button onClick={() => handleExport('csv')}>CSV</button>
              <button onClick={() => handleExport('json')}>JSON</button>
            </div>
          )}
        </div>
      </div>

      {error && (
        <div className="error-panel">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {result && (
        <>
          <div className="analysis-summary">
            <div className="summary-card">
              <h4>{t('multi.analysisId')}</h4>
              <p className="analysis-id">{result.analysis_id}</p>
            </div>
            <div className="summary-card">
              <h4>{t('multi.machinesFound')}</h4>
              <p className="summary-value">{result.machines.length}</p>
            </div>
            <div className="summary-card">
              <h4>{t('multi.suspiciousActivities')}</h4>
              <p className="summary-value" style={{ color: result.suspicious_count > 0 ? '#dc2626' : '#16a34a' }}>
                {result.suspicious_count}
              </p>
            </div>
            <div className="summary-card">
              <h4>{t('multi.lateralMovements')}</h4>
              <p className="summary-value">{result.lateral_movement.length}</p>
            </div>
          </div>

          <p className="summary-text">{result.summary}</p>

          <div className="tabs">
            <button
              className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              📊 {t('multi.machineOverview')}
            </button>
            <button
              className={`tab ${activeTab === 'crossmachine' ? 'active' : ''}`}
              onClick={() => setActiveTab('crossmachine')}
            >
              🔗 {t('multi.crossMachine')}
            </button>
            <button
              className={`tab ${activeTab === 'lateral' ? 'active' : ''}`}
              onClick={() => setActiveTab('lateral')}
            >
              🔄 {t('multi.lateralMovement')}
            </button>
          </div>

          {activeTab === 'overview' && (
            <div className="tab-content">
              {result.machines.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">🖥️</div>
                  <h3>{t('multi.noMachines')}</h3>
                  <p>{t('multi.noMachinesDesc')}</p>
                  <div className="empty-hint">
                    <p>💡 {t('multi.importHint')}</p>
                  </div>
                </div>
              ) : (
                <>
                  <div className="machine-graph-container">
                    <h4>🏢 {t('multi.machineRelationship')}</h4>
                    <div ref={networkRef} className="vis-network-graph" style={{ height: '600px', border: '1px solid #333', borderRadius: '8px' }}></div>
                    <div className="graph-legend">
                      <span className="legend-item">🌐 DC / 域控</span>
                      <span className="legend-item">🖥️ Server / 服务器</span>
                      <span className="legend-item">💻 Workstation / 工作站</span>
                      <span className="legend-item">⚠️ 可疑关联</span>
                    </div>
                  </div>

                  <div className="machines-grid">
                    {result.machines.map((machine, index) => {
                      const isInLateral = result.lateral_movement.some(
                        lm => lm.source_machine === machine.name || lm.target_machine === machine.name
                      )
                      return (
                        <div key={index} className={`machine-card ${isInLateral ? 'alert' : ''}`}>
                          <div className="machine-header">
                            <span className="machine-icon">{getRoleIcon(machine.role)}</span>
                            <h4>{machine.name}</h4>
                            {isInLateral && <span className="alert-badge">⚠️</span>}
                          </div>
                          <div className="machine-details">
                            <div className="detail-row">
                              <span className="label">{t('multi.ip')}:</span>
                              <span className="value">{machine.ip || 'N/A'}</span>
                            </div>
                            <div className="detail-row">
                              <span className="label">{t('multi.domain')}:</span>
                              <span className="value">{machine.domain || 'N/A'}</span>
                            </div>
                            <div className="detail-row">
                              <span className="label">{t('multi.role')}:</span>
                              <span className="value">{machine.role || t('common.unknown')}</span>
                            </div>
                            <div className="detail-row">
                              <span className="label">{t('multi.os')}:</span>
                              <span className="value">{machine.os_version || t('common.unknown')}</span>
                            </div>
                            <div className="detail-row">
                              <span className="label">{t('multi.lastSeen')}:</span>
                              <span className="value">{formatTime(machine.last_seen)}</span>
                            </div>
                          </div>
                          {isInLateral && (
                            <div className="machine-alert-indicator">
                              <span>⚠️ {t('multi.involvedInLateral')}</span>
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </>
              )}
            </div>
          )}

          {activeTab === 'crossmachine' && (
            <div className="tab-content">
              {result.cross_machine_activity.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">✅</div>
                  <h3>{t('multi.noSuspiciousActivity')}</h3>
                  <p>{t('multi.noSuspiciousActivityDesc')}</p>
                </div>
              ) : (
                <div className="activity-list">
                  {result.cross_machine_activity.map((activity, index) => (
                    <div key={index} className={`activity-card ${activity.suspicious ? 'suspicious' : ''}`}>
                      <div className="activity-header">
                        <div className="user-info">
                          <span className="user-icon">👤</span>
                          <span className="user-name">{activity.user}</span>
                        </div>
                        <span
                          className="severity-badge"
                          style={{ backgroundColor: getSeverityColor(activity.severity) }}
                        >
                          {getSeverityLabel(activity.severity)}
                        </span>
                      </div>
                      <div className="activity-body">
                        <p className="activity-desc">
                          {t('multi.loggedInto')} {activity.machine_count} {t('multi.machines')}:
                        </p>
                        <div className="machine-tags">
                          {activity.machines.map((machine, i) => (
                            <span key={i} className="machine-tag">{machine}</span>
                          ))}
                        </div>
                        <p className="login-count">
                          {t('multi.totalLogins')}: {activity.login_count}
                        </p>
                        <div className="recommendation">
                          <span className="rec-icon">💡</span>
                          <span>{activity.recommendation}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'lateral' && (
            <div className="tab-content">
              {result.lateral_movement.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">✅</div>
                  <h3>{t('multi.noLateralMovement')}</h3>
                  <p>{t('multi.noLateralMovementDesc')}</p>
                </div>
              ) : (
                <>
                  <div className="lateral-summary">
                    <div className="lateral-stat">
                      <span className="stat-icon">🔄</span>
                      <span className="stat-text">{result.lateral_movement.length} {t('multi.lateralMovementsDetected')}</span>
                    </div>
                  </div>
                  <div className="lateral-table">
                    <table>
                      <thead>
                        <tr>
                          <th>{t('multi.time')}</th>
                          <th>{t('multi.source')}</th>
                          <th>{t('multi.target')}</th>
                          <th>{t('multi.user')}</th>
                          <th>{t('multi.event')}</th>
                          <th>{t('multi.description')}</th>
                          <th>{t('multi.severity')}</th>
                          <th>{t('multi.mitre')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.lateral_movement.map((movement, index) => (
                          <tr key={index} className={movement.severity === 'critical' || movement.severity === 'high' ? 'danger-row' : ''}>
                            <td className="time-cell">{formatTime(movement.timestamp)}</td>
                            <td className="source-cell">
                              <span className="machine-badge source">{movement.source_machine}</span>
                            </td>
                            <td className="target-cell">
                              <span className="machine-badge target">{movement.target_machine}</span>
                            </td>
                            <td className="user-cell">👤 {movement.user}</td>
                            <td className="event-cell">{movement.event_id}</td>
                            <td className="desc-cell">{movement.description}</td>
                            <td>
                              <span
                                className="severity-badge"
                                style={{ backgroundColor: getSeverityColor(movement.severity) }}
                              >
                                {getSeverityLabel(movement.severity)}
                              </span>
                            </td>
                            <td className="mitre-cell">
                              {movement.mitre_attack.map((m, i) => (
                                <span key={i} className="mitre-tag">{m}</span>
                              ))}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}
        </>
      )}

      <div className="quick-actions">
        <h4>{t('multi.quickActions')}</h4>
        <div className="quick-buttons">
          <button className="quick-btn" onClick={() => navigate('/correlation')}>
            🔗 {t('multi.viewCorrelation')}
          </button>
          <button className="quick-btn" onClick={() => navigate('/timeline')}>
            📊 {t('multi.viewTimeline')}
          </button>
          <button className="quick-btn" onClick={() => navigate('/alerts')}>
            🔔 {t('multi.viewAlerts')}
          </button>
        </div>
      </div>
    </div>
  )
}

export default Multi
