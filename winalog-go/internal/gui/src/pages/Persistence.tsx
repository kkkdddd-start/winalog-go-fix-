import { useState, useEffect } from 'react'
import { useI18n } from '../locales/I18n'
import { Line } from 'react-chartjs-2'
import { persistenceAPI, reportsAPI } from '../api'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
)

interface Detection {
  id: string
  time: string
  technique: string
  category: string
  severity: string
  title: string
  description: string
  evidence: {
    type: string
    key?: string
    value?: string
    file_path?: string
  }
  recommended_action: string
  false_positive_risk: string
  explanation?: string
  recommendation?: string
  real_case?: string
}

interface DetectionStats {
  total_detections: number
  duration_ms: number
  error_count: number
  by_severity: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  by_category: Record<string, number>
  by_technique: Record<string, number>
}

interface Detector {
  name: string
  enabled: boolean
  description: string
  technique: string
  category: string
}

interface DetectorRule {
  name: string
  enabled: boolean
  description: string
  technique: string
  category: string
  registry_paths?: string[]
  suspicious_indicators: string[]
  system_paths?: string[]
  whitelist: string[]
  severity_mapping?: Record<string, string>
  builtin_whitelist?: string[]
  builtin_dll_whitelist?: string[]
  builtin_clsids_whitelist?: string[]
  whitelist_type?: string
}

function Persistence() {
  const { t } = useI18n()
  const [detections, setDetections] = useState<Detection[]>(() => {
    const saved = localStorage.getItem('persistence_detections')
    if (saved) {
      try {
        return JSON.parse(saved)
      } catch {
        // ignore parse errors
      }
    }
    return []
  })

  // 导出菜单点击外部关闭
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const menu = document.getElementById('persistence-export-menu')
      if (menu && !menu.contains(e.target as Node)) {
        menu.style.display = 'none'
      }
    }
    document.addEventListener('click', handleClickOutside)
    return () => document.removeEventListener('click', handleClickOutside)
  }, [])
  const [stats, setStats] = useState<DetectionStats | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedDetection, setSelectedDetection] = useState<Detection | null>(null)
  const [filter, setFilter] = useState<{
    severity?: string
    category?: string
    technique?: string
  }>({})
  const [showDetectorConfig, setShowDetectorConfig] = useState(false)
  const [showRuleEditor, setShowRuleEditor] = useState(false)
  const [detectors, setDetectors] = useState<Detector[]>([])
  const [detectorLoading, setDetectorLoading] = useState(false)
  const [editingRule, setEditingRule] = useState<DetectorRule | null>(null)
  const [ruleLoading, setRuleLoading] = useState(false)
  const [generatingReport, setGeneratingReport] = useState(false)
  const [reportFormat, setReportFormat] = useState('html')

  const fetchDetectors = async () => {
    try {
      setDetectorLoading(true)
      const response = await persistenceAPI.listDetectors()
      setDetectors(response.data.detectors || [])
    } catch (err) {
      console.error('Failed to fetch detectors:', err)
    } finally {
      setDetectorLoading(false)
    }
  }

  const toggleDetector = (name: string) => {
    setDetectors(detectors.map(d => 
      d.name === name ? { ...d, enabled: !d.enabled } : d
    ))
  }

  const saveDetectorConfig = async () => {
    try {
      await persistenceAPI.updateDetectors(
        detectors.map(d => ({ name: d.name, enabled: d.enabled }))
      )
      setShowDetectorConfig(false)
    } catch (err) {
      console.error('Failed to save detector config:', err)
      alert(t('persistence.saveConfigFailed'))
    }
  }

  const handleShowDetectorConfig = () => {
    fetchDetectors()
    setShowDetectorConfig(true)
  }

  const handleShowRuleEditor = async (detectorName?: string) => {
    setRuleLoading(true)
    try {
      if (detectorName) {
        const response = await persistenceAPI.getRule(detectorName)
        const rule = response.data.detector
        setEditingRule({
          ...rule,
          suspicious_indicators: rule.patterns || [],
          whitelist: rule.whitelist || [],
        })
      } else {
        const response = await persistenceAPI.listRules()
        const rule = response.data.rules?.[0]
        if (!rule) {
          alert(t('persistence.noEditableRule'))
          return
        }
        setEditingRule({
          ...rule,
          suspicious_indicators: rule.patterns || [],
          whitelist: rule.whitelist || [],
        })
      }
      setShowRuleEditor(true)
    } catch (err) {
      console.error('Failed to fetch rule details:', err)
    } finally {
      setRuleLoading(false)
    }
  }

  const handleSaveRule = async () => {
    if (!editingRule) return
    try {
      if (editingRule.whitelist_type) {
        await persistenceAPI.updateWhitelist({
          name: editingRule.name,
          whitelist: editingRule.whitelist,
          dll_whitelist: editingRule.builtin_dll_whitelist,
          clsids_whitelist: editingRule.builtin_clsids_whitelist,
        })
      } else {
        await persistenceAPI.updateRule({
          name: editingRule.name,
          enabled: editingRule.enabled,
          suspicious_indicators: editingRule.suspicious_indicators,
          whitelist: editingRule.whitelist,
        })
      }
      setShowRuleEditor(false)
      setEditingRule(null)
    } catch (err) {
      console.error('Failed to save rule:', err)
      alert(t('persistence.saveRuleFailed'))
    }
  }

  const handleIndicatorChange = (index: number, value: string) => {
    if (!editingRule) return
    const newIndicators = [...editingRule.suspicious_indicators]
    newIndicators[index] = value
    setEditingRule({ ...editingRule, suspicious_indicators: newIndicators })
  }

  const handleAddIndicator = () => {
    if (!editingRule) return
    setEditingRule({
      ...editingRule,
      suspicious_indicators: [...editingRule.suspicious_indicators, ''],
    })
  }

  const handleRemoveIndicator = (index: number) => {
    if (!editingRule) return
    const newIndicators = editingRule.suspicious_indicators.filter((_, i) => i !== index)
    setEditingRule({ ...editingRule, suspicious_indicators: newIndicators })
  }

  const handleWhitelistChange = (index: number, value: string) => {
    if (!editingRule) return
    const newWhitelist = [...editingRule.whitelist]
    newWhitelist[index] = value
    setEditingRule({ ...editingRule, whitelist: newWhitelist })
  }

  const handleAddWhitelist = () => {
    if (!editingRule) return
    setEditingRule({
      ...editingRule,
      whitelist: [...editingRule.whitelist, ''],
    })
  }

  const handleRemoveWhitelist = (index: number) => {
    if (!editingRule) return
    const newWhitelist = editingRule.whitelist.filter((_, i) => i !== index)
    setEditingRule({ ...editingRule, whitelist: newWhitelist })
  }

  const handleDllWhitelistChange = (index: number, value: string) => {
    if (!editingRule || !editingRule.builtin_dll_whitelist) return
    const newList = [...editingRule.builtin_dll_whitelist]
    newList[index] = value
    setEditingRule({ ...editingRule, builtin_dll_whitelist: newList })
  }

  const handleAddDllWhitelist = () => {
    if (!editingRule) return
    setEditingRule({
      ...editingRule,
      builtin_dll_whitelist: [...(editingRule.builtin_dll_whitelist || []), ''],
    })
  }

  const handleRemoveDllWhitelist = (index: number) => {
    if (!editingRule || !editingRule.builtin_dll_whitelist) return
    const newList = editingRule.builtin_dll_whitelist.filter((_, i) => i !== index)
    setEditingRule({ ...editingRule, builtin_dll_whitelist: newList })
  }

  const handleClsidsWhitelistChange = (index: number, value: string) => {
    if (!editingRule || !editingRule.builtin_clsids_whitelist) return
    const newList = [...editingRule.builtin_clsids_whitelist]
    newList[index] = value
    setEditingRule({ ...editingRule, builtin_clsids_whitelist: newList })
  }

  const handleAddClsidsWhitelist = () => {
    if (!editingRule) return
    setEditingRule({
      ...editingRule,
      builtin_clsids_whitelist: [...(editingRule.builtin_clsids_whitelist || []), ''],
    })
  }

  const handleRemoveClsidsWhitelist = (index: number) => {
    if (!editingRule || !editingRule.builtin_clsids_whitelist) return
    const newList = editingRule.builtin_clsids_whitelist.filter((_, i) => i !== index)
    setEditingRule({ ...editingRule, builtin_clsids_whitelist: newList })
  }

  const calculateStats = (dets: Detection[]): DetectionStats => {
    const stats: DetectionStats = {
      total_detections: dets.length,
      duration_ms: 0,
      error_count: 0,
      by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      by_category: {},
      by_technique: {},
    }

    dets.forEach(d => {
      const sev = d.severity?.toLowerCase() || 'info'
      if (sev in stats.by_severity) {
        (stats.by_severity as any)[sev]++
      }
      stats.by_category[d.category] = (stats.by_category[d.category] || 0) + 1
      stats.by_technique[d.technique] = (stats.by_technique[d.technique] || 0) + 1
    })

    return stats
  }

  const fetchDetections = async (force = false) => {
    try {
      setLoading(true)
      setError(null)
      const params: { category?: string; technique?: string; force?: boolean } = {}
      if (filter.category) params.category = filter.category
      if (filter.technique) params.technique = filter.technique
      if (force) params.force = true
      const response = await persistenceAPI.detect(params)
      const data = response.data
      const dets = data.detections || []
      setDetections(dets)
      try {
        // 只保留最近 500 条，防止 localStorage 超限
        const toSave = dets.slice(-500)
        localStorage.setItem('persistence_detections', JSON.stringify(toSave))
      } catch (e) {
        console.warn('Failed to save detections to localStorage:', e)
        localStorage.removeItem('persistence_detections')
      }
      setStats(calculateStats(dets))
    } catch (err: any) {
      const msg = err.response?.status === 404
        ? 'Persistence detection not available (Windows only feature)'
        : err.response?.data?.error
          ? `Error: ${err.response.data.error}`
          : err.message || 'Failed to fetch detections'
      setError(msg)
      console.error('Persistence detection error:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleGenerateReport = async () => {
    try {
      setGeneratingReport(true)
      const response = await reportsAPI.generate({
        type: 'persistence',
        format: reportFormat,
      })
      if (response.data.id) {
        const reportId = response.data.id
        let status = response.data.status
        const maxAttempts = 30
        let attempts = 0

        while (status === 'generating' && attempts < maxAttempts) {
          await new Promise(resolve => setTimeout(resolve, 1000))
          try {
            const statusResponse = await reportsAPI.get(reportId)
            status = statusResponse.data.status
            attempts++
          } catch {
            break
          }
        }

        if (status === 'completed') {
          const link = document.createElement('a')
          link.href = `/api/reports/${reportId}/download?format=${reportFormat}`
          link.download = `persistence_report_${new Date().toISOString().slice(0, 10)}.${reportFormat}`
          link.click()
        } else if (status === 'failed') {
          alert(t('persistence.reportGenerationFailed'))
        } else {
          alert(t('persistence.reportGenerationTimeout'))
        }
      }
    } catch (err: any) {
      alert(err.message || 'Failed to generate report')
      console.error('Failed to generate report:', err)
    } finally {
      setGeneratingReport(false)
    }
  }

  const handleExportCSV = () => {
    if (filteredDetections.length === 0) {
      alert(t('persistence.exportNoData'))
      return
    }
    const headers = ['Time', 'Technique', 'Category', 'Severity', 'Title', 'Description', 'Evidence Type', 'Evidence Key', 'Evidence Value', 'Recommended Action', 'False Positive Risk']
    const csvContent = [
      headers.join(','),
      ...filteredDetections.map(d => [
        d.time || '',
        d.technique || '',
        d.category || '',
        d.severity || '',
        `"${(d.title || '').replace(/"/g, '""')}"`,
        `"${(d.description || '').replace(/"/g, '""')}"`,
        d.evidence?.type || '',
        `"${(d.evidence?.key || '').replace(/"/g, '""')}"`,
        `"${(d.evidence?.value || '').replace(/"/g, '""')}"`,
        `"${(d.recommended_action || '').replace(/"/g, '""')}"`,
        d.false_positive_risk || '',
      ].join(','))
    ].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `persistence_detections_${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  const handleExportFromBackend = () => {
    const params = new URLSearchParams()
    if (filter.category) params.append('category', filter.category)
    if (filter.technique) params.append('technique', filter.technique)
    params.append('format', 'csv')
    window.open(`/api/persistence/detect?${params.toString()}`, '_blank')
  }

  const filteredDetections = detections
    .filter(d => {
      if (filter.severity && d.severity?.toLowerCase() !== filter.severity) return false
      if (filter.category && d.category !== filter.category) return false
      if (filter.technique && d.technique !== filter.technique) return false
      return true
    })
    .reduce((acc, d) => {
      const key = d.id || `${d.technique}-${d.category}-${d.title}-${d.evidence?.key}`
      if (!acc.seen.has(key)) {
        acc.seen.add(key)
        acc.items.push(d)
      }
      return acc
    }, { seen: new Set<string>(), items: [] as Detection[] }).items

  const severityChartData = {
    labels: Object.keys(stats?.by_severity || {}),
    datasets: [
      {
        label: t('persistence.bySeverity'),
        data: Object.values(stats?.by_severity || {}),
        backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#65a30d', '#3b82f6'],
        fill: true,
      },
    ],
  }

  const categoryChartData = {
    labels: Object.keys(stats?.by_category || {}),
    datasets: [
      {
        label: t('persistence.byCategory'),
        data: Object.values(stats?.by_category || {}),
        backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16'],
        fill: true,
      },
    ],
  }

  const defaultStats = {
    total_detections: 0,
    duration_ms: 0,
    error_count: 0,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    by_category: {} as Record<string, number>,
    by_technique: {} as Record<string, number>,
  }

  const displayStats = stats || defaultStats

  return (
    <div className="persistence-page">
      {loading && (
        <div className="loading-overlay">
          <div className="spinner"></div>
          <p>{t('persistence.scanning')}</p>
          <p className="hint">{t('persistence.scanningHint')}</p>
        </div>
      )}

      <div className="page-header">
        <div className="header-left">
          <h1>{t('persistence.title')}</h1>
        </div>
        <div className="header-right">
          <div className="export-dropdown">
            <button onClick={() => {
              const menu = document.getElementById('persistence-export-menu')
              if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none'
            }} className="btn btn-secondary">
              导出 CSV ▾
            </button>
            <div id="persistence-export-menu" className="export-menu">
              <button onClick={handleExportCSV}>前端导出（已加载数据）</button>
              <button onClick={handleExportFromBackend}>后端导出（完整数据）</button>
            </div>
          </div>
        </div>
      </div>

      <div className="action-bar">
        <button onClick={() => fetchDetections(false)} className="btn btn-primary" disabled={loading}>
          {t('persistence.startScan')}
        </button>
        <button onClick={() => fetchDetections(true)} className="btn btn-secondary" disabled={loading}>
          {t('persistence.rescan')}
        </button>
        <button onClick={handleShowDetectorConfig} className="btn btn-secondary">
          {t('persistence.detectorConfig')}
        </button>
        <div className="report-format-selector">
          <select
            value={reportFormat}
            onChange={e => setReportFormat(e.target.value)}
            className="report-format-select"
          >
            <option value="html">{t('persistence.formatHTML')}</option>
            <option value="pdf">{t('persistence.formatPDF')}</option>
            <option value="json">{t('persistence.formatJSON')}</option>
          </select>
        </div>
        <button onClick={handleGenerateReport} className="btn btn-secondary" disabled={generatingReport}>
          {generatingReport ? t('persistence.generating') : t('persistence.generateReport')}
        </button>
      </div>

      {showDetectorConfig && (
        <div className="modal-overlay" onClick={() => setShowDetectorConfig(false)}>
          <div className="modal-content detector-config-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{t('persistence.detectorConfig')}</h2>
              <button className="close-btn" onClick={() => setShowDetectorConfig(false)}>×</button>
            </div>
            <div className="modal-body">
              <p className="config-description">
                {t('persistence.detectorConfigDesc')}
              </p>
              {detectorLoading ? (
                <div className="loading">{t('common.loading')}</div>
              ) : (
                <div className="detectors-list">
                  {detectors.map(detector => (
                    <div key={detector.name} className="detector-item">
                      <label className="detector-checkbox">
                        <input
                          type="checkbox"
                          checked={detector.enabled}
                          onChange={() => toggleDetector(detector.name)}
                        />
                        <span className="detector-name">{detector.name.replace(/_/g, ' ')}</span>
                      </label>
                      <span className="detector-technique">{detector.technique}</span>
                      <span className="detector-description">{detector.description}</span>
                      <button
                        className="edit-rule-btn"
                        onClick={(e) => {
                          e.stopPropagation()
                          setShowDetectorConfig(false)
                          handleShowRuleEditor(detector.name)
                        }}
                      >
                        {t('persistence.editRule')}
                      </button>
                    </div>
                  ))}
                </div>
              )}
              <div className="modal-actions">
                <button onClick={saveDetectorConfig} className="btn btn-primary">
                  {t('common.save')}
                </button>
                <button onClick={() => setShowDetectorConfig(false)} className="btn btn-secondary">
                  {t('common.cancel')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="error-banner">
          {t('common.error')}: {error}
          <button onClick={() => fetchDetections(false)} className="btn btn-small">重试</button>
        </div>
      )}

      <div className="stats-grid">
        <div className="stat-card stat-total">
          <div className="stat-value">{displayStats.total_detections}</div>
          <div className="stat-label">{t('persistence.total')}</div>
        </div>
        <div className="stat-card stat-critical">
          <div className="stat-value">{displayStats.by_severity.critical}</div>
          <div className="stat-label">{t('persistence.critical')}</div>
        </div>
        <div className="stat-card stat-high">
          <div className="stat-value">{displayStats.by_severity.high}</div>
          <div className="stat-label">{t('persistence.high')}</div>
        </div>
        <div className="stat-card stat-medium">
          <div className="stat-value">{displayStats.by_severity.medium}</div>
          <div className="stat-label">{t('persistence.medium')}</div>
        </div>
        <div className="stat-card stat-low">
          <div className="stat-value">{displayStats.by_severity.low}</div>
          <div className="stat-label">{t('persistence.low')}</div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="chart-card">
          <h3>{t('persistence.bySeverity')}</h3>
          <div className="chart-container">
            <Line
              data={severityChartData}
              options={{ responsive: true, plugins: { legend: { display: false } } }}
            />
          </div>
        </div>
        <div className="chart-card">
          <h3>{t('persistence.byCategory')}</h3>
          <div className="chart-container">
            <Line
              data={categoryChartData}
              options={{ responsive: true, plugins: { legend: { display: false } } }}
            />
          </div>
        </div>
      </div>

      <div className="filters">
        <select
          value={filter.severity || ''}
          onChange={e => setFilter({ ...filter, severity: e.target.value || undefined })}
        >
          <option value="">{t('persistence.allSeverities')}</option>
          <option value="critical">{t('persistence.critical')}</option>
          <option value="high">{t('persistence.high')}</option>
          <option value="medium">{t('persistence.medium')}</option>
          <option value="low">{t('persistence.low')}</option>
        </select>
        <select
          value={filter.category || ''}
          onChange={e => setFilter({ ...filter, category: e.target.value || undefined })}
        >
          <option value="">{t('persistence.allCategories')}</option>
          <option value="Registry">{t('persistence.categoryRegistry')}</option>
          <option value="ScheduledTask">{t('persistence.categoryScheduledTask')}</option>
          <option value="Service">{t('persistence.categoryService')}</option>
          <option value="WMI">{t('persistence.categoryWMI')}</option>
          <option value="COM">{t('persistence.categoryCOM')}</option>
          <option value="BITS">{t('persistence.categoryBITS')}</option>
          <option value="Accessibility">{t('persistence.categoryAccessibility')}</option>
        </select>
      </div>

      <div className="detections-table-container">
        {filteredDetections.length === 0 ? (
          <div className="empty-detections">
            <p>暂无检测数据</p>
            <p className="hint">点击上方"开始检测"按钮进行扫描</p>
          </div>
        ) : (
          <table className="detections-table">
            <thead>
              <tr>
                <th>{t('persistence.severity')}</th>
                <th>{t('persistence.technique')}</th>
                <th>{t('persistence.category')}</th>
                <th>{t('persistence.title')}</th>
                <th>{t('persistence.evidence')}</th>
                <th>{t('persistence.falsePositiveRisk')}</th>
              </tr>
            </thead>
            <tbody>
              {filteredDetections.map(detection => (
              <tr
                key={detection.id}
                onClick={() => setSelectedDetection(detection)}
                className="detection-row"
              >
                <td>
                  <span className={`severity-badge severity-${detection.severity?.toLowerCase()}`}>
                    {t(`persistence.${detection.severity?.toLowerCase()}`)}
                  </span>
                </td>
                <td>
                  <span className="technique-tag">{detection.technique}</span>
                </td>
                <td>{detection.category}</td>
                <td>{detection.title}</td>
                <td className="evidence-cell">
                  {detection.evidence?.key && <div className="evidence-key">{detection.evidence.key}</div>}
                  {detection.evidence?.value && <div className="evidence-value">{detection.evidence.value}</div>}
                </td>
                <td>{t(`persistence.${detection.false_positive_risk?.toLowerCase()}Risk`) || detection.false_positive_risk}</td>
              </tr>
            ))}
            </tbody>
          </table>
        )}
      </div>

      {selectedDetection && (
        <div className="modal-overlay" onClick={() => setSelectedDetection(null)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{selectedDetection.title}</h2>
              <button className="close-btn" onClick={() => setSelectedDetection(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-section">
                <h4>{t('persistence.basicInfo')}</h4>
                <p><strong>{t('persistence.severity')}:</strong> {selectedDetection.severity}</p>
                <p><strong>{t('persistence.technique')}:</strong> {selectedDetection.technique}</p>
                <p><strong>{t('persistence.time')}:</strong> {new Date(selectedDetection.time).toLocaleString()}</p>
              </div>
              {selectedDetection.explanation && (
              <div className="detail-section">
                <h4>{t('persistence.explanation')}</h4>
                <p>{selectedDetection.explanation}</p>
              </div>
              )}
              <div className="detail-section">
                <h4>{t('persistence.description')}</h4>
                <p>{selectedDetection.description}</p>
              </div>
              {selectedDetection.recommendation && (
              <div className="detail-section">
                <h4>{t('persistence.recommendation')}</h4>
                <p style={{ whiteSpace: 'pre-wrap' }}>{selectedDetection.recommendation}</p>
              </div>
              )}
              {selectedDetection.real_case && selectedDetection.real_case !== '暂无真实案例' && (
              <div className="detail-section">
                <h4>{t('persistence.realCase')}</h4>
                <p>{selectedDetection.real_case}</p>
              </div>
              )}
            </div>
          </div>
        </div>
      )}

      {showRuleEditor && editingRule && (
        <div className="modal-overlay" onClick={() => setShowRuleEditor(false)}>
          <div className="modal-content rule-editor-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2>{t('persistence.ruleEditor')}</h2>
              <button className="close-btn" onClick={() => setShowRuleEditor(false)}>×</button>
            </div>
            <div className="modal-body">
              {ruleLoading ? (
                <div className="loading">{t('common.loading')}</div>
              ) : (
                <>
                  <div className="rule-editor-header">
                    <div className="rule-info">
                      <h3>{editingRule.name.replace(/_/g, ' ')}</h3>
                      <p>{editingRule.description}</p>
                      <span className="technique-tag">{editingRule.technique}</span>
                    </div>
                    <label className="rule-enabled-toggle">
                      <input
                        type="checkbox"
                        checked={editingRule.enabled}
                        onChange={(e) => setEditingRule({ ...editingRule, enabled: e.target.checked })}
                      />
                      <span>{editingRule.enabled ? t('persistence.enabled') : t('persistence.disabled')}</span>
                    </label>
                  </div>

                  {editingRule.registry_paths && editingRule.registry_paths.length > 0 && (
                    <div className="rule-section">
                      <h4>{t('persistence.registryPaths')}</h4>
                      <div className="paths-list">
                        {editingRule.registry_paths.map((path, idx) => (
                          <div key={idx} className="path-item">{path}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="rule-section">
                    <h4>{t('persistence.suspiciousIndicators')}</h4>
                    <p className="section-desc">
                      {t('persistence.indicatorDesc')}
                    </p>
                    <div className="indicators-list">
                      {editingRule.suspicious_indicators.map((indicator, idx) => (
                        <div key={idx} className="indicator-item">
                          <input
                            type="text"
                            value={indicator}
                            onChange={(e) => handleIndicatorChange(idx, e.target.value)}
                            placeholder={t('persistence.indicatorPlaceholder')}
                          />
                          <button
                            className="remove-btn"
                            onClick={() => handleRemoveIndicator(idx)}
                          >
                            ×
                          </button>
                        </div>
                      ))}
                      <button className="add-btn" onClick={handleAddIndicator}>
                        + {t('persistence.addIndicator')}
                      </button>
                    </div>
                  </div>

                  <div className="rule-section">
                    <h4>{t('persistence.whitelistEntries')}</h4>
                    <p className="section-desc">
                      {t('persistence.whitelistDesc')}
                    </p>
                    {editingRule.builtin_whitelist && editingRule.builtin_whitelist.length > 0 && (
                      <div className="builtin-whitelist">
                        <h5>{t('persistence.builtinWhitelist') || 'Builtin Whitelist (Read-only)'}</h5>
                        <div className="whitelist-list readonly">
                          {editingRule.builtin_whitelist.map((entry, idx) => (
                            <div key={idx} className="whitelist-item">
                              <span className="whitelist-entry">{entry}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {editingRule.builtin_dll_whitelist && editingRule.builtin_dll_whitelist.length > 0 && (
                      <div className="builtin-whitelist">
                        <h5>{t('persistence.builtinDllWhitelist') || 'Builtin DLL Whitelist (Read-only)'}</h5>
                        <div className="whitelist-list readonly">
                          {editingRule.builtin_dll_whitelist.map((entry, idx) => (
                            <div key={idx} className="whitelist-item">
                              <span className="whitelist-entry">{entry}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {editingRule.builtin_clsids_whitelist && editingRule.builtin_clsids_whitelist.length > 0 && (
                      <div className="builtin-whitelist">
                        <h5>{t('persistence.builtinClsidsWhitelist') || 'Builtin CLSIDs Whitelist (Read-only)'}</h5>
                        <div className="whitelist-list readonly">
                          {editingRule.builtin_clsids_whitelist.map((entry, idx) => (
                            <div key={idx} className="whitelist-item">
                              <span className="whitelist-entry">{entry}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    <h5>{t('persistence.userWhitelist') || 'User Whitelist'}</h5>
                    <div className="whitelist-list">
                      {editingRule.whitelist.map((entry, idx) => (
                        <div key={idx} className="whitelist-item">
                          <input
                            type="text"
                            value={entry}
                            onChange={(e) => handleWhitelistChange(idx, e.target.value)}
                            placeholder={t('persistence.whitelistPlaceholder')}
                          />
                          <button
                            className="remove-btn"
                            onClick={() => handleRemoveWhitelist(idx)}
                          >
                            ×
                          </button>
                        </div>
                      ))}
                      <button className="add-btn" onClick={handleAddWhitelist}>
                        + {t('persistence.addWhitelist')}
                      </button>
                    </div>
                    {editingRule.builtin_dll_whitelist && (
                      <>
                        <h5>{t('persistence.userDllWhitelist') || 'User DLL Whitelist'}</h5>
                        <div className="whitelist-list">
                          {editingRule.builtin_dll_whitelist.map((entry, idx) => (
                            <div key={idx} className="whitelist-item">
                              <input
                                type="text"
                                value={entry}
                                onChange={(e) => handleDllWhitelistChange(idx, e.target.value)}
                                placeholder={t('persistence.whitelistPlaceholder')}
                              />
                              <button
                                className="remove-btn"
                                onClick={() => handleRemoveDllWhitelist(idx)}
                              >
                                ×
                              </button>
                            </div>
                          ))}
                          <button className="add-btn" onClick={handleAddDllWhitelist}>
                            + {t('persistence.addWhitelist')}
                          </button>
                        </div>
                      </>
                    )}
                    {editingRule.builtin_clsids_whitelist && (
                      <>
                        <h5>{t('persistence.userClsidsWhitelist') || 'User CLSIDs Whitelist'}</h5>
                        <div className="whitelist-list">
                          {editingRule.builtin_clsids_whitelist.map((entry, idx) => (
                            <div key={idx} className="whitelist-item">
                              <input
                                type="text"
                                value={entry}
                                onChange={(e) => handleClsidsWhitelistChange(idx, e.target.value)}
                                placeholder={t('persistence.whitelistPlaceholder')}
                              />
                              <button
                                className="remove-btn"
                                onClick={() => handleRemoveClsidsWhitelist(idx)}
                              >
                                ×
                              </button>
                            </div>
                          ))}
                          <button className="add-btn" onClick={handleAddClsidsWhitelist}>
                            + {t('persistence.addWhitelist')}
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </>
              )}
              <div className="modal-actions">
                <button onClick={() => setShowRuleEditor(false)} className="btn btn-secondary">
                  {t('common.cancel')}
                </button>
                <button onClick={handleSaveRule} className="btn btn-primary">
                  {t('common.save')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Persistence
