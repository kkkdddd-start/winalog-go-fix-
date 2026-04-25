import { useState, useEffect } from 'react'
import { useI18n } from '../locales/I18n'
import { reportsAPI } from '../api'

interface Report {
  id: string
  title: string
  type: string
  format: string
  generated_at: string
  file_size: number
  status?: string
}

function Reports() {
  const { t, locale } = useI18n()
  const [generating, setGenerating] = useState(false)
  const [reportType, setReportType] = useState('security')
  const [format, setFormat] = useState('html')
  const [reportLang, setReportLang] = useState(locale || 'en')
  const [dateRange, setDateRange] = useState('7d')
  const [reports, setReports] = useState<Report[]>([])
  const [lastGenerated, setLastGenerated] = useState<string | null>(null)
  const [generateError, setGenerateError] = useState<string | null>(null)

  useEffect(() => {
    reportsAPI.list().then(res => setReports(res.data.reports)).catch(console.error)
  }, [])

  const handleGenerate = async () => {
    setGenerating(true)
    setGenerateError(null)
    
    try {
      const endTime = new Date()
      const startTime = new Date()
      
      switch (dateRange) {
        case '24h': startTime.setHours(startTime.getHours() - 24); break
        case '7d': startTime.setDate(startTime.getDate() - 7); break
        case '30d': startTime.setDate(startTime.getDate() - 30); break
        case '90d': startTime.setDate(startTime.getDate() - 90); break
      }
      
      const genRes = await reportsAPI.generate({
        type: reportType,
        format,
        language: reportLang,
        start_time: startTime.toISOString(),
        end_time: endTime.toISOString()
      })
      
      const reportId = genRes.data.id
      
      let status = genRes.data.status || 'generating'
      let pollCount = 0
      const maxPolls = 60
      
      while (status === 'generating' && pollCount < maxPolls) {
        await new Promise(resolve => setTimeout(resolve, 2000))
        pollCount++
        
        try {
          const statusRes = await reportsAPI.get(reportId)
          status = statusRes.data.status || 'generating'
        } catch (e) {
          console.error('Error polling report status:', e)
          break
        }
      }
      
      setLastGenerated(new Date().toLocaleString())
      
      const res = await reportsAPI.list()
      const newReports = res.data.reports || []
      setReports(newReports)
      
      if (newReports.length > 0) {
        const latestReport = newReports[0]
        
        if (status === 'completed') {
          const downloadNow = confirm(`Report generated successfully!\n\nReport: ${latestReport.title || latestReport.id}\nType: ${latestReport.type}\nFormat: ${latestReport.format}\nStatus: ${status}\n\nClick OK to download now, or Cancel to view in reports list.`)
          if (downloadNow) {
            handleDownload(latestReport)
          }
        } else {
          setGenerateError(`Report generation is still ${status}. Please check the reports list later.`)
        }
      }
    } catch (error) {
      console.error('Report generation failed:', error)
      setGenerateError('Failed to generate report. Please try again.')
    } finally {
      setGenerating(false)
    }
  }

  const handleView = async (report: Report) => {
    try {
      const res = await reportsAPI.download(report.id)
      const blob = new Blob([res.data], { type: res.headers['content-type'] || 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const newWindow = window.open('', '_blank')
      if (newWindow) {
        if (report.format === 'html') {
          const reader = new FileReader()
          reader.onload = () => {
            newWindow.document.write(reader.result as string)
            newWindow.document.close()
          }
          reader.readAsText(blob)
        } else {
          newWindow.document.write(`<pre>${JSON.stringify(res.data, null, 2)}</pre>`)
          newWindow.document.close()
        }
      }
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to view report:', error)
      alert('Failed to view report')
    }
  }

  const handleDownload = async (report: Report) => {
    try {
      const res = await reportsAPI.download(report.id)
      const blob = new Blob([res.data], { type: res.headers['content-type'] || 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${report.title || report.id}.${report.format}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to download report:', error)
      alert('Failed to download report')
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }

  const reportTypes = [
    { value: 'security', label: t('reports.securitySummary'), icon: '🛡️', desc: 'Comprehensive security overview with event statistics and alerts' },
    { value: 'alert', label: t('reports.alertAnalysis'), icon: '🚨', desc: 'Detailed alert analysis with threat patterns' },
    { value: 'timeline', label: t('reports.eventTimeline'), icon: '📊', desc: 'Chronological event timeline with correlations' },
    { value: 'compliance', label: t('reports.complianceReport'), icon: '📋', desc: 'Compliance status and audit trail report' },
  ]

  const formatOptions = [
    { value: 'html', label: 'HTML', icon: '🌐', desc: 'Interactive web report with charts' },
    { value: 'json', label: 'JSON', icon: '📄', desc: 'Structured data for further processing' },
    { value: 'pdf', label: 'PDF', icon: '📕', desc: 'Printable document format' },
  ]

  return (
    <div className="reports-page">
      <h2>{t('reports.title')}</h2>
      
      <div className="reports-grid">
        <div className="reports-card main-config">
          <h3>{t('reports.generateReport')}</h3>
          <p className="card-desc">{t('reports.generateDesc')}</p>
          
          <div className="config-section">
            <label className="section-label">Report Type</label>
            <div className="type-grid">
              {reportTypes.map(rt => (
                <div 
                  key={rt.value}
                  className={`type-option ${reportType === rt.value ? 'selected' : ''}`}
                  onClick={() => setReportType(rt.value)}
                >
                  <div className="type-icon">{rt.icon}</div>
                  <div className="type-label">{rt.label}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="config-section">
            <label className="section-label">Output Format</label>
            <div className="format-row">
              {formatOptions.map(fo => (
                <div 
                  key={fo.value}
                  className={`format-option ${format === fo.value ? 'selected' : ''}`}
                  onClick={() => setFormat(fo.value)}
                >
                  <div className="format-icon">{fo.icon}</div>
                  <div className="format-label">{fo.label}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="config-section">
            <label className="section-label">Time Range</label>
            <div className="date-range-selector">
              {['24h', '7d', '30d', '90d'].map(range => (
                <button
                  key={range}
                  className={`range-btn ${dateRange === range ? 'active' : ''}`}
                  onClick={() => setDateRange(range)}
                >
                  {range === '24h' && 'Last 24 Hours'}
                  {range === '7d' && 'Last 7 Days'}
                  {range === '30d' && 'Last 30 Days'}
                  {range === '90d' && 'Last 90 Days'}
                </button>
              ))}
            </div>
          </div>

          <div className="config-section">
            <label className="section-label">Report Language</label>
            <div className="format-row">
              <div 
                className={`format-option ${reportLang === 'en' ? 'selected' : ''}`}
                onClick={() => setReportLang('en')}
              >
                <div className="format-icon">EN</div>
                <div className="format-label">{t('reports.languageEnglish')}</div>
              </div>
              <div 
                className={`format-option ${reportLang === 'zh' ? 'selected' : ''}`}
                onClick={() => setReportLang('zh')}
              >
                <div className="format-icon">CN</div>
                <div className="format-label">{t('reports.languageChinese')}</div>
              </div>
            </div>
          </div>

          {generateError && (
            <div className="error-message">
              ⚠️ {generateError}
            </div>
          )}

          <button 
            className="btn-primary generate-btn" 
            onClick={handleGenerate}
            disabled={generating}
          >
            {generating ? (
              <>
                <span className="btn-spinner"></span>
                Generating Report...
              </>
            ) : (
              <>📊 {t('reports.generate')}</>
            )}
          </button>

          {lastGenerated && (
            <div className="last-generated">
              ✓ Last report generated at {lastGenerated}
            </div>
          )}
        </div>

        <div className="reports-card stats-card">
          <h3>Report Statistics</h3>
          
          <div className="stats-preview">
            <div className="stat-item">
              <div className="stat-icon">📁</div>
              <div className="stat-value">{reports.length}</div>
              <div className="stat-label">Total Reports</div>
            </div>
            
            <div className="stat-item">
              <div className="stat-icon">🛡️</div>
              <div className="stat-value">{reports.filter(r => r.type === 'security').length}</div>
              <div className="stat-label">Security Reports</div>
            </div>
            
            <div className="stat-item">
              <div className="stat-icon">🚨</div>
              <div className="stat-value">{reports.filter(r => r.type === 'alert').length}</div>
              <div className="stat-label">Alert Reports</div>
            </div>
          </div>

          <div className="chart-placeholder">
            <div className="chart-label">Reports by Type</div>
            <div className="mini-chart">
              <div className="bar" style={{height: '60%', background: '#00d9ff'}}></div>
              <div className="bar" style={{height: '30%', background: '#f97316'}}></div>
              <div className="bar" style={{height: '80%', background: '#22c55e'}}></div>
              <div className="bar" style={{height: '45%', background: '#eab308'}}></div>
            </div>
          </div>
        </div>
      </div>

      <div className="reports-card full-width">
        <h3>{t('reports.recentReports')}</h3>
        
        {reports.length > 0 ? (
          <div className="reports-table">
            <table>
              <thead>
                <tr>
                  <th>Report Name</th>
                  <th>Type</th>
                  <th>Format</th>
                  <th>Generated</th>
                  <th>Size</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(report => (
                  <tr key={report.id}>
                    <td>
                      <div className="report-name">
                        <span className="report-icon">
                          {report.type === 'security' && '🛡️'}
                          {report.type === 'alert' && '🚨'}
                          {report.type === 'timeline' && '📊'}
                          {report.type === 'compliance' && '📋'}
                        </span>
                        {report.title || report.id}
                      </div>
                    </td>
                    <td><span className={`type-badge ${report.type}`}>{report.type}</span></td>
                    <td><span className="format-badge">{report.format.toUpperCase()}</span></td>
                    <td>{new Date(report.generated_at).toLocaleString()}</td>
                    <td>{formatSize(report.file_size)}</td>
                    <td>
                      <button className="btn-small" onClick={() => handleView(report)}>View</button>
                      <button className="btn-small" onClick={() => handleDownload(report)}>Download</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">📊</div>
            <div className="empty-text">{t('reports.noReports')}</div>
            <div className="empty-hint">Generate your first report using the form above</div>
          </div>
        )}
      </div>

      <style>{`
        .reports-page h2 {
          font-size: 1.8rem;
          color: #00d9ff;
          margin-bottom: 24px;
        }
        
        .reports-grid {
          display: grid;
          grid-template-columns: 2fr 1fr;
          gap: 20px;
          margin-bottom: 20px;
        }
        
        .reports-card {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          padding: 24px;
          border: 1px solid #333;
        }
        
        .reports-card.full-width {
          grid-column: 1 / -1;
        }
        
        .reports-card h3 {
          color: #00d9ff;
          font-size: 1.2rem;
          margin-bottom: 8px;
        }
        
        .card-desc {
          color: #888;
          font-size: 0.85rem;
          margin-bottom: 24px;
        }
        
        .config-section {
          margin-bottom: 24px;
        }
        
        .section-label {
          display: block;
          color: #888;
          font-size: 0.85rem;
          margin-bottom: 12px;
          text-transform: uppercase;
          letter-spacing: 1px;
        }
        
        .type-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 12px;
        }
        
        .type-option {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 16px;
          background: rgba(0, 0, 0, 0.2);
          border-radius: 8px;
          cursor: pointer;
          border: 2px solid transparent;
          transition: all 0.2s;
        }
        
        .type-option:hover {
          background: rgba(0, 217, 255, 0.05);
        }
        
        .type-option.selected {
          border-color: #00d9ff;
          background: rgba(0, 217, 255, 0.1);
        }
        
        .type-icon {
          font-size: 1.5rem;
        }
        
        .type-label {
          color: #eee;
          font-weight: 500;
        }
        
        .format-row {
          display: flex;
          gap: 12px;
        }
        
        .format-option {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 8px;
          padding: 16px;
          background: rgba(0, 0, 0, 0.2);
          border-radius: 8px;
          cursor: pointer;
          border: 2px solid transparent;
          transition: all 0.2s;
        }
        
        .format-option:hover {
          background: rgba(0, 217, 255, 0.05);
        }
        
        .format-option.selected {
          border-color: #00d9ff;
          background: rgba(0, 217, 255, 0.1);
        }
        
        .format-icon {
          font-size: 1.5rem;
        }
        
        .format-label {
          color: #eee;
          font-size: 0.9rem;
        }
        
        .date-range-selector {
          display: flex;
          gap: 8px;
        }
        
        .range-btn {
          flex: 1;
          padding: 10px 16px;
          background: rgba(0, 0, 0, 0.2);
          border: 1px solid #333;
          border-radius: 6px;
          color: #888;
          cursor: pointer;
          transition: all 0.2s;
          font-size: 0.85rem;
        }
        
        .range-btn:hover {
          border-color: #00d9ff;
          color: #00d9ff;
        }
        
        .range-btn.active {
          background: #00d9ff;
          border-color: #00d9ff;
          color: #1a1a2e;
        }
        
        .generate-btn {
          width: 100%;
          padding: 14px 24px;
          font-size: 1rem;
        }
        
        .btn-spinner {
          width: 18px;
          height: 18px;
          border: 2px solid rgba(0,0,0,0.2);
          border-top-color: #1a1a2e;
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
          display: inline-block;
          margin-right: 8px;
        }
        
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        
        .last-generated {
          text-align: center;
          color: #22c55e;
          font-size: 0.85rem;
          margin-top: 12px;
        }
        
        .error-message {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
          color: #ef4444;
          padding: 12px;
          border-radius: 8px;
          margin-bottom: 16px;
          font-size: 0.9rem;
        }
        
        .stats-preview {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 16px;
          margin-bottom: 24px;
        }
        
        .stat-item {
          text-align: center;
          padding: 16px;
          background: rgba(0, 0, 0, 0.2);
          border-radius: 8px;
        }
        
        .stat-icon {
          font-size: 1.5rem;
          margin-bottom: 8px;
        }
        
        .stat-value {
          font-size: 1.8rem;
          font-weight: bold;
          color: #fff;
        }
        
        .stat-label {
          font-size: 0.75rem;
          color: #888;
          text-transform: uppercase;
          margin-top: 4px;
        }
        
        .chart-placeholder {
          background: rgba(0, 0, 0, 0.2);
          border-radius: 8px;
          padding: 16px;
        }
        
        .chart-label {
          color: #888;
          font-size: 0.85rem;
          margin-bottom: 16px;
        }
        
        .mini-chart {
          display: flex;
          align-items: flex-end;
          gap: 8px;
          height: 80px;
        }
        
        .bar {
          flex: 1;
          border-radius: 4px 4px 0 0;
          min-height: 8px;
        }
        
        .reports-table table {
          width: 100%;
          border-collapse: collapse;
        }
        
        .reports-table th,
        .reports-table td {
          padding: 12px 16px;
          text-align: left;
          border-bottom: 1px solid #333;
        }
        
        .reports-table th {
          background: rgba(0, 0, 0, 0.2);
          color: #00d9ff;
          font-weight: 600;
          font-size: 0.85rem;
          text-transform: uppercase;
        }
        
        .reports-table tr:hover {
          background: rgba(0, 217, 255, 0.05);
        }
        
        .report-name {
          display: flex;
          align-items: center;
          gap: 8px;
          font-family: monospace;
        }
        
        .report-icon {
          font-size: 1.2rem;
        }
        
        .type-badge, .format-badge {
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 0.8rem;
          text-transform: uppercase;
        }
        
        .type-badge.security { background: rgba(0, 217, 255, 0.1); color: #00d9ff; }
        .type-badge.alert { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
        .type-badge.timeline { background: rgba(34, 197, 94, 0.1); color: #22c55e; }
        .type-badge.compliance { background: rgba(234, 179, 8, 0.1); color: #eab308; }
        
        .format-badge {
          background: rgba(255, 255, 255, 0.05);
          color: #888;
        }
        
        .btn-small {
          padding: 6px 12px;
          font-size: 0.8rem;
          margin-right: 8px;
        }
        
        .empty-state {
          text-align: center;
          padding: 40px;
        }
        
        .empty-icon {
          font-size: 3rem;
          margin-bottom: 16px;
        }
        
        .empty-text {
          color: #888;
          font-size: 1.1rem;
          margin-bottom: 8px;
        }
        
        .empty-hint {
          color: #555;
          font-size: 0.85rem;
        }
      `}</style>
    </div>
  )
}

export default Reports