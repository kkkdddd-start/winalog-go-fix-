import { useEffect, useState, useRef } from 'react'
import { useI18n } from '../locales/I18n'
import { systemAPI } from '../api'

interface Metrics {
  total_events: number
  total_alerts: number
  events_per_minute: number
  alerts_per_hour: number
  uptime_seconds: number
  cpu_count: number
  go_version: string
  memory_usage_mb: number
  memory_limit_mb?: number
}

function Metrics() {
  const { t } = useI18n()
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [timeRange, setTimeRange] = useState<'1h' | '5m' | '1m'>('5m')
  const [history, setHistory] = useState<{events: number[], alerts: number[], memory: number[], timestamps: string[]}>({
    events: [],
    alerts: [],
    memory: [],
    timestamps: []
  })
  const canvasRef = useRef<HTMLCanvasElement>(null)

  const fetchMetrics = () => {
    systemAPI.getMetrics()
      .then(res => {
        setMetrics(res.data)
        setLoading(false)
        
        setHistory(prev => {
          const now = new Date().toLocaleTimeString()
          const newEvents = [...prev.events, res.data.total_events].slice(-20)
          const newAlerts = [...prev.alerts, res.data.total_alerts].slice(-20)
          const newMemory = [...prev.memory, res.data.memory_usage_mb].slice(-20)
          const newTimestamps = [...prev.timestamps, now].slice(-20)
          return { events: newEvents, alerts: newAlerts, memory: newMemory, timestamps: newTimestamps }
        })
      })
      .catch(err => {
        setError(err.message || t('common.error'))
        setLoading(false)
      })
  }

  useEffect(() => {
    fetchMetrics()
    const interval = setInterval(fetchMetrics, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (canvasRef.current && history.events.length > 1) {
      drawChart()
    }
  }, [history])

  const drawChart = () => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const width = canvas.width
    const height = canvas.height
    const padding = 40

    ctx.clearRect(0, 0, width, height)

    const maxEvents = Math.max(...history.events, 1)
    const minEvents = Math.min(...history.events, 0)
    const range = maxEvents - minEvents || 1

    ctx.strokeStyle = '#333'
    ctx.lineWidth = 1
    for (let i = 0; i <= 4; i++) {
      const y = padding + (height - 2 * padding) * i / 4
      ctx.beginPath()
      ctx.moveTo(padding, y)
      ctx.lineTo(width - padding, y)
      ctx.stroke()
    }

    const xStep = (width - 2 * padding) / (history.events.length - 1)

    ctx.strokeStyle = '#00d9ff'
    ctx.lineWidth = 2
    ctx.beginPath()
    history.events.forEach((val, i) => {
      const x = padding + i * xStep
      const y = padding + (height - 2 * padding) * (1 - (val - minEvents) / range)
      if (i === 0) ctx.moveTo(x, y)
      else ctx.lineTo(x, y)
    })
    ctx.stroke()

    ctx.fillStyle = '#00d9ff'
    history.events.forEach((val, i) => {
      const x = padding + i * xStep
      const y = padding + (height - 2 * padding) * (1 - (val - minEvents) / range)
      ctx.beginPath()
      ctx.arc(x, y, 3, 0, Math.PI * 2)
      ctx.fill()
    })
  }

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    if (days > 0) return `${days}d ${hours}h ${mins}m`
    if (hours > 0) return `${hours}h ${mins}m`
    return `${mins}m`
  }

  if (loading) return (
    <div className="metrics-page">
      <div className="loading-state">
        <div className="spinner"></div>
        <div>{t('common.loading')}</div>
      </div>
    </div>
  )

  if (error) return (
    <div className="metrics-page">
      <div className="error-state">❌ {error}</div>
    </div>
  )

  const memPercent = metrics ? ((metrics.memory_usage_mb / (metrics.memory_limit_mb || 512)) * 100).toFixed(1) : '0'

  return (
    <div className="metrics-page">
      <div className="page-header">
        <h2>{t('metrics.title')}</h2>
        <div className="time-range-selector">
          <button className={timeRange === '1m' ? 'active' : ''} onClick={() => setTimeRange('1m')}>1m</button>
          <button className={timeRange === '5m' ? 'active' : ''} onClick={() => setTimeRange('5m')}>5m</button>
          <button className={timeRange === '1h' ? 'active' : ''} onClick={() => setTimeRange('1h')}>1h</button>
        </div>
      </div>

      <div className="metrics-grid">
        <div className="metric-card large">
          <div className="metric-header">
            <span className="metric-icon">📊</span>
            <span className="metric-title">{t('metrics.totalEvents')}</span>
          </div>
          <div className="metric-value">{(metrics?.total_events || 0).toLocaleString()}</div>
          <div className="metric-trend up">
            📈 {(metrics?.events_per_minute || 0).toFixed(1)}/min
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-icon">🚨</span>
            <span className="metric-title">{t('metrics.totalAlerts')}</span>
          </div>
          <div className="metric-value alert">{(metrics?.total_alerts || 0).toLocaleString()}</div>
          <div className="metric-sub">{(metrics?.alerts_per_hour || 0).toFixed(1)}/hr</div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-icon">💾</span>
            <span className="metric-title">{t('metrics.memory')}</span>
          </div>
          <div className="metric-value memory">{(metrics?.memory_usage_mb || 0).toFixed(1)}</div>
          <div className="metric-bar">
            <div className="metric-bar-fill" style={{width: `${memPercent}%`}}></div>
          </div>
          <div className="metric-sub">{memPercent}% of limit</div>
        </div>

        <div className="metric-card">
          <div className="metric-header">
            <span className="metric-icon">⚡</span>
            <span className="metric-title">{t('systemInfo.uptime')}</span>
          </div>
          <div className="metric-value uptime">{formatUptime(metrics?.uptime_seconds || 0)}</div>
          <div className="metric-sub">{metrics?.uptime_seconds || 0}s total</div>
        </div>
      </div>

      <div className="chart-section">
        <div className="chart-card">
          <div className="chart-header">
            <h3>Event Throughput</h3>
            <div className="chart-legend">
              <span className="legend-item"><span className="dot cyan"></span>Total Events</span>
            </div>
          </div>
          <div className="chart-container">
            <canvas ref={canvasRef} width={800} height={200}></canvas>
          </div>
        </div>
      </div>

      <div className="prometheus-section">
        <div className="section-header">
          <h3>{t('metrics.prometheusFormat')}</h3>
          <button className="btn-copy" onClick={() => navigator.clipboard.writeText(getPrometheusText())}>
            📋 Copy
          </button>
        </div>
        <pre className="prometheus-code">{getPrometheusText()}</pre>
      </div>

      <style>{`
        .metrics-page {
          padding: 20px;
        }
        
        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 24px;
        }
        
        .metrics-page h2 {
          font-size: 1.8rem;
          color: #00d9ff;
        }
        
        .time-range-selector {
          display: flex;
          gap: 4px;
          background: rgba(0, 0, 0, 0.2);
          padding: 4px;
          border-radius: 6px;
        }
        
        .time-range-selector button {
          padding: 6px 12px;
          background: transparent;
          border: none;
          color: #888;
          cursor: pointer;
          border-radius: 4px;
          font-size: 0.85rem;
        }
        
        .time-range-selector button:hover {
          color: #00d9ff;
        }
        
        .time-range-selector button.active {
          background: #00d9ff;
          color: #1a1a2e;
        }
        
        .metrics-grid {
          display: grid;
          grid-template-columns: 2fr 1fr 1fr 1fr;
          gap: 16px;
          margin-bottom: 24px;
        }
        
        .metric-card {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          padding: 20px;
          border: 1px solid #333;
        }
        
        .metric-card.large {
          grid-row: span 2;
        }
        
        .metric-header {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 12px;
        }
        
        .metric-icon {
          font-size: 1.2rem;
        }
        
        .metric-title {
          color: #888;
          font-size: 0.85rem;
          text-transform: uppercase;
        }
        
        .metric-value {
          font-size: 2.2rem;
          font-weight: bold;
          color: #fff;
          margin-bottom: 8px;
        }
        
        .metric-value.alert {
          color: #ef4444;
        }
        
        .metric-value.memory {
          color: #f97316;
        }
        
        .metric-value.uptime {
          font-size: 1.8rem;
        }
        
        .metric-trend {
          font-size: 0.9rem;
        }
        
        .metric-trend.up {
          color: #22c55e;
        }
        
        .metric-trend.down {
          color: #ef4444;
        }
        
        .metric-sub {
          color: #666;
          font-size: 0.8rem;
          margin-top: 4px;
        }
        
        .metric-bar {
          height: 6px;
          background: rgba(255, 255, 255, 0.1);
          border-radius: 3px;
          margin-top: 8px;
          overflow: hidden;
        }
        
        .metric-bar-fill {
          height: 100%;
          background: linear-gradient(90deg, #f97316, #ea580c);
          border-radius: 3px;
        }
        
        .chart-section {
          margin-bottom: 24px;
        }
        
        .chart-card {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          padding: 20px;
          border: 1px solid #333;
        }
        
        .chart-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }
        
        .chart-header h3 {
          color: #00d9ff;
          font-size: 1rem;
          margin: 0;
        }
        
        .chart-legend {
          display: flex;
          gap: 16px;
        }
        
        .legend-item {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 0.85rem;
          color: #888;
        }
        
        .legend-item .dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
        }
        
        .legend-item .dot.cyan {
          background: #00d9ff;
        }
        
        .chart-container {
          height: 200px;
          position: relative;
        }
        
        .chart-container canvas {
          width: 100%;
          height: 100%;
        }
        
        .prometheus-section {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          padding: 20px;
          border: 1px solid #333;
        }
        
        .section-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 16px;
        }
        
        .section-header h3 {
          color: #00d9ff;
          font-size: 1rem;
          margin: 0;
        }
        
        .btn-copy {
          padding: 6px 12px;
          background: rgba(0, 217, 255, 0.1);
          border: 1px solid #00d9ff;
          border-radius: 4px;
          color: #00d9ff;
          cursor: pointer;
          font-size: 0.85rem;
        }
        
        .btn-copy:hover {
          background: rgba(0, 217, 255, 0.2);
        }
        
        .prometheus-code {
          background: rgba(0, 0, 0, 0.4);
          padding: 16px;
          border-radius: 8px;
          font-family: monospace;
          font-size: 0.8rem;
          color: #22c55e;
          overflow-x: auto;
          max-height: 300px;
          overflow-y: auto;
        }
        
        .loading-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 60vh;
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
        
        .error-state {
          padding: 40px;
          text-align: center;
          color: #ef4444;
          font-size: 1.1rem;
        }
      `}</style>
    </div>
  )

  function getPrometheusText() {
    return `# HELP winalog_events_total Total number of events
# TYPE winalog_events_total counter
winalog_events_total ${metrics?.total_events || 0}

# HELP winalog_alerts_total Total number of alerts
# TYPE winalog_alerts_total counter
winalog_alerts_total ${metrics?.total_alerts || 0}

# HELP winalog_events_per_minute Event ingestion rate
# TYPE winalog_events_per_minute gauge
winalog_events_per_minute ${metrics?.events_per_minute || 0}

# HELP winalog_alerts_per_hour Alert generation rate
# TYPE winalog_alerts_per_hour gauge
winalog_alerts_per_hour ${metrics?.alerts_per_hour || 0}

# HELP winalog_uptime_seconds Application uptime in seconds
# TYPE winalog_uptime_seconds counter
winalog_uptime_seconds ${metrics?.uptime_seconds || 0}

# HELP winalog_cpu_count Number of CPUs
# TYPE winalog_cpu_count gauge
winalog_cpu_count ${metrics?.cpu_count || 0}

# HELP winalog_memory_bytes Process memory usage in bytes
# TYPE winalog_memory_bytes gauge
winalog_memory_bytes ${((metrics?.memory_usage_mb || 0) * 1024 * 1024).toFixed(0)}

# HELP go_info Go version info
# TYPE go_info gauge
go_info{version="${metrics?.go_version || 'unknown'}"} 1`
  }
}

export default Metrics