import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { alertsAPI, timelineAPI, dashboardAPI } from '../api'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import { Line, Bar, Doughnut } from 'react-chartjs-2'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
)

interface AlertStats {
  total: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_type?: Record<string, number>
}

interface TrendData {
  labels: string[]
  events: number[]
  alerts: number[]
}

interface CollectionStats {
  total_events: number
  total_size: string
  sources: Record<string, number>
  last_import: string
}

function Dashboard() {
  const { t } = useI18n()
  const navigate = useNavigate()
  const [stats, setStats] = useState<AlertStats | null>(null)
  const [trendData, setTrendData] = useState<TrendData | null>(null)
  const [collectionStats, setCollectionStats] = useState<CollectionStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      alertsAPI.stats(),
      timelineAPI.get(24),
      dashboardAPI.getCollectionStats(),
    ])
      .then(([statsRes, timelineRes, collectionRes]) => {
        setStats(statsRes.data)

        const hours = 24
        const labels: string[] = []
        const events: number[] = []
        const alerts: number[] = []

        for (let i = hours - 1; i >= 0; i--) {
          const date = new Date()
          date.setHours(date.getHours() - i)
          labels.push(date.getHours() + ':00')

          const hourStart = new Date(date)
          hourStart.setMinutes(0, 0, 0)
          const hourEnd = new Date(date)
          hourEnd.setMinutes(59, 59, 999)

          const hourEvents = timelineRes.data.entries?.filter((e: any) => {
            const eventTime = new Date(e.timestamp)
            return e.type === 'event' && eventTime >= hourStart && eventTime <= hourEnd
          }).length || 0

          const hourAlerts = timelineRes.data.entries?.filter((e: any) => {
            const eventTime = new Date(e.timestamp)
            return e.type === 'alert' && eventTime >= hourStart && eventTime <= hourEnd
          }).length || 0

          events.push(hourEvents)
          alerts.push(hourAlerts)
        }

        setTrendData({ labels, events, alerts })
        setCollectionStats(collectionRes.data)
        setLoading(false)
      })
      .catch(() => {
        setStats({ total: 0, by_severity: {}, by_status: {} })
        setTrendData({ labels: [], events: [], alerts: [] })
        setCollectionStats({ total_events: 0, total_size: 'N/A', sources: {}, last_import: 'N/A' })
        setLoading(false)
      })
  }, [])

  if (loading) {
    return (
      <div className="dashboard">
        <div className="dashboard-loading">
          <div className="loading-spinner"></div>
          <p>{t('common.loading')}</p>
        </div>
      </div>
    )
  }

  const topAlertTypes = stats?.by_type
    ? Object.entries(stats.by_type)
        .sort((a, b) => (b[1] as number) - (a[1] as number))
        .slice(0, 5)
    : []

  const trendChartData = {
    labels: trendData?.labels || [],
    datasets: [
      {
        label: t('dashboard.events'),
        data: trendData?.events || [],
        borderColor: '#00d9ff',
        backgroundColor: 'rgba(0, 217, 255, 0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 6,
        pointHoverBackgroundColor: '#00d9ff',
      },
      {
        label: t('dashboard.alerts'),
        data: trendData?.alerts || [],
        borderColor: '#ff6b6b',
        backgroundColor: 'rgba(255, 107, 107, 0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 6,
        pointHoverBackgroundColor: '#ff6b6b',
      },
    ],
  }

  const trendChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
        labels: { color: '#aaa', usePointStyle: true, pointStyle: 'circle' },
      },
      tooltip: {
        backgroundColor: '#16213e',
        titleColor: '#00d9ff',
        bodyColor: '#fff',
        borderColor: '#00d9ff',
        borderWidth: 1,
        cornerRadius: 8,
        displayColors: true,
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(255,255,255,0.05)' },
        ticks: { color: '#888', maxTicksLimit: 8 },
      },
      y: {
        grid: { color: 'rgba(255,255,255,0.05)' },
        ticks: { color: '#888' },
        beginAtZero: true,
      },
    },
    interaction: {
      intersect: false,
      mode: 'index' as const,
    },
  }

  const alertTypeChartData = {
    labels: topAlertTypes.map(([type]) => type),
    datasets: [
      {
        data: topAlertTypes.map(([, count]) => count),
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(249, 115, 22, 0.8)',
          'rgba(234, 179, 8, 0.8)',
          'rgba(34, 197, 94, 0.8)',
          'rgba(59, 130, 246, 0.8)',
        ],
        borderColor: [
          '#ef4444',
          '#f97316',
          '#eab308',
          '#22c55e',
          '#3b82f6',
        ],
        borderWidth: 2,
      },
    ],
  }

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: { color: '#aaa', usePointStyle: true, pointStyle: 'circle', padding: 15 },
      },
      tooltip: {
        backgroundColor: '#16213e',
        titleColor: '#00d9ff',
        bodyColor: '#fff',
        borderColor: '#00d9ff',
        borderWidth: 1,
        cornerRadius: 8,
      },
    },
    cutout: '65%',
  }

  const severityChartData = {
    labels: [t('dashboard.critical'), t('dashboard.high'), t('dashboard.medium'), t('dashboard.low')],
    datasets: [
      {
        label: t('dashboard.alerts'),
        data: [
          stats?.by_severity?.critical || 0,
          stats?.by_severity?.high || 0,
          stats?.by_severity?.medium || 0,
          stats?.by_severity?.low || 0,
        ],
        backgroundColor: [
          'rgba(239, 68, 68, 0.8)',
          'rgba(249, 115, 22, 0.8)',
          'rgba(234, 179, 8, 0.8)',
          'rgba(34, 197, 94, 0.8)',
        ],
        borderColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
        borderWidth: 2,
        borderRadius: 6,
      },
    ],
  }

  const barChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: '#16213e',
        titleColor: '#00d9ff',
        bodyColor: '#fff',
        borderColor: '#00d9ff',
        borderWidth: 1,
        cornerRadius: 8,
      },
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: { color: '#888' },
      },
      y: {
        grid: { color: 'rgba(255,255,255,0.05)' },
        ticks: { color: '#888' },
        beginAtZero: true,
      },
    },
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h2>{t('dashboard.title')}</h2>
        <div className="header-time">{new Date().toLocaleString()}</div>
      </div>

      <div className="stats-cards">
        <div className="stat-card glow-critical" onClick={() => navigate('/alerts?severity=critical')}>
          <div className="stat-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats?.by_severity?.critical || 0}</span>
            <span className="stat-label">{t('dashboard.critical')}</span>
          </div>
          <div className="stat-glow"></div>
        </div>

        <div className="stat-card glow-high" onClick={() => navigate('/alerts?severity=high')}>
          <div className="stat-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats?.by_severity?.high || 0}</span>
            <span className="stat-label">{t('dashboard.high')}</span>
          </div>
          <div className="stat-glow"></div>
        </div>

        <div className="stat-card glow-medium" onClick={() => navigate('/alerts?severity=medium')}>
          <div className="stat-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats?.by_severity?.medium || 0}</span>
            <span className="stat-label">{t('dashboard.medium')}</span>
          </div>
          <div className="stat-glow"></div>
        </div>

        <div className="stat-card glow-low" onClick={() => navigate('/alerts?severity=low')}>
          <div className="stat-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
              <polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
          </div>
          <div className="stat-content">
            <span className="stat-value">{stats?.by_severity?.low || 0}</span>
            <span className="stat-label">{t('dashboard.low')}</span>
          </div>
          <div className="stat-glow"></div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="chart-card chart-trend" onClick={() => navigate('/timeline')}>
          <div className="chart-header">
            <h3>{t('dashboard.eventTrend')}</h3>
            <span className="chart-subtitle">{t('dashboard.last24Hours')}</span>
          </div>
          <div className="chart-body">
            <Line data={trendChartData} options={trendChartOptions} />
          </div>
        </div>

        <div className="chart-card chart-alert-type" onClick={() => navigate('/alerts')}>
          <div className="chart-header">
            <h3>{t('dashboard.topAlertTypes')}</h3>
            <span className="chart-subtitle">{t('dashboard.clickToView')}</span>
          </div>
          <div className="chart-body">
            {topAlertTypes.length > 0 ? (
              <Doughnut data={alertTypeChartData} options={doughnutOptions} />
            ) : (
              <div className="chart-empty">{t('dashboard.noData')}</div>
            )}
          </div>
        </div>

        <div className="chart-card chart-severity" onClick={() => navigate('/alerts')}>
          <div className="chart-header">
            <h3>{t('dashboard.bySeverity')}</h3>
          </div>
          <div className="chart-body">
            <Bar data={severityChartData} options={barChartOptions} />
          </div>
        </div>

        <div className="chart-card chart-collection">
          <div className="chart-header">
            <h3>{t('dashboard.collectionStatus')}</h3>
          </div>
          <div className="chart-body collection-stats">
            <div className="collection-item">
              <span className="collection-label">{t('dashboard.totalEvents')}</span>
              <span className="collection-value">{collectionStats?.total_events?.toLocaleString() || 0}</span>
            </div>
            <div className="collection-item">
              <span className="collection-label">{t('dashboard.dataSize')}</span>
              <span className="collection-value">{collectionStats?.total_size || 'N/A'}</span>
            </div>
            <div className="collection-item">
              <span className="collection-label">{t('dashboard.lastImport')}</span>
              <span className="collection-value">{collectionStats?.last_import || 'N/A'}</span>
            </div>
            <div className="collection-sources">
              <span className="collection-label">{t('dashboard.sources')}</span>
              <div className="source-tags">
                {Object.keys(collectionStats?.sources || {}).map(source => (
                  <span key={source} className="source-tag">{source}</span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="recent-section" onClick={() => navigate('/alerts')}>
        <div className="section-header">
          <h3>{t('dashboard.recentAlerts')}</h3>
          <span className="view-more">{t('dashboard.viewAll')} →</span>
        </div>
        <div className="recent-alerts-list">
          {stats && stats.total > 0 ? (
            <div className="alert-preview">
              <div className="alert-count-badge">{stats.total}</div>
              <span>{t('dashboard.totalAlertsDesc')}</span>
            </div>
          ) : (
            <div className="no-alerts">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
              </svg>
              <span>{t('dashboard.noAlerts')}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default Dashboard