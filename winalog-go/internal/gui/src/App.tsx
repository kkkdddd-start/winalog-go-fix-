import { Routes, Route, Link } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { I18nProvider, useI18n } from './locales/I18n'
import { settingsAPI, setRequestTimeout } from './api'
import LangSwitcher from './components/LangSwitcher'
import GlobalSearch from './components/GlobalSearch'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import EventDetail from './pages/EventDetail'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Timeline from './pages/Timeline'
import Reports from './pages/Reports'
import Forensics from './pages/Forensics'
import AssetInventory from './pages/AssetInventory'
import Rules from './pages/Rules'
import Settings from './pages/Settings'
import Metrics from './pages/Metrics'
import Persistence from './pages/Persistence'
import Analyze from './pages/Analyze'
import Correlation from './pages/Correlation'
import Multi from './pages/Multi'
import Query from './pages/Query'
import UEBA from './pages/UEBA'
import Suppress from './pages/Suppress'
import Live from './pages/Live'
import Monitor from './pages/Monitor'
import Collect from './pages/Collect'
import Logs from './pages/Logs'
import KnowledgeBase from './pages/KnowledgeBase'
import MachineAssets from './pages/MachineAssets'
import './App.css'

interface NavGroupProps {
  name: string
  open: boolean
  onToggle: () => void
  children: React.ReactNode
}

function NavGroup({ name, open, onToggle, children }: NavGroupProps) {
  return (
    <div className={`nav-group ${open ? 'open' : ''}`}>
      <div className="nav-group-header" onClick={onToggle}>
        <span className="nav-group-arrow">▶</span>
        <span>{name}</span>
      </div>
      <div className="nav-group-content">
        {children}
      </div>
    </div>
  )
}

function Navigation() {
  const { t } = useI18n()
  const [openGroups, setOpenGroups] = useState<Set<string>>(() => new Set(['eventMonitor']))

  const toggleGroup = (key: string) => {
    setOpenGroups(prev => {
      const next = new Set(prev)
      if (next.has(key)) {
        next.delete(key)
      } else {
        next.add(key)
      }
      return next
    })
  }

  return (
    <nav className="sidebar">
      <h1>{t('app.title')}</h1>

      <div className="nav-link-standalone">
        <Link to="/">{t('nav.dashboard')}</Link>
      </div>

      <NavGroup
        name={t('nav.groups.eventMonitor')}
        open={openGroups.has('eventMonitor')}
        onToggle={() => toggleGroup('eventMonitor')}
      >
        <Link to="/events">{t('nav.events')}</Link>
        <Link to="/timeline">{t('nav.timeline')}</Link>
        <Link to="/live">{t('nav.live')}</Link>
        <Link to="/monitor">{t('nav.monitor')}</Link>
      </NavGroup>

      <NavGroup
        name={t('nav.groups.alertRules')}
        open={openGroups.has('alertRules')}
        onToggle={() => toggleGroup('alertRules')}
      >
        <Link to="/alerts">{t('nav.alerts')}</Link>
        <Link to="/suppress">{t('nav.suppress')}</Link>
        <Link to="/rules">{t('nav.rules')}</Link>
      </NavGroup>

      <NavGroup
        name={t('nav.groups.securityAnalysis')}
        open={openGroups.has('securityAnalysis')}
        onToggle={() => toggleGroup('securityAnalysis')}
      >
        <Link to="/analyze">{t('nav.analyze')}</Link>
        <Link to="/persistence">{t('nav.persistence')}</Link>
        <Link to="/correlation">{t('nav.correlation')}</Link>
        <Link to="/multi">{t('nav.multi')}</Link>
        <Link to="/ueba">{t('nav.ueba')}</Link>
      </NavGroup>

      <NavGroup
        name={t('nav.groups.dataCollection')}
        open={openGroups.has('dataCollection')}
        onToggle={() => toggleGroup('dataCollection')}
      >
        <Link to="/collect">{t('nav.collect')}</Link>
        <Link to="/assets">机器资产</Link>
        <Link to="/asset-inventory">{t('nav.assetInventory')}</Link>
        <Link to="/forensics">{t('nav.forensics')}</Link>
      </NavGroup>

      <NavGroup
        name={t('nav.groups.systemInfo')}
        open={openGroups.has('systemInfo')}
        onToggle={() => toggleGroup('systemInfo')}
      >
        <Link to="/query">{t('nav.query')}</Link>
        <Link to="/metrics">{t('nav.metrics')}</Link>
        <Link to="/logs">{t('nav.logs')}</Link>
      </NavGroup>

      <div className="nav-link-standalone">
        <Link to="/reports">{t('nav.reports')}</Link>
      </div>

      <div className="nav-divider" />

      <div className="nav-link-standalone">
        <Link to="/docs" className="nav-docs-link">{t('nav.kb') || '知识库'}</Link>
      </div>

      <div className="nav-link-standalone">
        <Link to="/settings">{t('nav.settings')}</Link>
      </div>
    </nav>
  )
}

function AppContent() {
  const [searchOpen, setSearchOpen] = useState(false)

  useEffect(() => {
    settingsAPI.get().then(res => {
      const timeout = res.data.request_timeout || 600
      setRequestTimeout(timeout)
    }).catch(() => {
      setRequestTimeout(600)
    })

    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setSearchOpen(prev => !prev)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [])

  return (
    <>
      <LangSwitcher />
      <Navigation />
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/events" element={<Events />} />
          <Route path="/events/:id" element={<EventDetail />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:id" element={<AlertDetail />} />
          <Route path="/timeline" element={<Timeline />} />
          <Route path="/collect" element={<Collect />} />
          <Route path="/analyze" element={<Analyze />} />
          <Route path="/correlation" element={<Correlation />} />
          <Route path="/multi" element={<Multi />} />
          <Route path="/query" element={<Query />} />
          <Route path="/ueba" element={<UEBA />} />
          <Route path="/suppress" element={<Suppress />} />
          <Route path="/live" element={<Live />} />
          <Route path="/monitor" element={<Monitor />} />
          <Route path="/persistence" element={<Persistence />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/forensics" element={<Forensics />} />
          <Route path="/asset-inventory" element={<AssetInventory />} />
          <Route path="/assets" element={<MachineAssets />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/metrics" element={<Metrics />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/docs" element={<KnowledgeBase />} />
        </Routes>
      </main>
      <GlobalSearch isOpen={searchOpen} onClose={() => setSearchOpen(false)} />
    </>
  )
}

function App() {
  return (
    <I18nProvider>
      <div className="app">
        <AppContent />
      </div>
    </I18nProvider>
  )
}

export default App