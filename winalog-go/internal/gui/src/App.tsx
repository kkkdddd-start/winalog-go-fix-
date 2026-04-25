import { Routes, Route, Link } from 'react-router-dom'
import { useEffect } from 'react'
import { I18nProvider, useI18n } from './locales/I18n'
import { settingsAPI, setRequestTimeout } from './api'
import LangSwitcher from './components/LangSwitcher'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import EventDetail from './pages/EventDetail'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Timeline from './pages/Timeline'
import Reports from './pages/Reports'
import Forensics from './pages/Forensics'
import SystemInfo from './pages/SystemInfo'
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
import './App.css'

function Navigation() {
  const { t } = useI18n()
  
  return (
    <nav className="sidebar">
      <h1>{t('app.title')}</h1>
      <ul>
        <li><Link to="/">{t('nav.dashboard')}</Link></li>
        <li><Link to="/events">{t('nav.events')}</Link></li>
        <li><Link to="/alerts">{t('nav.alerts')}</Link></li>
        <li><Link to="/timeline">{t('nav.timeline')}</Link></li>
        <li><Link to="/collect">{t('nav.collect')}</Link></li>
        <li><Link to="/analyze">{t('nav.analyze')}</Link></li>
        <li><Link to="/correlation">{t('nav.correlation')}</Link></li>
        <li><Link to="/multi">{t('nav.multi')}</Link></li>
        <li><Link to="/query">{t('nav.query')}</Link></li>
        <li><Link to="/ueba">{t('nav.ueba')}</Link></li>
        <li><Link to="/suppress">{t('nav.suppress')}</Link></li>
        <li><Link to="/live">{t('nav.live')}</Link></li>
        <li><Link to="/monitor">{t('nav.monitor')}</Link></li>
        <li><Link to="/persistence">{t('nav.persistence')}</Link></li>
        <li><Link to="/reports">{t('nav.reports')}</Link></li>
        <li><Link to="/forensics">{t('nav.forensics')}</Link></li>
        <li><Link to="/system-info">{t('nav.systemInfo')}</Link></li>
        <li><Link to="/rules">{t('nav.rules')}</Link></li>
        <li><Link to="/metrics">{t('nav.metrics')}</Link></li>
        <li><Link to="/logs">{t('nav.logs')}</Link></li>
        <li><Link to="/settings">{t('nav.settings')}</Link></li>
      </ul>
    </nav>
  )
}

function AppContent() {
  useEffect(() => {
    settingsAPI.get().then(res => {
      const timeout = res.data.request_timeout || 600
      setRequestTimeout(timeout)
    }).catch(() => {
      setRequestTimeout(600)
    })
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
          <Route path="/system-info" element={<SystemInfo />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/metrics" element={<Metrics />} />
          <Route path="/logs" element={<Logs />} />
        </Routes>
      </main>
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