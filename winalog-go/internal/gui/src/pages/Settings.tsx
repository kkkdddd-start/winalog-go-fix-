import { useState, useEffect } from 'react'
import { settingsAPI, setRequestTimeout } from '../api'
import { useI18n } from '../locales/I18n'

function Settings() {
  const { t } = useI18n()
  const [activeTab, setActiveTab] = useState('general')
  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  const [settings, setSettings] = useState({
    databasePath: './winalog.db',
    logLevel: 'info',
    maxEvents: 1000000,
    retentionDays: 90,
    enableAlerting: true,
    enableLiveCollection: false,
    enableAutoUpdate: false,
    apiPort: 8080,
    apiHost: '0.0.0.0',
    corsEnabled: true,
    maxImportFileSize: 1024,
    exportDirectory: './exports',
    parserWorkers: 4,
    memoryLimit: 2048,
    requestTimeout: 600,
  })

  useEffect(() => {
    settingsAPI.get().then(res => {
      const data = res.data
      const timeout = data.request_timeout || 600
      setRequestTimeout(timeout)
      setSettings({
        databasePath: data.database_path || './winalog.db',
        logLevel: data.log_level || 'info',
        maxEvents: data.max_events || 1000000,
        retentionDays: data.retention_days || 90,
        enableAlerting: data.enable_alerting ?? true,
        enableLiveCollection: data.enable_live_collection ?? false,
        enableAutoUpdate: data.enable_auto_update ?? false,
        apiPort: data.api_port || 8080,
        apiHost: data.api_host || '0.0.0.0',
        corsEnabled: data.cors_enabled ?? true,
        maxImportFileSize: data.max_import_file_size || 1024,
        exportDirectory: data.export_directory || './exports',
        parserWorkers: data.parser_workers || 4,
        memoryLimit: data.memory_limit || 2048,
        requestTimeout: timeout,
      })
    }).catch(console.error)
  }, [])

  const handleSave = async () => {
    setLoading(true)
    setError(null)
    try {
      await settingsAPI.save({
        database_path: settings.databasePath,
        log_level: settings.logLevel,
        max_events: settings.maxEvents,
        retention_days: settings.retentionDays,
        enable_alerting: settings.enableAlerting,
        enable_live_collection: settings.enableLiveCollection,
        enable_auto_update: settings.enableAutoUpdate,
        api_port: settings.apiPort,
        api_host: settings.apiHost,
        cors_enabled: settings.corsEnabled,
        max_import_file_size: settings.maxImportFileSize,
        export_directory: settings.exportDirectory,
        parser_workers: settings.parserWorkers,
        memory_limit: settings.memoryLimit,
        request_timeout: settings.requestTimeout,
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to save settings')
    } finally {
      setLoading(false)
    }
  }

  const handleReset = async () => {
    setLoading(true)
    setError(null)
    try {
      await settingsAPI.reset()
      window.location.reload()
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to reset settings')
      setLoading(false)
    }
  }

  const handleChange = (key: string, value: any) => {
    setSettings({...settings, [key]: value})
  }

  return (
    <div className="settings-page">
      <div className="page-header">
        <h2>{t('settings.title')}</h2>
        {saved && <span className="save-indicator">✓ {t('settings.saved')}</span>}
      </div>

      <div className="settings-layout">
        <div className="settings-nav">
          <button 
            className={`nav-item ${activeTab === 'general' ? 'active' : ''}`}
            onClick={() => setActiveTab('general')}
          >
            <span className="nav-icon">⚙️</span>
            {t('settings.general')}
          </button>
          <button 
            className={`nav-item ${activeTab === 'database' ? 'active' : ''}`}
            onClick={() => setActiveTab('database')}
          >
            <span className="nav-icon">💾</span>
            {t('settings.database')}
          </button>
          <button 
            className={`nav-item ${activeTab === 'api' ? 'active' : ''}`}
            onClick={() => setActiveTab('api')}
          >
            <span className="nav-icon">🔌</span>
            {t('settings.apiServer')}
          </button>
          <button 
            className={`nav-item ${activeTab === 'collection' ? 'active' : ''}`}
            onClick={() => setActiveTab('collection')}
          >
            <span className="nav-icon">📡</span>
            {t('settings.collection')}
          </button>
          <button 
            className={`nav-item ${activeTab === 'advanced' ? 'active' : ''}`}
            onClick={() => setActiveTab('advanced')}
          >
            <span className="nav-icon">🔧</span>
            {t('settings.advanced')}
          </button>
        </div>

        <div className="settings-content">
          {activeTab === 'general' && (
            <div className="settings-section">
              <div className="section-header">
                <h3>{t('settings.generalSettings')}</h3>
                <p>{t('settings.configureBasic')}</p>
              </div>
              
              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.logLevel')}</label>
                  <p>{t('settings.logLevelDesc')}</p>
                </div>
                <select 
                  value={settings.logLevel}
                  onChange={e => handleChange('logLevel', e.target.value)}
                >
                  <option value="debug">{t('settings.debug')}</option>
                  <option value="info">{t('settings.info')}</option>
                  <option value="warn">{t('settings.warn')}</option>
                  <option value="error">{t('settings.error')}</option>
                </select>
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.exportDirectory')}</label>
                  <p>{t('settings.exportDirectoryDesc')}</p>
                </div>
                <input
                  type="text"
                  value={settings.exportDirectory}
                  onChange={e => handleChange('exportDirectory', e.target.value)}
                  className="text-input"
                />
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.autoUpdateRules')}</label>
                  <p>{t('settings.autoUpdateRulesDesc')}</p>
                </div>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={settings.enableAutoUpdate}
                    onChange={e => handleChange('enableAutoUpdate', e.target.checked)}
                  />
                  <span className="toggle-slider"></span>
                </label>
              </div>
            </div>
          )}

          {activeTab === 'database' && (
            <div className="settings-section">
              <div className="section-header">
                <h3>{t('settings.databaseSettings')}</h3>
                <p>{t('settings.configureDatabase')}</p>
              </div>
              
              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.databasePath')}</label>
                  <p>{t('settings.databasePathDesc')}</p>
                </div>
                <input
                  type="text"
                  value={settings.databasePath}
                  onChange={e => handleChange('databasePath', e.target.value)}
                  className="text-input"
                />
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.eventRetention')}</label>
                  <p>{t('settings.eventRetentionDesc')}</p>
                </div>
                <input
                  type="number"
                  value={settings.retentionDays}
                  onChange={e => handleChange('retentionDays', Number(e.target.value))}
                  className="number-input"
                  min="1"
                  max="365"
                />
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.maxEvents')}</label>
                  <p>{t('settings.maxEventsDesc')}</p>
                </div>
                <input
                  type="number"
                  value={settings.maxEvents}
                  onChange={e => handleChange('maxEvents', Number(e.target.value))}
                  className="number-input"
                  min="1000"
                  step="1000"
                />
              </div>
            </div>
          )}

          {activeTab === 'api' && (
            <div className="settings-section">
              <div className="section-header">
                <h3>{t('settings.apiServerSettings')}</h3>
                <p>{t('settings.configureApiServer')}</p>
              </div>
              
              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.apiHost')}</label>
                  <p>{t('settings.apiHostDesc')}</p>
                </div>
                <input
                  type="text"
                  value={settings.apiHost}
                  onChange={e => handleChange('apiHost', e.target.value)}
                  className="text-input"
                />
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.apiPort')}</label>
                  <p>{t('settings.apiPortDesc')}</p>
                </div>
                <input
                  type="number"
                  value={settings.apiPort}
                  onChange={e => handleChange('apiPort', Number(e.target.value))}
                  className="number-input"
                  min="1"
                  max="65535"
                />
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.enableCors')}</label>
                  <p>{t('settings.enableCorsDesc')}</p>
                </div>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={settings.corsEnabled}
                    onChange={e => handleChange('corsEnabled', e.target.checked)}
                  />
                  <span className="toggle-slider"></span>
                </label>
              </div>
            </div>
          )}

          {activeTab === 'collection' && (
            <div className="settings-section">
              <div className="section-header">
                <h3>{t('settings.collectionSettings')}</h3>
                <p>{t('settings.configureCollection')}</p>
              </div>
              
              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.enableAlerting')}</label>
                  <p>{t('settings.enableAlertingDesc')}</p>
                </div>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={settings.enableAlerting}
                    onChange={e => handleChange('enableAlerting', e.target.checked)}
                  />
                  <span className="toggle-slider"></span>
                </label>
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.enableLiveCollection')}</label>
                  <p>{t('settings.enableLiveCollectionDesc')}</p>
                </div>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={settings.enableLiveCollection}
                    onChange={e => handleChange('enableLiveCollection', e.target.checked)}
                  />
                  <span className="toggle-slider"></span>
                </label>
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.maxImportFileSize')}</label>
                  <p>{t('settings.maxImportFileSizeDesc')}</p>
                </div>
                <input
                  type="number"
                  value={settings.maxImportFileSize}
                  onChange={e => handleChange('maxImportFileSize', Number(e.target.value))}
                  className="number-input"
                  min="1"
                  max="10240"
                />
              </div>
            </div>
          )}

          {activeTab === 'advanced' && (
            <div className="settings-section">
              <div className="section-header">
                <h3>{t('settings.advancedSettings')}</h3>
                <p>{t('settings.expertConfig')}</p>
              </div>
              
              <div className="info-card">
                <h4>⚠️ {t('settings.warning')}</h4>
                <p>{t('settings.warningDesc')}</p>
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.parserWorkers')}</label>
                  <p>{t('settings.parserWorkersDesc')}</p>
                </div>
                <input
                  type="number"
                  value={settings.parserWorkers}
                  onChange={e => handleChange('parserWorkers', Number(e.target.value))}
                  className="number-input"
                  min="1"
                  max="32"
                />
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.memoryLimit')}</label>
                  <p>{t('settings.memoryLimitDesc')}</p>
                </div>
                <input
                  type="number"
                  value={settings.memoryLimit}
                  onChange={e => handleChange('memoryLimit', Number(e.target.value))}
                  className="number-input"
                  min="256"
                  max="16384"
                />
              </div>

              <div className="setting-card">
                <div className="setting-info">
                  <label>{t('settings.requestTimeout') || 'Request Timeout'}</label>
                  <p>{t('settings.requestTimeoutDesc') || 'HTTP request timeout in seconds'}</p>
                </div>
                <input
                  type="number"
                  value={settings.requestTimeout}
                  onChange={e => handleChange('requestTimeout', Number(e.target.value))}
                  className="number-input"
                  min="10"
                  max="600"
                />
              </div>
            </div>
          )}

          <div className="settings-actions">
            {error && <span className="error-text">{error}</span>}
            <button onClick={handleSave} className="btn-primary" disabled={loading}>
              {loading ? t('settings.saving') : t('settings.saveChanges')}
            </button>
            <button onClick={handleReset} className="btn-secondary" disabled={loading}>
              {t('settings.resetDefaults')}
            </button>
          </div>
        </div>
      </div>

      <style>{`
        .settings-page {
          padding: 20px;
          height: 100%;
          display: flex;
          flex-direction: column;
        }
        
        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }
        
        .settings-page h2 {
          font-size: 1.8rem;
          color: #00d9ff;
          margin: 0;
        }
        
        .save-indicator {
          color: #22c55e;
          font-size: 14px;
          animation: fadeIn 0.3s;
        }
        
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        
        .settings-layout {
          display: flex;
          gap: 20px;
          flex: 1;
        }
        
        .settings-nav {
          width: 220px;
          display: flex;
          flex-direction: column;
          gap: 4px;
          background: rgba(255, 255, 255, 0.02);
          padding: 12px;
          border-radius: 12px;
          border: 1px solid #333;
        }
        
        .nav-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          background: transparent;
          border: none;
          border-radius: 8px;
          color: #888;
          font-size: 14px;
          text-align: left;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .nav-item:hover {
          background: rgba(255, 255, 255, 0.05);
          color: #fff;
        }
        
        .nav-item.active {
          background: rgba(0, 217, 255, 0.1);
          color: #00d9ff;
        }
        
        .nav-icon {
          font-size: 18px;
        }
        
        .settings-content {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 16px;
          overflow-y: auto;
        }
        
        .settings-section {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        
        .section-header {
          margin-bottom: 8px;
        }
        
        .section-header h3 {
          color: #fff;
          font-size: 1.1rem;
          margin: 0 0 4px 0;
        }
        
        .section-header p {
          color: #888;
          font-size: 13px;
          margin: 0;
        }
        
        .setting-card {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 16px 20px;
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 10px;
          border: 1px solid #333;
        }
        
        .setting-info {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }
        
        .setting-info label {
          color: #fff;
          font-weight: 500;
        }
        
        .setting-info p {
          color: #888;
          font-size: 12px;
          margin: 0;
        }
        
        .text-input {
          width: 250px;
          padding: 10px 14px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          font-size: 14px;
        }
        
        .text-input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .number-input {
          width: 120px;
          padding: 10px 14px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          font-size: 14px;
          text-align: center;
        }
        
        .number-input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        select {
          padding: 10px 14px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 6px;
          color: #fff;
          font-size: 14px;
          cursor: pointer;
          min-width: 120px;
        }
        
        .toggle {
          position: relative;
          width: 48px;
          height: 26px;
        }
        
        .toggle input {
          opacity: 0;
          width: 0;
          height: 0;
        }
        
        .toggle-slider {
          position: absolute;
          cursor: pointer;
          top: 3px;
          left: 0;
          right: 0;
          bottom: 3px;
          background: #333;
          border-radius: 26px;
          transition: 0.3s;
        }
        
        .toggle-slider:before {
          content: "";
          position: absolute;
          width: 20px;
          height: 20px;
          left: 3px;
          bottom: 3px;
          background: #fff;
          border-radius: 50%;
          transition: 0.3s;
        }
        
        .toggle input:checked + .toggle-slider {
          background: #00d9ff;
        }
        
        .toggle input:checked + .toggle-slider:before {
          transform: translateX(22px);
        }
        
        .info-card {
          padding: 16px 20px;
          background: rgba(245, 158, 11, 0.1);
          border: 1px solid rgba(245, 158, 11, 0.3);
          border-radius: 10px;
        }
        
        .info-card h4 {
          color: #f59e0b;
          margin: 0 0 8px 0;
          font-size: 14px;
        }
        
        .info-card p {
          color: #888;
          font-size: 13px;
          margin: 0;
          line-height: 1.5;
        }
        
        .settings-actions {
          display: flex;
          gap: 12px;
          padding: 16px 0;
          margin-top: auto;
          border-top: 1px solid #333;
          align-items: center;
        }
        
        .error-text {
          color: #ef4444;
          font-size: 13px;
          margin-right: auto;
        }
        
        .btn-primary {
          padding: 12px 28px;
          background: #00d9ff;
          border: none;
          border-radius: 8px;
          color: #000;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .btn-primary:hover {
          background: #00c4e6;
          transform: translateY(-1px);
        }
        
        .btn-secondary {
          padding: 12px 28px;
          background: transparent;
          border: 1px solid #333;
          border-radius: 8px;
          color: #888;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .btn-secondary:hover {
          border-color: #fff;
          color: #fff;
        }
      `}</style>
    </div>
  )
}

export default Settings
