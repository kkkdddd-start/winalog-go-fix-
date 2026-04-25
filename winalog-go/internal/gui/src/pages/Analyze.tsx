import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { analyzeAPI } from '../api'

interface Finding {
  description: string
  severity: string
  score: number
  rule_name?: string
  mitre_attack?: string[]
  evidence?: EvidenceItem[]
}

interface EvidenceItem {
  event_id: number
  timestamp: string
  user: string
  computer: string
  message: string
}

interface AnalyzeResult {
  type: string
  severity: string
  score: number
  summary: string
  findings: Finding[]
}

interface Analyzer {
  id: string
  name: string
  desc: string
  icon: string
  category: string
  recommended: boolean
}

interface AnalyzerRule {
  name: string
  description: string
  technique: string
  category: string
  enabled: boolean
  event_ids: number[]
  thresholds?: Record<string, number>
  patterns: string[]
  whitelist: string[]
}

const analyzerIcons: Record<string, string> = {
  'brute-force': '🔐',
  'login': '🔑',
  'kerberos': '🎭',
  'powershell': '⚡',
  'lateral-movement': '🚀',
  'data-exfil': '📤',
  'persistence': '🎯',
  'privilege-escalation': '⬆️',
  'malware': '🦠',
  'anomaly': '🔍',
  'dc': '🏢',
}

const findingDescMap: Record<string, Record<string, string>> = {
  'en': {
    'Possible compromised account due to successful login after multiple failures': '可能因多次登录失败后成功登录而导致账户被盗',
    'High number of failed login attempts': '大量登录失败尝试',
    'Suspicious IP with high failed login count targeting multiple users': '可疑IP大量登录失败尝试并针对多个用户',
  },
  'zh': {
    'Possible compromised account due to successful login after multiple failures': '可能因多次登录失败后成功登录而导致账户被盗',
    'High number of failed login attempts': '大量登录失败尝试',
    'Suspicious IP with high failed login count targeting multiple users': '可疑IP大量登录失败尝试并针对多个用户',
  },
}

const getLocalizedFindingDesc = (desc: string, locale: string = 'zh'): string => {
  const lang = locale.startsWith('zh') ? 'zh' : 'en'
  return findingDescMap[lang][desc] || desc
}

const analyzerCategories = [
  { id: 'authentication', name: 'Authentication' },
  { id: 'execution', name: 'Execution' },
  { id: 'lateral-movement', name: 'Lateral Movement' },
  { id: 'persistence', name: 'Persistence' },
  { id: 'collection', name: 'Collection' },
  { id: 'domain-services', name: 'Domain Services' },
]

function Analyze() {
  const { t, locale } = useI18n()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<AnalyzeResult | null>(null)
  const [selectedAnalyzer, setSelectedAnalyzer] = useState('brute-force')
  const [hours, setHours] = useState(24)
  const [error, setError] = useState('')
  const [showRuleEditor, setShowRuleEditor] = useState(false)
  const [editingRule, setEditingRule] = useState<AnalyzerRule | null>(null)
  const [ruleLoading, setRuleLoading] = useState(false)

  const analyzers: Analyzer[] = [
    { id: 'brute_force', name: t('analyze.bruteForce'), desc: t('analyze.bruteForceDesc'), icon: analyzerIcons['brute-force'], category: 'authentication', recommended: true },
    { id: 'login', name: t('analyze.login'), desc: t('analyze.loginDesc'), icon: analyzerIcons['login'], category: 'authentication', recommended: false },
    { id: 'kerberos', name: t('analyze.kerberos'), desc: t('analyze.kerberosDesc'), icon: analyzerIcons['kerberos'], category: 'authentication', recommended: false },
    { id: 'powershell', name: t('analyze.powershell'), desc: t('analyze.powershellDesc'), icon: analyzerIcons['powershell'], category: 'execution', recommended: true },
    { id: 'lateral_movement', name: t('analyze.lateralMovement'), desc: t('analyze.lateralMovementDesc'), icon: analyzerIcons['lateral-movement'], category: 'lateral-movement', recommended: false },
    { id: 'data_exfiltration', name: t('analyze.dataExfil'), desc: t('analyze.dataExfilDesc'), icon: analyzerIcons['data-exfil'], category: 'collection', recommended: false },
    { id: 'persistence', name: t('analyze.persistence'), desc: t('analyze.persistenceDesc'), icon: analyzerIcons['persistence'], category: 'persistence', recommended: false },
    { id: 'privilege_escalation', name: t('analyze.privilegeEscalation'), desc: t('analyze.privilegeEscalationDesc'), icon: analyzerIcons['privilege-escalation'], category: 'privilege-escalation', recommended: false },
    { id: 'dc', name: t('analyze.domainController'), desc: t('analyze.domainControllerDesc'), icon: analyzerIcons['dc'], category: 'domain-services', recommended: false },
  ]

  const handleRun = async () => {
    setLoading(true)
    setError('')
    try {
      const analyzerType = selectedAnalyzer.replace(/_/g, '-')
      const res = await analyzeAPI.run(analyzerType, { hours })
      setResult(res.data)
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to run analyzer')
    } finally {
      setLoading(false)
    }
  }

  const handleShowRuleEditor = async (analyzerId: string) => {
    setRuleLoading(true)
    try {
      const res = await analyzeAPI.getRule(analyzerId)
      setEditingRule(res.data.rule)
      setShowRuleEditor(true)
    } catch (err) {
      console.error('Failed to fetch rule:', err)
    } finally {
      setRuleLoading(false)
    }
  }

  const handleSaveRule = async () => {
    if (!editingRule) return
    try {
      await analyzeAPI.updateRule({
        name: editingRule.name,
        enabled: editingRule.enabled,
        event_ids: editingRule.event_ids,
        thresholds: editingRule.thresholds,
        patterns: editingRule.patterns,
        whitelist: editingRule.whitelist,
      })
      setShowRuleEditor(false)
      setEditingRule(null)
    } catch (err) {
      console.error('Failed to save rule:', err)
      alert('Failed to save rule configuration')
    }
  }

  const handlePatternChange = (index: number, value: string) => {
    if (!editingRule) return
    const newPatterns = [...editingRule.patterns]
    newPatterns[index] = value
    setEditingRule({ ...editingRule, patterns: newPatterns })
  }

  const handleAddPattern = () => {
    if (!editingRule) return
    setEditingRule({
      ...editingRule,
      patterns: [...editingRule.patterns, ''],
    })
  }

  const handleRemovePattern = (index: number) => {
    if (!editingRule) return
    const newPatterns = editingRule.patterns.filter((_, i) => i !== index)
    setEditingRule({ ...editingRule, patterns: newPatterns })
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

  const groupedAnalyzers = analyzers.reduce((acc, analyzer) => {
    if (!acc[analyzer.category]) acc[analyzer.category] = []
    acc[analyzer.category].push(analyzer)
    return acc
  }, {} as Record<string, Analyzer[]>)

  return (
    <div className="analyze-page">
      <div className="page-header">
        <h2>{t('analyze.title')}</h2>
        <p className="page-desc">{t('analyze.pageDesc')}</p>
      </div>

      <div className="analyze-grid">
        <div className="analyzer-section">
          <div className="section-header">
            <h3>{t('analyze.selectAnalyzer')}</h3>
          </div>

          {Object.entries(groupedAnalyzers).map(([category, items]) => (
            <div key={category} className="analyzer-category">
              <div className="category-header">
                {analyzerCategories.find(c => c.id === category)?.name || category}
              </div>
              <div className="analyzer-list">
                {items.map(analyzer => (
                  <div
                    key={analyzer.id}
                    className={`analyzer-card ${selectedAnalyzer === analyzer.id ? 'selected' : ''}`}
                    onClick={() => setSelectedAnalyzer(analyzer.id)}
                  >
                    <div className="analyzer-icon">{analyzer.icon}</div>
                    <div className="analyzer-content">
                      <div className="analyzer-header">
                        <span className="analyzer-name">{analyzer.name}</span>
                        {analyzer.recommended && (
                          <span className="recommended-badge">{t('analyze.recommended')}</span>
                        )}
                      </div>
                      <p className="analyzer-desc">{analyzer.desc}</p>
                    </div>
                    <div className="select-indicator">
                      {selectedAnalyzer === analyzer.id && '✓'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="config-section">
          <div className="section-header">
            <h3>{t('analyze.configuration')}</h3>
          </div>

          <div className="config-card">
            <div className="config-item">
              <label>{t('analyze.selectedAnalyzer')}</label>
              <div className="selected-analyzer-display">
                <span className="analyzer-icon">{analyzerIcons[selectedAnalyzer]}</span>
                <span>{analyzers.find(a => a.id === selectedAnalyzer)?.name}</span>
              </div>
            </div>

            <div className="config-item">
              <label>{t('analyze.timeWindow')}</label>
              <div className="time-selector">
                <button
                  className={hours === 1 ? 'active' : ''}
                  onClick={() => setHours(1)}
                >1h</button>
                <button
                  className={hours === 6 ? 'active' : ''}
                  onClick={() => setHours(6)}
                >6h</button>
                <button
                  className={hours === 24 ? 'active' : ''}
                  onClick={() => setHours(24)}
                >24h</button>
                <button
                  className={hours === 72 ? 'active' : ''}
                  onClick={() => setHours(72)}
                >72h</button>
                <button
                  className={hours === 168 ? 'active' : ''}
                  onClick={() => setHours(168)}
                >7d</button>
              </div>
            </div>

            <button
              onClick={handleRun}
              disabled={loading}
              className="btn-primary btn-run"
            >
              {loading ? (
                <>
                  <span className="btn-spinner"></span>
                  {t('analyze.running')}
                </>
              ) : (
                <>
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polygon points="5 3 19 12 5 21 5 3"/>
                  </svg>
                  {t('analyze.runAnalyzer')}
                </>
              )}
            </button>

            <button
              onClick={() => handleShowRuleEditor(selectedAnalyzer)}
              className="btn-secondary btn-edit-rule"
            >
              {t('analyze.editRule') || 'Edit Rule'}
            </button>
          </div>

          {error && (
            <div className="error-panel">
              <span className="error-icon">⚠️</span>
              <span>{error}</span>
            </div>
          )}

          <div className="quick-actions">
            <h4>{t('analyze.quickActions')}</h4>
            <div className="quick-buttons">
              <button 
                className="quick-btn"
                onClick={() => navigate('/timeline')}
              >
                📊 {t('analyze.viewTimeline')}
              </button>
              <button 
                className="quick-btn"
                onClick={() => navigate('/alerts')}
              >
                🔔 {t('analyze.viewAlerts')}
              </button>
              <button 
                className="quick-btn"
                onClick={() => navigate('/persistence')}
              >
                🎯 {t('analyze.detectPersistence')}
              </button>
            </div>
          </div>
        </div>
      </div>

      {result && (
        <div className="results-section">
          <div className="section-header">
            <h3>{t('analyze.results')}</h3>
          </div>

          <div className="results-grid">
            <div className="result-summary-card">
              <div className="result-header">
                <span className="result-icon">{analyzerIcons[result.type]}</span>
                <span className="result-type">{analyzers.find(a => a.id === result.type)?.name}</span>
              </div>
              <div className="result-stats">
                <div className="stat-item">
                  <span className="stat-label">{t('analyze.severity')}</span>
                  <span className={`severity-badge severity-${result.severity}`}>
                    {result.severity.toUpperCase()}
                  </span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">{t('analyze.score')}</span>
                  <span className="score-value">{result.score.toFixed(1)}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">{t('analyze.findings')}</span>
                  <span className="findings-count">{result.findings.length}</span>
                </div>
              </div>
              <p className="result-summary">{result.summary}</p>
            </div>

            {result.findings.length > 0 && (
              <div className="findings-card">
                <h4>{t('analyze.findingsList')}</h4>
                <div className="findings-list">
                  {result.findings.map((f, i) => (
                    <div key={i} className="finding-item">
                      <div className="finding-header">
                        <span className={`severity-indicator severity-${f.severity}`}></span>
                        <span className="finding-desc">{getLocalizedFindingDesc(f.description, locale)}</span>
                      </div>
                      <div className="finding-meta">
                        {f.rule_name && <span className="rule-name">{f.rule_name}</span>}
                        <span className="finding-score">Score: {f.score.toFixed(1)}</span>
                        {f.evidence && f.evidence.length > 0 && (
                          <span className="evidence-count">{f.evidence.length} events</span>
                        )}
                      </div>
                      {f.evidence && f.evidence.length > 0 && (
                        <div className="evidence-list">
                          <div className="evidence-header">{t('analyze.relatedEvents')}</div>
                          {f.evidence.slice(0, 5).map((e, j) => (
                            <div key={j} className="evidence-item">
                              <span className="evidence-time">{new Date(e.timestamp).toLocaleString()}</span>
                              <span className="evidence-user">{e.user || '-'}</span>
                              <span className="evidence-computer">{e.computer || '-'}</span>
                              <span className="evidence-msg" title={e.message}>
                                {e.message?.substring(0, 80)}{e.message && e.message.length > 80 ? '...' : ''}
                              </span>
                            </div>
                          ))}
                          {f.evidence.length > 5 && (
                            <div className="evidence-more">+{f.evidence.length - 5} more events</div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="analyzer-info">
        <div className="section-header">
          <h3>{t('analyze.aboutAnalyzers')}</h3>
        </div>
        <div className="info-grid">
          {analyzers.slice(0, 4).map(analyzer => (
            <div key={analyzer.id} className="info-card">
              <div className="info-icon">{analyzer.icon}</div>
              <div className="info-content">
                <h4>{analyzer.name}</h4>
                <p>{analyzer.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {showRuleEditor && editingRule && (
        <div className="modal-overlay" onClick={() => setShowRuleEditor(false)}>
          <div className="modal-content rule-editor-modal" onClick={e => e.stopPropagation()}>
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
                <span className={editingRule.enabled ? 'enabled' : 'disabled'}>
                  {editingRule.enabled ? t('persistence.enabled') || 'Enabled' : t('persistence.disabled') || 'Disabled'}
                </span>
              </label>
            </div>
            <div className="modal-body">
              {ruleLoading ? (
                <div className="loading">{t('common.loading')}</div>
              ) : (
                <>
                  <div className="rule-section">
                    <h4>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                      </svg>
                      Event IDs
                    </h4>
                    <p className="section-desc">
                      {editingRule.event_ids?.join(', ') || 'No event IDs configured'}
                    </p>
                  </div>

                  {editingRule.thresholds && Object.keys(editingRule.thresholds).length > 0 && (
                    <div className="rule-section">
                      <h4>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M12 20V10M18 20V4M6 20v-4"/>
                        </svg>
                        {t('analyze.thresholds') || 'Thresholds'}
                      </h4>
                      <div className="thresholds-list">
                        {Object.entries(editingRule.thresholds).map(([key, value]) => (
                          <div key={key} className="threshold-item">
                            <span className="threshold-key">{key.replace(/_/g, ' ')}</span>
                            <input
                              type="number"
                              value={value}
                              onChange={(e) => setEditingRule({
                                ...editingRule,
                                thresholds: { ...editingRule.thresholds!, [key]: parseInt(e.target.value) || 0 }
                              })}
                            />
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="rule-section">
                    <h4>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8"/>
                        <path d="M21 21l-4.35-4.35"/>
                      </svg>
                      {t('analyze.patterns') || 'Detection Patterns'}
                    </h4>
                    <p className="section-desc">
                      {t('analyze.patternsDesc') || 'Keywords or patterns that trigger detection'}
                    </p>
                    <div className="patterns-list">
                      {editingRule.patterns.map((pattern, idx) => (
                        <div key={idx} className="pattern-item">
                          <input
                            type="text"
                            value={pattern}
                            onChange={(e) => handlePatternChange(idx, e.target.value)}
                            placeholder="Enter pattern..."
                          />
                          <button
                            className="remove-btn"
                            onClick={() => handleRemovePattern(idx)}
                          >
                            ×
                          </button>
                        </div>
                      ))}
                      <button className="add-btn" onClick={handleAddPattern}>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M12 5v14M5 12h14"/>
                        </svg>
                        {t('analyze.addPattern') || 'Add Pattern'}
                      </button>
                    </div>
                  </div>

                  <div className="rule-section">
                    <h4>
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M9 12l2 2 4-4"/>
                        <path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"/>
                      </svg>
                      {t('analyze.whitelist') || 'Whitelist'}
                    </h4>
                    <p className="section-desc">
                      {t('analyze.whitelistDesc') || 'Entries that will not trigger detection'}
                    </p>
                    <div className="whitelist-list">
                      {editingRule.whitelist.map((entry, idx) => (
                        <div key={idx} className="whitelist-item">
                          <input
                            type="text"
                            value={entry}
                            onChange={(e) => handleWhitelistChange(idx, e.target.value)}
                            placeholder="Enter whitelist entry..."
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
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M12 5v14M5 12h14"/>
                        </svg>
                        {t('analyze.addWhitelist') || 'Add Whitelist Entry'}
                      </button>
                    </div>
                  </div>
                </>
              )}
              <div className="modal-actions">
                <button onClick={() => setShowRuleEditor(false)} className="btn btn-secondary">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                  {t('common.cancel') || 'Cancel'}
                </button>
                <button onClick={handleSaveRule} className="btn btn-primary">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/>
                    <polyline points="17,21 17,13 7,13 7,21"/>
                    <polyline points="7,3 7,8 15,8"/>
                  </svg>
                  {t('common.save') || 'Save'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Analyze