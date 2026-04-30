import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useI18n } from '../locales/I18n'
import { analyzeAPI } from '../api'
import analyzerDocs from '../docs/analyzers.md?raw'

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
  'en': {},
  'zh': {
    // Brute Force
    'Possible compromised account due to successful login after multiple failures': '可能因多次登录失败后成功登录而导致账户被盗',
    'High number of failed login attempts': '大量登录失败尝试',
    'Suspicious IP with high failed login count targeting multiple users': '可疑IP大量登录失败尝试并针对多个用户',

    // Login
    'Low login success rate indicates potential attack': '登录成功率低表明可能存在攻击',
    'High number of failed login attempts - possible brute force': '大量登录失败尝试 - 可能存在暴力破解',
    'Multiple RDP connections detected': '检测到多个RDP连接',
    'Multiple logins from different locations in short time': '短时间内多次从不同位置登录',
    'Login outside working hours': '工作时间外登录',
    'Successful login from unusual source or time': '来自异常来源或时间的成功登录',
    'Failed login attempt - possible brute force': '登录失败尝试 - 可能存在暴力破解',

    // Kerberos
    'TGT with suspicious lifetime or encryption detected': '检测到生命周期或加密异常的TGT票据',
    'TGS request for user account - possible Kerberoasting attack': '用户账户的TGS请求 - 可能存在Kerberoasting攻击',
    'TGS request with suspicious service - possible Silver Ticket': '可疑服务的TGS请求 - 可能存在Silver Ticket攻击',
    'Failed Kerberos preauthentication - possible brute force or AS-REP Roasting': 'Kerberos预认证失败 - 可能存在暴力破解或AS-REP Roasting攻击',
    'AS-REP ticket modification detected - possible AS-REP Roasting': '检测到AS-REP票据修改 - 可能存在AS-REP Roasting攻击',
    'Possible Golden Ticket attack detected - TGT with suspicious lifetime': '可能检测到Golden Ticket攻击 - TGT生命周期异常',
    'Possible Silver Ticket attack detected': '可能检测到Silver Ticket攻击',
    'Kerberoasting attack detected - TGS requests for service accounts': '检测到Kerberoasting攻击 - 服务账户的TGS请求',
    'High number of failed Kerberos preauthentication attempts': '大量Kerberos预认证失败尝试',

    // PowerShell
    'PowerShell encoded command detected - common in attacks': '检测到PowerShell编码命令 - 常见于攻击活动',
    'Suspicious PowerShell script detected - possible attacker tool': '检测到可疑PowerShell脚本 - 可能为攻击工具',
    'PowerShell encoded command detected': '检测到PowerShell编码命令',

    // Lateral Movement
    'Suspicious RDP login from external IP': '来自外部IP的可疑RDP登录',
    'PSExec-like process execution detected': '检测到类似PSExec的进程执行',
    'WMI remote execution detected': '检测到WMI远程执行',
    'Logon with explicit credentials - possible lateral movement': '使用显式凭据登录 - 可能存在横向移动',

    // Persistence
    'Multiple user accounts created in short period - possible account creation attack': '短时间内创建多个用户账户 - 可能存在账户创建攻击',
    'Suspicious service installed': '检测到可疑服务安装',
    'New service installed': '检测到新服务安装',
    'Scheduled task created': '检测到计划任务创建',
    'User added to privileged group': '用户被添加到特权组',
    'User removed from privileged group': '用户从特权组移除',

    // Privilege Escalation
    'User assigned multiple sensitive privileges - potential privilege escalation': '用户被分配多个敏感权限 - 可能存在权限提升',
    'User heavily using sensitive privileges': '用户大量使用敏感权限',
    'Suspicious process executed multiple times': '可疑进程多次执行',
    'Multiple cmd.exe processes spawned - possible command execution attack': '多个cmd.exe进程生成 - 可能存在命令执行攻击',

    // Data Exfiltration
    'Login detected during unusual hours': '检测到异常时间登录',
    'Process accessing sensitive file extension': '进程访问敏感文件扩展名',
    'Suspicious keyword detected': '检测到可疑关键字',
    'File copy to removable media detected': '检测到文件复制到可移动媒体',

    // Domain Controller
    'Privileged user account created': '特权用户账户被创建',
    'Privileged user account deleted': '特权用户账户被删除',
    'Privileged account created or deleted': '特权账户被创建或删除',
    'User added to sensitive group': '用户被添加到敏感组',
    'User removed from sensitive group': '用户从敏感组移除',
    'Modification of sensitive attribute': '敏感属性被修改',
    'Directory object access related to replication': '与复制相关的目录对象访问',
    'AD object moved in directory': '目录中的AD对象被移动',
    'Access to sensitive network share': '访问敏感网络共享',
    'Sensitive privilege assigned': '敏感权限被分配',
    'Krbtgt account password changed - verify if authorized': 'Krbtgt账户密码被更改 - 请验证是否为授权操作',
    'Directory service policy was modified': '目录服务策略被修改',
    'Directory object was accessed': '目录对象被访问',
    'Failed logon attempt to privileged account': '特权账户登录失败尝试',
    'Privileged account logged in via network to DC': '特权账户通过网络登录到域控制器',
    'TGT requested for krbtgt account': '为krbtgt账户请求了TGT',
    'Possible DCSync attack detected - replication of sensitive AD data': '可能检测到DCSync攻击 - 敏感AD数据复制',
    'Sensitive group membership changes detected': '检测到敏感组成员的变更',
    'Directory service policy changes detected': '检测到目录服务策略变更',
    'High number of directory replication operations': '大量目录复制操作',

    // MITRE ATT&CK mappings (displayed as tooltip)
    'T1059.001': 'MITRE ATT&CK T1059.001: PowerShell',
    'T1021.001': 'MITRE ATT&CK T1021.001: RDP',
    'T1021.002': 'MITRE ATT&CK T1021.002: PSExec',
    'T1047': 'MITRE ATT&CK T1047: WMI',
    'T1078.004': 'MITRE ATT&CK T1078.004: 有效账户',
    'T1543': 'MITRE ATT&CK T1543: 创建/修改系统进程',
    'T1053': 'MITRE ATT&CK T1053: 计划任务',
    'T1098': 'MITRE ATT&CK T1098: 账户操纵',
    'T1003.006': 'MITRE ATT&CK T1003.006: DCSync',
    'T1484.001': 'MITRE ATT&CK T1484.001: 域策略修改',
  },
}

const getLocalizedFindingDesc = (desc: string, locale: string = 'zh'): string => {
  const lang = locale.startsWith('zh') ? 'zh' : 'en'

  // Direct match
  if (findingDescMap[lang][desc]) {
    return findingDescMap[lang][desc]
  }

  // Handle dynamic descriptions with prefixes
  const prefixes: Record<string, string> = {
    // PowerShell
    'Suspicious PowerShell script detected: ': '检测到可疑PowerShell脚本: ',
    'Suspicious script detected: ': '检测到可疑脚本: ',

    // Persistence
    'Suspicious service installed: ': '检测到可疑服务安装: ',
    'New service installed: ': '检测到新服务安装: ',
    'Scheduled task created: ': '检测到计划任务创建: ',
    'User added to privileged group: ': '用户被添加到特权组: ',
    'User removed from privileged group: ': '用户从特权组移除: ',
    'User added to sensitive group: ': '用户被添加到敏感组: ',
    'User removed from sensitive group: ': '用户从敏感组移除: ',

    // Privilege Escalation
    'User heavily using sensitive privileges: ': '用户大量使用敏感权限: ',
    'Suspicious process executed multiple times: ': '可疑进程多次执行: ',

    // Data Exfiltration
    'Process accessing sensitive file extension: ': '进程访问敏感文件扩展名: ',
    'Suspicious keyword detected: ': '检测到可疑关键字: ',

    // DC
    'Modification of sensitive attribute: ': '敏感属性被修改: ',
    'Sensitive privilege assigned: ': '敏感权限被分配: ',

    // Other
    'Possible DCSync attack: ': '可能存在DCSync攻击: ',
  }

  for (const [prefix, translation] of Object.entries(prefixes)) {
    if (desc.startsWith(prefix)) {
      const dynamicPart = desc.substring(prefix.length)
      return translation + dynamicPart
    }
  }

  // If no translation found, return original
  return desc
}

const analyzerIdMap: Record<string, string> = {
  'brute_force': '1',
  'login': '2',
  'kerberos': '3',
  'powershell': '4',
  'lateral_movement': '5',
  'persistence': '6',
  'privilege_escalation': '7',
  'data_exfiltration': '8',
  'dc': '9',
  'domain_controller': '9',
}

const parseAnalyzerDoc = (markdown: string, analyzerId: string): string => {
  const normalizedId = analyzerId.replace(/-/g, '_')
  const num = analyzerIdMap[normalizedId] || analyzerIdMap[analyzerId]
  if (!num) return ''

  const sectionPattern = new RegExp(`##\\s*${num}\\.\\s*[\\s\\S]*?(?=##\\s*\\d+\\.|##\\s*$)`, 'i')
  const match = markdown.match(sectionPattern)
  if (match) {
    return match[0]
      .replace(/^##\s*\d+\.\s*.*?\n/, '')
      .replace(/^### /gm, '<h4>')
      .replace(/^## /gm, '<h3>')
      .replace(/\n/g, '<br/>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/- \*\*(.*?)\*\*/g, '<li><strong>$1</strong>')
      .replace(/^- /gm, '<li>')
      .replace(/$/gm, '</li>')
  }
  return ''
}

const AnalyzerInfoPanel = ({ analyzerId, analyzerName, analyzerIcon, onClose }: {
  analyzerId: string;
  analyzerName: string;
  analyzerIcon: string;
  onClose: () => void;
}) => {
  const doc = parseAnalyzerDoc(analyzerDocs, analyzerId)

  if (!doc) return null

  return (
    <div className="analyzer-info-panel">
      <div className="info-panel-header">
        <div className="info-panel-title">
          <span className="analyzer-icon">{analyzerIcon}</span>
          <span>{analyzerName}</span>
        </div>
        <button className="info-panel-close" onClick={onClose}>×</button>
      </div>
      <div className="info-panel-content" dangerouslySetInnerHTML={{ __html: doc }} />
    </div>
  )
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
  const [useCustomDate, setUseCustomDate] = useState(false)
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')
  const [limit, setLimit] = useState(10000)
  const [useCustomLimit, setUseCustomLimit] = useState(false)
  const [customLimit, setCustomLimit] = useState(10000)
  const [error, setError] = useState('')
  const [showRuleEditor, setShowRuleEditor] = useState(false)
  const [editingRule, setEditingRule] = useState<AnalyzerRule | null>(null)
  const [ruleLoading, setRuleLoading] = useState(false)
  const [findingsPage, setFindingsPage] = useState(1)
  const [findingsPageSize] = useState(10)
  const [showOriginalLang, setShowOriginalLang] = useState(false)
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null)
  const [showAnalyzerInfo, setShowAnalyzerInfo] = useState(false)

  const analyzers: Analyzer[] = [
    { id: 'brute_force', name: t('analyze.bruteForce'), desc: t('analyze.bruteForceDesc'), icon: analyzerIcons['brute-force'], category: 'authentication', recommended: true },
    { id: 'login', name: t('analyze.login'), desc: t('analyze.loginDesc'), icon: analyzerIcons['login'], category: 'authentication', recommended: false },
    { id: 'kerberos', name: t('analyze.kerberos'), desc: t('analyze.kerberosDesc'), icon: analyzerIcons['kerberos'], category: 'authentication', recommended: false },
    { id: 'powershell', name: t('analyze.powershell'), desc: t('analyze.powershellDesc'), icon: analyzerIcons['powershell'], category: 'execution', recommended: true },
    { id: 'lateral_movement', name: t('analyze.lateralMovement'), desc: t('analyze.lateralMovementDesc'), icon: analyzerIcons['lateral-movement'], category: 'lateral-movement', recommended: false },
    { id: 'data_exfiltration', name: t('analyze.dataExfil'), desc: t('analyze.dataExfilDesc'), icon: analyzerIcons['data-exfil'], category: 'collection', recommended: false },
    { id: 'persistence', name: t('analyze.persistence'), desc: t('analyze.persistenceDesc'), icon: analyzerIcons['persistence'], category: 'persistence', recommended: false },
    { id: 'privilege_escalation', name: t('analyze.privilegeEscalation'), desc: t('analyze.privilegeEscalationDesc'), icon: analyzerIcons['privilege-escalation'], category: 'privilege-escalation', recommended: false },
    { id: 'domain_controller', name: t('analyze.domainController'), desc: t('analyze.domainControllerDesc'), icon: analyzerIcons['dc'], category: 'domain-services', recommended: false },
  ]

  const selectedAnalyzerData = analyzers.find(a => a.id === selectedAnalyzer)

  const handleRun = async () => {
    setLoading(true)
    setError('')
    setFindingsPage(1)
    setExpandedFinding(null)
    try {
      const analyzerType = selectedAnalyzer.replace(/_/g, '-')
      const params: { hours?: number; start_time?: string; end_time?: string; limit?: number } = {}
      if (useCustomDate && startDate && endDate) {
        params.start_time = new Date(startDate).toISOString()
        params.end_time = new Date(endDate).toISOString()
      } else {
        params.hours = hours
      }
      params.limit = useCustomLimit ? customLimit : limit
      const res = await analyzeAPI.run(analyzerType, params)
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
                <button
                  className="btn-info"
                  onClick={() => setShowAnalyzerInfo(!showAnalyzerInfo)}
                  title="查看分析器详情"
                >
                  {showAnalyzerInfo ? '隐藏详情' : '查看详情'}
                </button>
              </div>
            </div>

            <div className="config-item">
              <label>{t('analyze.timeWindow')}</label>
              <div className="time-selector">
                <button
                  className={hours === 1 ? 'active' : ''}
                  onClick={() => { setHours(1); setUseCustomDate(false); }}
                >1h</button>
                <button
                  className={hours === 6 ? 'active' : ''}
                  onClick={() => { setHours(6); setUseCustomDate(false); }}
                >6h</button>
                <button
                  className={hours === 24 ? 'active' : ''}
                  onClick={() => { setHours(24); setUseCustomDate(false); }}
                >24h</button>
                <button
                  className={hours === 72 ? 'active' : ''}
                  onClick={() => { setHours(72); setUseCustomDate(false); }}
                >72h</button>
                <button
                  className={hours === 168 ? 'active' : ''}
                  onClick={() => { setHours(168); setUseCustomDate(false); }}
                >7d</button>
              </div>
            </div>

            <div className="config-item">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={useCustomDate}
                  onChange={(e) => setUseCustomDate(e.target.checked)}
                />
                <span>{t('analyze.useCustomDate') || '使用自定义日期'}</span>
              </label>
              {useCustomDate && (
                <div className="date-range-selector">
                  <div className="date-input-group">
                    <label>{t('analyze.startDate') || '开始日期'}</label>
                    <input
                      type="datetime-local"
                      value={startDate}
                      onChange={(e) => setStartDate(e.target.value)}
                      className="date-input"
                    />
                  </div>
                  <div className="date-input-group">
                    <label>{t('analyze.endDate') || '结束日期'}</label>
                    <input
                      type="datetime-local"
                      value={endDate}
                      onChange={(e) => setEndDate(e.target.value)}
                      className="date-input"
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="config-item">
              <label>{t('analyze.dataLimit') || '分析数据量'}</label>
              <div className="limit-selector">
                <button
                  className={!useCustomLimit && limit === 10000 ? 'active' : ''}
                  onClick={() => { setLimit(10000); setUseCustomLimit(false); }}
                >1万</button>
                <button
                  className={!useCustomLimit && limit === 50000 ? 'active' : ''}
                  onClick={() => { setLimit(50000); setUseCustomLimit(false); }}
                >5万</button>
                <button
                  className={!useCustomLimit && limit === 100000 ? 'active' : ''}
                  onClick={() => { setLimit(100000); setUseCustomLimit(false); }}
                >10万</button>
                <button
                  className={useCustomLimit ? 'active' : ''}
                  onClick={() => setUseCustomLimit(true)}
                >自定义</button>
              </div>
              {useCustomLimit && (
                <div className="custom-limit-input">
                  <input
                    type="number"
                    value={customLimit}
                    onChange={(e) => setCustomLimit(Math.max(1, parseInt(e.target.value) || 1))}
                    min="1"
                    max="1000000"
                    className="limit-input"
                  />
                  <span className="limit-unit">条</span>
                </div>
              )}
              <span className="config-hint">
                {t('analyze.dataLimitHint') || '注意：数据量越大分析时间越长'}
              </span>
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

      {showAnalyzerInfo && selectedAnalyzerData && (
        <AnalyzerInfoPanel
          analyzerId={selectedAnalyzer}
          analyzerName={selectedAnalyzerData.name}
          analyzerIcon={selectedAnalyzerData.icon}
          onClose={() => setShowAnalyzerInfo(false)}
        />
      )}

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
                <div className="findings-header">
                  <h4>{t('analyze.findingsList')}</h4>
                  <div className="findings-controls">
                    <label className="lang-toggle">
                      <input
                        type="checkbox"
                        checked={showOriginalLang}
                        onChange={(e) => setShowOriginalLang(e.target.checked)}
                      />
                      <span>显示原文</span>
                    </label>
                  </div>
                </div>

                <div className="findings-list">
                  {result.findings
                    .slice((findingsPage - 1) * findingsPageSize, findingsPage * findingsPageSize)
                    .map((f, i) => {
                      const actualIndex = (findingsPage - 1) * findingsPageSize + i
                      return (
                      <div key={i} className={`finding-item ${expandedFinding === actualIndex ? 'expanded' : ''}`}>
                        <div className="finding-header" onClick={() => setExpandedFinding(expandedFinding === actualIndex ? null : actualIndex)}>
                          <span className={`severity-indicator severity-${f.severity}`}></span>
                          <span className="finding-desc">
                            {showOriginalLang ? f.description : getLocalizedFindingDesc(f.description, locale)}
                          </span>
                          <span className="expand-icon">{expandedFinding === actualIndex ? '−' : '+'}</span>
                        </div>
                        <div className="finding-meta">
                          {f.rule_name && <span className="rule-name">{f.rule_name}</span>}
                          <span className="finding-score">Score: {f.score.toFixed(1)}</span>
                          {f.evidence && f.evidence.length > 0 && (
                            <span className="evidence-count">{f.evidence.length} events</span>
                          )}
                        </div>
                        {expandedFinding === actualIndex && f.evidence && f.evidence.length > 0 && (
                          <div className="evidence-list">
                            <div className="evidence-header">
                              {t('analyze.relatedEvents')} (Event ID: {f.evidence[0]?.event_id})
                            </div>
                            <table className="evidence-table">
                              <thead>
                                <tr>
                                  <th>时间</th>
                                  <th>用户</th>
                                  <th>计算机</th>
                                  <th>原始日志</th>
                                </tr>
                              </thead>
                              <tbody>
                                {f.evidence.map((e, j) => (
                                  <tr key={j}>
                                    <td className="evidence-time">{new Date(e.timestamp).toLocaleString()}</td>
                                    <td className="evidence-user">{e.user || '-'}</td>
                                    <td className="evidence-computer">{e.computer || '-'}</td>
                                    <td className="evidence-msg" title={e.message}>{e.message}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    )})}
                </div>

                {result.findings.length > findingsPageSize && (
                  <div className="pagination">
                    <span className="pagination-info">
                      第 {(findingsPage - 1) * findingsPageSize + 1} - {Math.min(findingsPage * findingsPageSize, result.findings.length)} 条，共 {result.findings.length} 条
                    </span>
                    <div className="pagination-controls">
                      <button
                        className="pagination-btn"
                        disabled={findingsPage === 1}
                        onClick={() => setFindingsPage(1)}
                      >首页</button>
                      <button
                        className="pagination-btn"
                        disabled={findingsPage === 1}
                        onClick={() => setFindingsPage(p => p - 1)}
                      >上一页</button>
                      <span className="pagination-current">{findingsPage} / {Math.ceil(result.findings.length / findingsPageSize)}</span>
                      <button
                        className="pagination-btn"
                        disabled={findingsPage >= Math.ceil(result.findings.length / findingsPageSize)}
                        onClick={() => setFindingsPage(p => p + 1)}
                      >下一页</button>
                      <button
                        className="pagination-btn"
                        disabled={findingsPage >= Math.ceil(result.findings.length / findingsPageSize)}
                        onClick={() => setFindingsPage(Math.ceil(result.findings.length / findingsPageSize))}
                      >末页</button>
                    </div>
                  </div>
                )}
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