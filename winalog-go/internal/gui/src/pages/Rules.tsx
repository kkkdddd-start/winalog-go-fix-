import { useEffect, useState, useRef } from 'react'
import { rulesAPI, RuleInfo } from '../api'
import api from '../api'

interface TemplateInfo {
  name: string
  description: string
  parameters: TemplateParamInfo[]
  is_template: boolean
}

interface TemplateParamInfo {
  name: string
  description: string
  default?: string
  required: boolean
  type: string
  options?: string[]
}

function Rules() {
  const [rules, setRules] = useState<RuleInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [totalCount, setTotalCount] = useState(0)
  const [enabledCount, setEnabledCount] = useState(0)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedRule, setSelectedRule] = useState<RuleInfo | null>(null)
  const [showValidateModal, setShowValidateModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [showTemplateModal, setShowTemplateModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [editingRule, setEditingRule] = useState<RuleInfo | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [addRuleStep, setAddRuleStep] = useState<'choice' | 'custom'>('choice')
  const [newRule, setNewRule] = useState({
    name: '',
    description: '',
    severity: 'medium',
    score: 50,
    mitre_attack: [] as string[],
    event_ids: [] as number[],
    message: '',
  })
  const [templates, setTemplates] = useState<TemplateInfo[]>([])
  const [selectedTemplate, setSelectedTemplate] = useState<TemplateInfo | null>(null)
  const [templateParams, setTemplateParams] = useState<Record<string, string>>({})
  const [validateResult, setValidateResult] = useState<{valid: boolean, errors: string[], warnings: string[]} | null>(null)
  const [validating, setValidating] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState<{imported: number, failed: number, errors: string[]} | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const fetchRules = () => {
    rulesAPI.list()
      .then(res => {
        setRules(res.data.rules || [])
        setTotalCount(res.data.total_count || 0)
        setEnabledCount(res.data.enabled_count || 0)
        setLoading(false)
      })
      .catch(err => {
        setError(err.message || 'Failed to load rules')
        setLoading(false)
      })
  }

  useEffect(() => {
    fetchRules()
  }, [])

  const fetchTemplates = () => {
    rulesAPI.listTemplates()
      .then(res => {
        setTemplates(res.data.templates || [])
      })
      .catch(err => {
        console.error('Failed to load templates:', err)
      })
  }

  const handleOpenTemplateModal = () => {
    fetchTemplates()
    setShowTemplateModal(true)
  }

  const handleSelectTemplate = (template: TemplateInfo) => {
    setSelectedTemplate(template)
    const params: Record<string, string> = {}
    template.parameters.forEach(p => {
      params[p.name] = p.default || ''
    })
    setTemplateParams(params)
  }

  const handleInstantiateTemplate = () => {
    if (!selectedTemplate) return
    rulesAPI.instantiateTemplate(selectedTemplate.name, templateParams)
      .then(() => {
        setShowTemplateModal(false)
        setSelectedTemplate(null)
        setTemplateParams({})
        fetchRules()
      })
      .catch(err => {
        console.error('Failed to create rule from template:', err)
        alert('Failed to create rule from template')
      })
  }

  const handleToggle = (name: string, currentEnabled: boolean) => {
    rulesAPI.toggle(name, !currentEnabled)
      .then(() => {
        setRules(rules.map(r => 
          r.name === name ? { ...r, enabled: !currentEnabled } : r
        ))
        setEnabledCount(prev => currentEnabled ? prev - 1 : prev + 1)
      })
      .catch(err => {
        console.error('Failed to toggle rule:', err)
      })
  }

  const handleEditRule = (rule: RuleInfo) => {
    if (!rule.is_custom) {
      const confirmed = confirm('This is a built-in rule. Changes will be temporary and not persisted after restart. Continue?')
      if (!confirmed) return
    }
    setEditingRule({ ...rule })
    setShowEditModal(true)
  }

  const handleDeleteRule = (rule: RuleInfo) => {
    if (!rule.is_custom) {
      alert('Cannot delete built-in rules')
      return
    }
    const confirmed = confirm(`Are you sure you want to delete rule "${rule.name}"?`)
    if (!confirmed) return
    api.delete(`/rules/${rule.name}`)
      .then(() => {
        fetchRules()
      })
      .catch((err: any) => {
        console.error('Failed to delete rule:', err)
        alert('Failed to delete rule')
      })
  }

  const handleSaveEdit = () => {
    if (!editingRule) return
    rulesAPI.update(editingRule.name, editingRule)
      .then(() => {
        setShowEditModal(false)
        setEditingRule(null)
        fetchRules()
      })
      .catch(err => {
        console.error('Failed to update rule:', err)
        alert('Failed to update rule')
      })
  }

  const handleAddRule = () => {
    setShowAddModal(true)
    setAddRuleStep('choice')
    setNewRule({
      name: '',
      description: '',
      severity: 'medium',
      score: 50,
      mitre_attack: [],
      event_ids: [],
      message: '',
    })
  }

  const handleOpenTemplateModalFromAdd = () => {
    setShowAddModal(false)
    handleOpenTemplateModal()
  }

  const handleOpenCustomRuleFromAdd = () => {
    setAddRuleStep('custom')
  }

  const handleCreateCustomRule = () => {
    if (!newRule.name.trim()) {
      alert('Rule name is required')
      return
    }
    rulesAPI.save({
      name: newRule.name,
      description: newRule.description,
      severity: newRule.severity,
      enabled: true,
      score: newRule.score,
      mitre_attack: newRule.mitre_attack,
      event_ids: newRule.event_ids,
      message: newRule.message,
    })
      .then(() => {
        setShowAddModal(false)
        fetchRules()
      })
      .catch(err => {
        console.error('Failed to add rule:', err)
        alert('Failed to create rule')
      })
  }

  const handleValidate = () => {
    setShowValidateModal(true)
    setValidateResult(null)
  }

  const handleValidateRule = (rule: Partial<RuleInfo> & { name: string }) => {
    setValidating(true)
    rulesAPI.validate(rule)
      .then(res => {
        setValidateResult(res.data)
      })
      .catch(err => {
        setValidateResult({
          valid: false,
          errors: [err.message || 'Validation failed'],
          warnings: []
        })
      })
      .finally(() => {
        setValidating(false)
      })
  }

  const handleExport = (format: 'json' | 'yaml') => {
    rulesAPI.export(format)
      .then(res => {
        const blob = new Blob([res.data], { type: format === 'yaml' ? 'text/yaml' : 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `rules_export.${format}`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      })
      .catch(err => {
        console.error('Failed to export rules:', err)
        alert('Failed to export rules')
      })
  }

  const handleImportClick = () => {
    setShowImportModal(true)
    setImportResult(null)
  }

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const content = e.target?.result as string
        let parsedRules: RuleInfo[] = []

        if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
          const lines = content.split('\n')
          let currentRule: Partial<RuleInfo> = {}
          for (const line of lines) {
            if (line.startsWith('- name:')) {
              if (currentRule.name) {
                parsedRules.push(currentRule as RuleInfo)
              }
              currentRule = { name: line.replace('- name:', '').trim(), mitre_attack: [] }
            } else if (line.startsWith('  description:')) {
              currentRule.description = line.replace('  description:', '').trim()
            } else if (line.startsWith('  severity:')) {
              currentRule.severity = line.replace('  severity:', '').trim()
            } else if (line.startsWith('  enabled:')) {
              currentRule.enabled = line.replace('  enabled:', '').trim() === 'true'
            } else if (line.startsWith('  score:')) {
              currentRule.score = parseFloat(line.replace('  score:', '').trim()) || 50
            } else if (line.startsWith('    - ')) {
              if (!currentRule.mitre_attack) currentRule.mitre_attack = []
              currentRule.mitre_attack.push(line.replace('    - ', '').trim())
            }
          }
          if (currentRule.name) {
            parsedRules.push(currentRule as RuleInfo)
          }
        } else {
          const data = JSON.parse(content)
          parsedRules = Array.isArray(data) ? data : data.rules || []
        }

        if (parsedRules.length === 0) {
          setImportResult({ imported: 0, failed: 0, errors: ['No valid rules found in file'] })
          return
        }

        setImporting(true)
        rulesAPI.import(parsedRules)
          .then(res => {
            setImportResult(res.data)
            if (res.data.imported > 0) {
              fetchRules()
            }
          })
          .catch(err => {
            setImportResult({
              imported: 0,
              failed: parsedRules.length,
              errors: [err.message || 'Import failed']
            })
          })
          .finally(() => {
            setImporting(false)
          })
      } catch (err: any) {
        setImportResult({
          imported: 0,
          failed: 0,
          errors: ['Failed to parse file: ' + (err.message || 'Invalid format')]
        })
      }
    }
    reader.readAsText(file)
  }

  const handleViewDetails = (rule: RuleInfo) => {
    setSelectedRule(rule)
  }

  const getSeverityClass = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'severity-critical'
      case 'high': return 'severity-high'
      case 'medium': return 'severity-medium'
      case 'low': return 'severity-low'
      default: return 'severity-info'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return '🔴'
      case 'high': return '🟠'
      case 'medium': return '🟡'
      case 'low': return '🟢'
      default: return '⚪'
    }
  }

  const filteredRules = rules.filter(rule => {
    if (filterSeverity !== 'all' && rule.severity?.toLowerCase() !== filterSeverity) return false
    if (filterStatus === 'enabled' && !rule.enabled) return false
    if (filterStatus === 'disabled' && rule.enabled) return false
    if (searchQuery && !rule.name.toLowerCase().includes(searchQuery.toLowerCase())) return false
    return true
  })

  if (loading) return (
    <div className="rules-page">
      <div className="loading-state">
        <div className="spinner"></div>
        <div>Loading rules...</div>
      </div>
    </div>
  )

  if (error) return (
    <div className="rules-page">
      <div className="error-state">{error}</div>
    </div>
  )

  return (
    <div className="rules-page">
      <div className="page-header">
        <h2>Detection Rules</h2>
        <div className="header-actions">
          <button className="btn-secondary" onClick={handleValidate}>Validate</button>
          <button className="btn-secondary" onClick={handleImportClick}>Import</button>
          <div className="export-dropdown">
            <button className="btn-secondary">Export</button>
            <div className="export-menu">
              <button onClick={() => handleExport('json')}>JSON</button>
              <button onClick={() => handleExport('yaml')}>YAML</button>
            </div>
          </div>
          <button className="btn-primary" onClick={handleAddRule}>Add Rule</button>
        </div>
      </div>

      <div className="stats-cards">
        <div className="stat-card">
          <div className="stat-icon">📋</div>
          <div className="stat-content">
            <div className="stat-value">{totalCount}</div>
            <div className="stat-label">Total Rules</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon enabled">✓</div>
          <div className="stat-content">
            <div className="stat-value enabled">{enabledCount}</div>
            <div className="stat-label">Enabled</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-icon disabled">✗</div>
          <div className="stat-content">
            <div className="stat-value disabled">{totalCount - enabledCount}</div>
            <div className="stat-label">Disabled</div>
          </div>
        </div>
      </div>

      <div className="filter-bar">
        <input
          type="text"
          placeholder="Search rules..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          className="search-input"
        />
        <select 
          value={filterSeverity} 
          onChange={e => setFilterSeverity(e.target.value)}
          className="filter-select"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select 
          value={filterStatus} 
          onChange={e => setFilterStatus(e.target.value)}
          className="filter-select"
        >
          <option value="all">All Status</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </select>
      </div>

      <div className="rules-grid">
        {filteredRules.map(rule => (
          <div key={rule.id} className={`rule-card ${rule.enabled ? '' : 'disabled'}`}>
            <div className="rule-header">
              <div className="rule-title">
                <span className={`severity-dot ${getSeverityClass(rule.severity)}`}></span>
                <span className="rule-name">{rule.name}</span>
              </div>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={rule.enabled}
                  onChange={() => handleToggle(rule.name, rule.enabled)}
                />
                <span className="slider"></span>
              </label>
            </div>
            
            <div className="rule-meta">
              <span className={`severity-badge ${getSeverityClass(rule.severity)}`}>
                {getSeverityIcon(rule.severity)} {rule.severity}
              </span>
              <span className="score-badge">Score: {rule.score}</span>
              {!rule.is_custom && <span className="builtin-badge">Built-in</span>}
            </div>
            
            <p className="rule-description">{rule.description}</p>
            
            <div className="rule-footer">
              <div className="mitre-tags">
                {rule.mitre_attack?.slice(0, 3).map(m => (
                  <span key={m} className="mitre-tag">{m}</span>
                ))}
                {rule.mitre_attack && rule.mitre_attack.length > 3 && (
                  <span className="mitre-tag">+{rule.mitre_attack.length - 3}</span>
                )}
              </div>
              <div className="rule-actions">
                <button className="rule-action" onClick={() => handleViewDetails(rule)}>Details</button>
                <button className="rule-action" onClick={() => handleEditRule(rule)}>Edit</button>
                {rule.is_custom && (
                  <button className="rule-action rule-action-delete" onClick={() => handleDeleteRule(rule)}>Delete</button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {filteredRules.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon">🛡️</div>
          <div>No rules match your filters</div>
        </div>
      )}

      {selectedRule && (
        <div className="modal-overlay" onClick={() => setSelectedRule(null)}>
          <div className="modal-content rule-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Rule Details</h3>
              <button className="close-btn" onClick={() => setSelectedRule(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-section">
                <div className="detail-row">
                  <span className="detail-label">Name:</span>
                  <span className="detail-value">{selectedRule.name}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">ID:</span>
                  <span className="detail-value mono">{selectedRule.id}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Severity:</span>
                  <span className={`severity-badge ${getSeverityClass(selectedRule.severity)}`}>
                    {getSeverityIcon(selectedRule.severity)} {selectedRule.severity}
                  </span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Score:</span>
                  <span className="detail-value">{selectedRule.score}</span>
                </div>
                <div className="detail-row">
                  <span className="detail-label">Status:</span>
                  <span className={`status-badge ${selectedRule.enabled ? 'enabled' : 'disabled'}`}>
                    {selectedRule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </div>

              <div className="detail-section">
                <h4>Description</h4>
                <p className="detail-description">{selectedRule.description}</p>
              </div>

              {selectedRule.mitre_attack && selectedRule.mitre_attack.length > 0 && (
                <div className="detail-section">
                  <h4>MITRE ATT&CK</h4>
                  <div className="mitre-tags">
                    {selectedRule.mitre_attack.map(m => (
                      <span key={m} className="mitre-tag">{m}</span>
                    ))}
                  </div>
                </div>
              )}

              {selectedRule.tags && selectedRule.tags.length > 0 && (
                <div className="detail-section">
                  <h4>Tags</h4>
                  <div className="tags-list">
                    {selectedRule.tags.map(tag => (
                      <span key={tag} className="tag-item">{tag}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {showValidateModal && (
        <div className="modal-overlay" onClick={() => setShowValidateModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Validate Rule</h3>
              <button className="close-btn" onClick={() => setShowValidateModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <p className="modal-desc">Enter rule YAML or JSON content to validate:</p>
              <textarea
                className="validate-input"
                placeholder={`- name: Example Rule
  description: This is an example rule
  severity: high
  enabled: true
  score: 80`}
                rows={10}
              />
              <div className="modal-actions">
                <button className="btn-secondary" onClick={() => setShowValidateModal(false)}>
                  Cancel
                </button>
                <button 
                  className="btn-primary" 
                  onClick={() => {
                    const textarea = document.querySelector('.validate-input') as HTMLTextAreaElement
                    if (textarea?.value) {
                      const content = textarea.value
                      try {
                        if (content.trim().startsWith('-')) {
                          handleValidateRule({ name: 'temp', description: content, severity: 'medium', enabled: true, score: 50 })
                        } else {
                          const parsed = JSON.parse(content)
                          handleValidateRule(parsed)
                        }
                      } catch {
                        handleValidateRule({ name: 'temp', description: content, severity: 'medium', enabled: true, score: 50 })
                      }
                    }
                  }}
                  disabled={validating}
                >
                  {validating ? 'Validating...' : 'Validate'}
                </button>
              </div>
              {validateResult && (
                <div className={`validation-result ${validateResult.valid ? 'valid' : 'invalid'}`}>
                  <div className="result-header">
                    {validateResult.valid ? '✓ Valid Rule' : '✗ Invalid Rule'}
                  </div>
                  {validateResult.errors.length > 0 && (
                    <div className="result-errors">
                      <strong>Errors:</strong>
                      <ul>{validateResult.errors.map((e, i) => <li key={i}>{e}</li>)}</ul>
                    </div>
                  )}
                  {validateResult.warnings.length > 0 && (
                    <div className="result-warnings">
                      <strong>Warnings:</strong>
                      <ul>{validateResult.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {showAddModal && (
        <div className="modal-overlay" onClick={() => setShowAddModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Add New Rule</h3>
              <button className="close-btn" onClick={() => setShowAddModal(false)}>×</button>
            </div>
            <div className="modal-body">
              {addRuleStep === 'choice' ? (
                <div className="add-rule-choice">
                  <p className="modal-desc">Choose how to create a new rule:</p>
                  <div className="choice-cards">
                    <div className="choice-card" onClick={handleOpenTemplateModalFromAdd}>
                      <div className="choice-icon">📋</div>
                      <div className="choice-title">From Template</div>
                      <div className="choice-desc">Create a rule from a pre-defined template with customizable parameters</div>
                    </div>
                    <div className="choice-card" onClick={handleOpenCustomRuleFromAdd}>
                      <div className="choice-icon">✏️</div>
                      <div className="choice-title">Custom Rule</div>
                      <div className="choice-desc">Create a custom rule by filling in the rule details manually</div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="add-rule-form">
                  <div className="form-group">
                    <label>Rule Name <span className="required">*</span></label>
                    <input
                      type="text"
                      value={newRule.name}
                      onChange={e => setNewRule({...newRule, name: e.target.value})}
                      placeholder="e.g. suspicious-login-detected"
                    />
                  </div>
                  <div className="form-group">
                    <label>Description</label>
                    <textarea
                      value={newRule.description}
                      onChange={e => setNewRule({...newRule, description: e.target.value})}
                      rows={3}
                      placeholder="Describe what this rule detects..."
                    />
                  </div>
                  <div className="form-row">
                    <div className="form-group">
                      <label>Severity</label>
                      <select
                        value={newRule.severity}
                        onChange={e => setNewRule({...newRule, severity: e.target.value})}
                      >
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label>Score (0-100)</label>
                      <input
                        type="number"
                        min="0"
                        max="100"
                        value={newRule.score}
                        onChange={e => setNewRule({...newRule, score: parseFloat(e.target.value) || 0})}
                      />
                    </div>
                  </div>
                  <div className="form-group">
                    <label>MITRE ATT&CK (comma-separated)</label>
                    <input
                      type="text"
                      value={newRule.mitre_attack?.join(', ') || ''}
                      onChange={e => setNewRule({
                        ...newRule,
                        mitre_attack: e.target.value.split(',').map(s => s.trim()).filter(s => s)
                      })}
                      placeholder="T1055, T1056"
                    />
                  </div>
                  <div className="form-group">
                    <label>Event IDs (comma-separated)</label>
                    <input
                      type="text"
                      value={newRule.event_ids?.join(', ') || ''}
                      onChange={e => setNewRule({
                        ...newRule,
                        event_ids: e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n))
                      })}
                      placeholder="4624, 4625"
                    />
                  </div>
                  <div className="form-group">
                    <label>Alert Message</label>
                    <input
                      type="text"
                      value={newRule.message}
                      onChange={e => setNewRule({...newRule, message: e.target.value})}
                      placeholder="Alert message when rule triggers"
                    />
                  </div>
                  <div className="modal-actions">
                    <button className="btn-secondary" onClick={() => setAddRuleStep('choice')}>
                      Back
                    </button>
                    <button className="btn-primary" onClick={handleCreateCustomRule}>
                      Create Rule
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {showImportModal && (
        <div className="modal-overlay" onClick={() => setShowImportModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Import Rules</h3>
              <button className="close-btn" onClick={() => setShowImportModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <p className="modal-desc">Select a YAML or JSON file containing rules:</p>
              <details className="format-example">
                <summary>View Format Examples</summary>
                <div className="format-content">
                  <h5>JSON Format:</h5>
                  <pre>{`[
  {
    "name": "custom-rule-1",
    "description": "My custom rule",
    "severity": "high",
    "enabled": true,
    "score": 80,
    "mitre_attack": ["T1055"],
    "event_ids": [4624, 4625],
    "message": "Suspicious activity detected"
  }
]`}</pre>
                  <h5>YAML Format:</h5>
                  <pre>{`- name: custom-rule-1
  description: My custom rule
  severity: high
  enabled: true
  score: 80
  mitre_attack:
    - T1055
  event_ids:
    - 4624
    - 4625
  message: Suspicious activity detected`}</pre>
                </div>
              </details>
              <input
                type="file"
                ref={fileInputRef}
                accept=".yaml,.yml,.json"
                onChange={handleFileUpload}
                style={{ display: 'none' }}
              />
              <button 
                className="btn-primary btn-upload"
                onClick={() => fileInputRef.current?.click()}
                disabled={importing}
              >
                {importing ? 'Importing...' : 'Choose File'}
              </button>
              {importResult && (
                <div className={`import-result ${importResult.imported > 0 ? 'success' : 'error'}`}>
                  <div className="result-header">
                    {importResult.imported > 0 
                      ? `✓ Imported ${importResult.imported} rules` 
                      : '✗ Import failed'}
                  </div>
                  {importResult.failed > 0 && (
                    <div className="result-info">Failed: {importResult.failed}</div>
                  )}
                  {importResult.errors.length > 0 && (
                    <div className="result-errors">
                      <ul>{importResult.errors.map((e, i) => <li key={i}>{e}</li>)}</ul>
                    </div>
                  )}
                </div>
              )}
              <div className="modal-actions">
                <button className="btn-secondary" onClick={() => setShowImportModal(false)}>
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showTemplateModal && (
        <div className="modal-overlay" onClick={() => setShowTemplateModal(false)}>
          <div className="modal-content template-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Create Rule from Template</h3>
              <button className="close-btn" onClick={() => setShowTemplateModal(false)}>×</button>
            </div>
            <div className="modal-body">
              {!selectedTemplate ? (
                <>
                  <p className="modal-desc">Select a template:</p>
                  <div className="template-list">
                    {templates.length === 0 ? (
                      <div className="empty-state">No templates available</div>
                    ) : (
                      templates.map(template => (
                        <div 
                          key={template.name} 
                          className="template-card"
                          onClick={() => handleSelectTemplate(template)}
                        >
                          <div className="template-name">{template.name}</div>
                          <div className="template-desc">{template.description}</div>
                          <div className="template-params">
                            {template.parameters.length} parameters
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </>
              ) : (
                <>
                  <div className="selected-template-header">
                    <button className="btn-back" onClick={() => setSelectedTemplate(null)}>← Back</button>
                    <h4>{selectedTemplate.name}</h4>
                  </div>
                  <div className="template-params-form">
                    {selectedTemplate.parameters.map(param => (
                      <div key={param.name} className="param-item">
                        <label>
                          {param.name}
                          {param.required && <span className="required">*</span>}
                        </label>
                        <p className="param-desc">{param.description}</p>
                        {param.options && param.options.length > 0 ? (
                          <select 
                            value={templateParams[param.name] || ''}
                            onChange={e => setTemplateParams({...templateParams, [param.name]: e.target.value})}
                          >
                            <option value="">Select...</option>
                            {param.options.map(opt => (
                              <option key={opt} value={opt}>{opt}</option>
                            ))}
                          </select>
                        ) : (
                          <input
                            type={param.type === 'number' ? 'number' : 'text'}
                            value={templateParams[param.name] || ''}
                            onChange={e => setTemplateParams({...templateParams, [param.name]: e.target.value})}
                            placeholder={param.default || ''}
                          />
                        )}
                      </div>
                    ))}
                  </div>
                  <div className="modal-actions">
                    <button className="btn-secondary" onClick={() => setShowTemplateModal(false)}>
                      Cancel
                    </button>
                    <button 
                      className="btn-primary"
                      onClick={handleInstantiateTemplate}
                      disabled={selectedTemplate.parameters.some(p => p.required && !templateParams[p.name])}
                    >
                      Create Rule
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {showEditModal && editingRule && (
        <div className="modal-overlay" onClick={() => setShowEditModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Edit Rule</h3>
              <button className="close-btn" onClick={() => setShowEditModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  value={editingRule.name}
                  onChange={e => setEditingRule({...editingRule, name: e.target.value})}
                  disabled={!editingRule.is_custom}
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={editingRule.description}
                  onChange={e => setEditingRule({...editingRule, description: e.target.value})}
                  rows={3}
                />
              </div>
              <div className="form-row">
                <div className="form-group">
                  <label>Severity</label>
                  <select
                    value={editingRule.severity}
                    onChange={e => setEditingRule({...editingRule, severity: e.target.value})}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Score (0-100)</label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={editingRule.score}
                    onChange={e => setEditingRule({...editingRule, score: parseFloat(e.target.value) || 0})}
                  />
                </div>
              </div>
              <div className="form-group">
                <label>MITRE ATT&CK</label>
                <input
                  type="text"
                  value={editingRule.mitre_attack?.join(', ') || ''}
                  onChange={e => setEditingRule({
                    ...editingRule,
                    mitre_attack: e.target.value.split(',').map(s => s.trim()).filter(s => s)
                  })}
                  placeholder="T1234, T5678"
                />
              </div>
              <div className="form-group">
                <label>Event IDs (comma-separated)</label>
                <input
                  type="text"
                  value={editingRule.event_ids?.join(', ') || ''}
                  onChange={e => setEditingRule({
                    ...editingRule,
                    event_ids: e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n))
                  })}
                  placeholder="4624, 4625"
                />
              </div>
              <div className="form-group">
                <label>Message</label>
                <input
                  type="text"
                  value={editingRule.message || ''}
                  onChange={e => setEditingRule({...editingRule, message: e.target.value})}
                />
              </div>
              <div className="modal-actions">
                <button className="btn-secondary" onClick={() => setShowEditModal(false)}>
                  Cancel
                </button>
                <button className="btn-primary" onClick={handleSaveEdit}>
                  Save Changes
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <style>{`
        .rules-page {
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
        
        .rules-page h2 {
          font-size: 1.8rem;
          color: #00d9ff;
          margin: 0;
        }
        
        .header-actions {
          display: flex;
          gap: 12px;
        }
        
        .btn-primary {
          padding: 10px 20px;
          background: #00d9ff;
          border: none;
          border-radius: 6px;
          color: #000;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .btn-primary:hover {
          background: #00c4e6;
        }
        
        .btn-secondary {
          padding: 10px 20px;
          background: rgba(0, 217, 255, 0.1);
          border: 1px solid #00d9ff;
          border-radius: 6px;
          color: #00d9ff;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .btn-secondary:hover {
          background: rgba(0, 217, 255, 0.2);
        }
        
        .export-dropdown {
          position: relative;
        }
        
        .export-menu {
          display: none;
          position: absolute;
          top: 100%;
          right: 0;
          background: #1a1a2e;
          border: 1px solid #333;
          border-radius: 6px;
          overflow: hidden;
          z-index: 100;
        }
        
        .export-dropdown:hover .export-menu {
          display: block;
        }
        
        .export-menu button {
          display: block;
          width: 100%;
          padding: 10px 20px;
          background: none;
          border: none;
          color: #fff;
          text-align: left;
          cursor: pointer;
        }
        
        .export-menu button:hover {
          background: rgba(0, 217, 255, 0.1);
        }
        
        .stats-cards {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 16px;
          margin-bottom: 20px;
        }
        
        .stat-card {
          display: flex;
          align-items: center;
          gap: 16px;
          padding: 20px;
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          border: 1px solid #333;
        }
        
        .stat-icon {
          font-size: 24px;
          width: 48px;
          height: 48px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(255, 255, 255, 0.05);
          border-radius: 10px;
        }
        
        .stat-icon.enabled {
          background: rgba(34, 197, 94, 0.1);
          color: #22c55e;
        }
        
        .stat-icon.disabled {
          background: rgba(239, 68, 68, 0.1);
          color: #ef4444;
        }
        
        .stat-value {
          font-size: 28px;
          font-weight: 700;
          color: #fff;
        }
        
        .stat-value.enabled { color: #22c55e; }
        .stat-value.disabled { color: #ef4444; }
        
        .stat-label {
          font-size: 13px;
          color: #888;
          margin-top: 4px;
        }
        
        .filter-bar {
          display: flex;
          gap: 12px;
          margin-bottom: 20px;
        }
        
        .search-input {
          flex: 1;
          padding: 10px 16px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 8px;
          color: #fff;
          font-size: 14px;
        }
        
        .search-input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .filter-select {
          padding: 10px 16px;
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid #333;
          border-radius: 8px;
          color: #fff;
          font-size: 14px;
          cursor: pointer;
        }
        
        .rules-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
          gap: 16px;
          flex: 1;
          overflow-y: auto;
        }
        
        .rule-card {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          border: 1px solid #333;
          padding: 20px;
          display: flex;
          flex-direction: column;
          gap: 12px;
          transition: all 0.2s;
        }
        
        .rule-card:hover {
          border-color: #00d9ff;
          transform: translateY(-2px);
        }
        
        .rule-card.disabled {
          opacity: 0.6;
        }
        
        .rule-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        
        .rule-title {
          display: flex;
          align-items: center;
          gap: 10px;
        }
        
        .severity-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
        }
        
        .severity-dot.severity-critical { background: #ef4444; box-shadow: 0 0 8px #ef4444; }
        .severity-dot.severity-high { background: #f97316; box-shadow: 0 0 8px #f97316; }
        .severity-dot.severity-medium { background: #eab308; box-shadow: 0 0 8px #eab308; }
        .severity-dot.severity-low { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
        .severity-dot.severity-info { background: #6b7280; }
        
        .rule-name {
          font-weight: 600;
          color: #fff;
          font-size: 15px;
        }
        
        .switch {
          position: relative;
          width: 44px;
          height: 24px;
        }
        
        .switch input {
          opacity: 0;
          width: 0;
          height: 0;
        }
        
        .slider {
          position: absolute;
          cursor: pointer;
          top: 3px;
          left: 0;
          right: 0;
          bottom: 3px;
          background: #333;
          border-radius: 24px;
          transition: 0.3s;
        }
        
        .slider:before {
          content: "";
          position: absolute;
          width: 18px;
          height: 18px;
          left: 3px;
          bottom: 3px;
          background: #fff;
          border-radius: 50%;
          transition: 0.3s;
        }
        
        input:checked + .slider {
          background: #22c55e;
        }
        
        input:checked + .slider:before {
          transform: translateX(20px);
        }
        
        .rule-meta {
          display: flex;
          gap: 10px;
          align-items: center;
        }
        
        .severity-badge {
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 12px;
          font-weight: 600;
        }
        
        .severity-badge.severity-critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .severity-badge.severity-high { background: rgba(249, 115, 22, 0.2); color: #f97316; }
        .severity-badge.severity-medium { background: rgba(234, 179, 8, 0.2); color: #eab308; }
        .severity-badge.severity-low { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
        .severity-badge.severity-info { background: rgba(107, 114, 128, 0.2); color: #9ca3af; }
        
        .score-badge {
          font-size: 12px;
          color: #888;
          padding: 4px 8px;
          background: rgba(255, 255, 255, 0.05);
          border-radius: 4px;
        }
        
        .builtin-badge {
          font-size: 11px;
          color: #f59e0b;
          padding: 4px 8px;
          background: rgba(245, 158, 11, 0.1);
          border-radius: 4px;
          border: 1px solid rgba(245, 158, 11, 0.3);
        }
        
        .rule-description {
          color: #888;
          font-size: 13px;
          line-height: 1.5;
          margin: 0;
          flex: 1;
        }
        
        .rule-footer {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding-top: 12px;
          border-top: 1px solid #333;
        }
        
        .rule-actions {
          display: flex;
          gap: 8px;
        }
        
        .mitre-tags {
          display: flex;
          gap: 6px;
          flex-wrap: wrap;
        }
        
        .mitre-tag {
          font-size: 11px;
          padding: 3px 8px;
          background: rgba(59, 130, 246, 0.1);
          color: #3b82f6;
          border-radius: 4px;
          font-family: monospace;
        }
        
        .rule-action {
          padding: 6px 12px;
          background: transparent;
          border: 1px solid #333;
          border-radius: 6px;
          color: #888;
          font-size: 12px;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .rule-action:hover {
          border-color: #00d9ff;
          color: #00d9ff;
        }
        
        .rule-action-delete {
          color: #ef4444;
          border-color: #ef4444;
        }
        
        .rule-action-delete:hover {
          background: rgba(239, 68, 68, 0.1);
          border-color: #ef4444;
          color: #ef4444;
        }
        
        .form-group {
          margin-bottom: 16px;
        }
        
        .form-group label {
          display: block;
          margin-bottom: 6px;
          color: #888;
          font-size: 13px;
          font-weight: 500;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
          width: 100%;
          padding: 10px 12px;
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid #333;
          border-radius: 6px;
          color: #eee;
          font-size: 14px;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .form-group input:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        
        .form-row {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
        }
        
        .format-example {
          margin-bottom: 16px;
          padding: 12px;
          background: rgba(0, 0, 0, 0.2);
          border-radius: 6px;
          border: 1px solid #333;
        }
        
        .format-example summary {
          cursor: pointer;
          color: #00d9ff;
          font-weight: 500;
        }
        
        .format-content h5 {
          color: #888;
          margin: 12px 0 8px 0;
          font-size: 13px;
        }
        
        .format-content pre {
          background: rgba(0, 0, 0, 0.3);
          padding: 12px;
          border-radius: 4px;
          font-size: 12px;
          color: #ccc;
          overflow-x: auto;
          white-space: pre-wrap;
          word-break: break-all;
        }
        
        .add-rule-choice {
          padding: 10px 0;
        }
        
        .add-rule-choice .modal-desc {
          margin-bottom: 20px;
        }
        
        .choice-cards {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
        }
        
        .choice-card {
          padding: 24px 20px;
          background: rgba(0, 0, 0, 0.2);
          border: 2px solid #333;
          border-radius: 12px;
          cursor: pointer;
          transition: all 0.2s;
          text-align: center;
        }
        
        .choice-card:hover {
          border-color: #00d9ff;
          background: rgba(0, 217, 255, 0.05);
          transform: translateY(-2px);
        }
        
        .choice-icon {
          font-size: 36px;
          margin-bottom: 12px;
        }
        
        .choice-title {
          font-size: 16px;
          font-weight: 600;
          color: #fff;
          margin-bottom: 8px;
        }
        
        .choice-desc {
          font-size: 13px;
          color: #888;
          line-height: 1.4;
        }
        
        .add-rule-form {
          padding: 10px 0;
        }
        
        .loading-state, .empty-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 300px;
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
        }
        
        .empty-icon {
          font-size: 48px;
        }
        
        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0, 0, 0, 0.8);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
        }
        
        .modal-content {
          background: #1a1a2e;
          border-radius: 12px;
          padding: 24px;
          max-width: 600px;
          width: 90%;
          max-height: 80vh;
          overflow-y: auto;
          border: 1px solid #333;
        }
        
        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }
        
        .modal-header h3 {
          color: #00d9ff;
          margin: 0;
        }
        
        .close-btn {
          background: none;
          border: none;
          color: #888;
          font-size: 24px;
          cursor: pointer;
        }
        
        .close-btn:hover {
          color: #fff;
        }
        
        .modal-desc {
          color: #888;
          margin-bottom: 16px;
        }
        
        .modal-actions {
          display: flex;
          gap: 12px;
          margin-top: 16px;
        }
        
        .validate-input {
          width: 100%;
          padding: 12px;
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid #333;
          border-radius: 6px;
          color: #eee;
          font-family: monospace;
          font-size: 13px;
          resize: vertical;
        }
        
        .validate-input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .validation-result, .import-result {
          margin-top: 16px;
          padding: 12px;
          border-radius: 8px;
        }
        
        .validation-result.valid, .import-result.success {
          background: rgba(34, 197, 94, 0.1);
          border: 1px solid rgba(34, 197, 94, 0.3);
        }
        
        .validation-result.invalid, .import-result.error {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .result-header {
          font-weight: 600;
          margin-bottom: 8px;
        }
        
        .validation-result.valid .result-header { color: #22c55e; }
        .validation-result.invalid .result-header { color: #ef4444; }
        .import-result.success .result-header { color: #22c55e; }
        .import-result.error .result-header { color: #ef4444; }
        
        .result-errors, .result-warnings {
          font-size: 13px;
          color: #888;
        }
        
        .result-errors ul, .result-warnings ul {
          margin: 8px 0 0 0;
          padding-left: 20px;
        }
        
        .result-errors { color: #ef4444; }
        .result-warnings { color: #f59e0b; }
        
        .btn-upload {
          width: 100%;
        }
        
        .rule-modal .detail-section {
          margin-bottom: 20px;
        }
        
        .rule-modal .detail-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 8px 0;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .detail-label {
          color: #888;
          font-size: 14px;
        }
        
        .detail-value {
          color: #fff;
          font-weight: 500;
        }
        
        .detail-value.mono {
          font-family: monospace;
          font-size: 13px;
        }
        
        .status-badge {
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
        }
        
        .status-badge.enabled {
          background: rgba(34, 197, 94, 0.2);
          color: #22c55e;
        }
        
        .status-badge.disabled {
          background: rgba(239, 68, 68, 0.2);
          color: #ef4444;
        }
        
        .rule-modal h4 {
          color: #00d9ff;
          margin: 0 0 12px 0;
          font-size: 14px;
        }
        
        .detail-description {
          color: #ccc;
          line-height: 1.6;
          margin: 0;
        }
        
        .tags-list {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
        }
        
        .tag-item {
          padding: 4px 10px;
          background: rgba(168, 85, 247, 0.1);
          color: #a855f7;
          border-radius: 4px;
          font-size: 12px;
        }
        
        .template-modal {
          max-width: 600px;
        }
        
        .template-list {
          display: flex;
          flex-direction: column;
          gap: 12px;
          max-height: 400px;
          overflow-y: auto;
        }
        
        .template-card {
          padding: 15px;
          background: rgba(0, 0, 0, 0.2);
          border: 1px solid #333;
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .template-card:hover {
          background: rgba(0, 217, 255, 0.05);
          border-color: #00d9ff;
        }
        
        .template-name {
          font-weight: bold;
          color: #00d9ff;
          margin-bottom: 5px;
        }
        
        .template-desc {
          font-size: 13px;
          color: #888;
          margin-bottom: 8px;
        }
        
        .template-params {
          font-size: 12px;
          color: #666;
        }
        
        .selected-template-header {
          display: flex;
          align-items: center;
          gap: 15px;
          margin-bottom: 20px;
        }
        
        .selected-template-header h4 {
          margin: 0;
          color: #00d9ff;
        }
        
        .btn-back {
          background: none;
          border: none;
          color: #888;
          cursor: pointer;
          padding: 5px 10px;
        }
        
        .btn-back:hover {
          color: #00d9ff;
        }
        
        .template-params-form {
          display: flex;
          flex-direction: column;
          gap: 15px;
        }
        
        .param-item label {
          display: block;
          font-weight: bold;
          color: #ccc;
          margin-bottom: 5px;
        }
        
        .param-item .required {
          color: #ef4444;
          margin-left: 4px;
        }
        
        .param-desc {
          font-size: 12px;
          color: #666;
          margin: 0 0 8px 0;
        }
        
        .param-item input,
        .param-item select {
          width: 100%;
          padding: 8px 12px;
          background: #16213e;
          border: 1px solid #333;
          border-radius: 4px;
          color: #eee;
          font-size: 14px;
        }
        
        .param-item input:focus,
        .param-item select:focus {
          outline: none;
          border-color: #00d9ff;
        }
      `}</style>
    </div>
  )
}

export default Rules
