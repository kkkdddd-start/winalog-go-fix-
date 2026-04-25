import { useState, useEffect } from 'react'
import { useI18n } from '../locales/I18n'
import { suppressAPI } from '../api'

interface SuppressCondition {
  field: string
  operator: string
  value: string
}

interface SuppressRule {
  id: number
  name: string
  conditions: SuppressCondition[]
  duration: number
  scope: string
  enabled: boolean
  expires_at: string
  created_at: string
}

const FIELD_OPTIONS = [
  { value: 'event_id', label: 'Event ID' },
  { value: 'source', label: 'Source' },
  { value: 'log_name', label: 'Log Name' },
  { value: 'computer', label: 'Computer' },
  { value: 'user', label: 'User' },
  { value: 'user_sid', label: 'User SID' },
  { value: 'ip_address', label: 'IP Address' },
]

const OPERATOR_OPTIONS = [
  { value: 'equals', label: 'Equals' },
  { value: 'contains', label: 'Contains' },
  { value: 'starts_with', label: 'Starts With' },
  { value: 'ends_with', label: 'Ends With' },
]

const DURATION_OPTIONS = [
  { value: 60, label: '1 hour' },
  { value: 360, label: '6 hours' },
  { value: 1440, label: '24 hours' },
  { value: 10080, label: '7 days' },
  { value: 43200, label: '30 days' },
  { value: 0, label: 'Permanent' },
]

function Suppress() {
  const { t } = useI18n()
  const [rules, setRules] = useState<SuppressRule[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [editingRule, setEditingRule] = useState<SuppressRule | null>(null)
  const [selectedRule, setSelectedRule] = useState<SuppressRule | null>(null)

  const [formData, setFormData] = useState({
    name: '',
    duration: 1440,
    scope: 'global',
    expires_at: '',
    conditions: [] as SuppressCondition[],
  })

  const [editFormData, setEditFormData] = useState({
    name: '',
    duration: 1440,
    scope: 'global',
    expires_at: '',
    conditions: [] as SuppressCondition[],
    enabled: true,
  })

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = async () => {
    setLoading(true)
    setError('')
    try {
      const res = await suppressAPI.list()
      setRules(res.data.rules || [])
    } catch (err: any) {
      setError(err.message || 'Failed to load suppress rules')
    } finally {
      setLoading(false)
    }
  }

  const resetForm = () => {
    setFormData({
      name: '',
      duration: 1440,
      scope: 'global',
      expires_at: '',
      conditions: [],
    })
  }

  const handleCreate = async () => {
    if (!formData.name.trim()) {
      alert('Rule name is required')
      return
    }

    setLoading(true)
    setError('')
    try {
      await suppressAPI.create({
        name: formData.name,
        duration: formData.duration,
        scope: formData.scope,
        expires_at: formData.expires_at,
        conditions: formData.conditions,
        enabled: true,
      })
      setShowModal(false)
      resetForm()
      loadRules()
    } catch (err: any) {
      setError(err.message || 'Failed to create rule')
    } finally {
      setLoading(false)
    }
  }

  const handleEdit = (rule: SuppressRule) => {
    setEditingRule(rule)
    setEditFormData({
      name: rule.name,
      duration: rule.duration,
      scope: rule.scope,
      expires_at: rule.expires_at,
      conditions: rule.conditions || [],
      enabled: rule.enabled,
    })
    setShowEditModal(true)
  }

  const handleUpdate = async () => {
    if (!editingRule) return
    if (!editFormData.name.trim()) {
      alert('Rule name is required')
      return
    }

    setLoading(true)
    setError('')
    try {
      await suppressAPI.update(editingRule.id, {
        name: editFormData.name,
        duration: editFormData.duration,
        scope: editFormData.scope,
        expires_at: editFormData.expires_at,
        conditions: editFormData.conditions,
        enabled: editFormData.enabled,
      })
      setShowEditModal(false)
      setEditingRule(null)
      loadRules()
    } catch (err: any) {
      setError(err.message || 'Failed to update rule')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this rule?')) return

    setLoading(true)
    setError('')
    try {
      await suppressAPI.delete(id)
      loadRules()
    } catch (err: any) {
      setError(err.message || 'Failed to delete rule')
    } finally {
      setLoading(false)
    }
  }

  const handleToggle = async (id: number, enabled: boolean) => {
    setLoading(true)
    setError('')
    try {
      await suppressAPI.toggle(id, !enabled)
      loadRules()
    } catch (err: any) {
      setError(err.message || 'Failed to toggle rule')
    } finally {
      setLoading(false)
    }
  }

  const addCondition = (setter: Function, conditions: SuppressCondition[]) => {
    setter([...conditions, { field: 'event_id', operator: 'equals', value: '' }])
  }

  const updateCondition = (setter: Function, conditions: SuppressCondition[], index: number, field: string, value: string) => {
    const updated = [...conditions]
    updated[index] = { ...updated[index], [field]: value }
    setter(updated)
  }

  const removeCondition = (setter: Function, conditions: SuppressCondition[], index: number) => {
    setter(conditions.filter((_, i) => i !== index))
  }

  const getDurationLabel = (minutes: number) => {
    if (minutes === 0) return 'Permanent'
    if (minutes < 60) return `${minutes}m`
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h`
    return `${Math.floor(minutes / 1440)}d`
  }

  const formatConditions = (conditions: SuppressCondition[]) => {
    if (!conditions || conditions.length === 0) return 'No conditions (global suppress)'
    return conditions.map(c => `${c.field} ${c.operator} "${c.value}"`).join(' AND ')
  }

  const renderConditionInput = (
    conditions: SuppressCondition[],
    setter: Function,
    show: boolean
  ) => {
    if (!show) return null
    return (
      <div className="conditions-section">
        <div className="conditions-header">
          <label>Conditions</label>
          <button
            type="button"
            className="btn-add-condition"
            onClick={() => addCondition(setter, conditions)}
          >
            + Add Condition
          </button>
        </div>
        {conditions.length === 0 ? (
          <p className="no-conditions">No conditions - will suppress all matching alerts</p>
        ) : (
          <div className="conditions-list">
            {conditions.map((cond, index) => (
              <div key={index} className="condition-row">
                <select
                  value={cond.field}
                  onChange={e => updateCondition(setter, conditions, index, 'field', e.target.value)}
                >
                  {FIELD_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
                <select
                  value={cond.operator}
                  onChange={e => updateCondition(setter, conditions, index, 'operator', e.target.value)}
                >
                  {OPERATOR_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
                <input
                  type="text"
                  value={cond.value}
                  onChange={e => updateCondition(setter, conditions, index, 'value', e.target.value)}
                  placeholder="Value"
                />
                <button
                  type="button"
                  className="btn-remove-condition"
                  onClick={() => removeCondition(setter, conditions, index)}
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="suppress-page">
      <div className="page-header">
        <h2>{t('suppress.title')}</h2>
        <p className="page-desc">{t('suppress.pageDesc')}</p>
      </div>

      <div className="suppress-toolbar">
        <button
          onClick={() => setShowModal(true)}
          className="btn-primary"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          {t('suppress.addRule')}
        </button>
      </div>

      {error && (
        <div className="error-panel">
          <span className="error-icon">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {loading && rules.length === 0 ? (
        <div className="loading-state">
          <span className="spinner"></span>
          <span>{t('common.loading')}</span>
        </div>
      ) : rules.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🛡️</div>
          <h3>{t('suppress.noRules')}</h3>
          <p>{t('suppress.noRulesDesc')}</p>
        </div>
      ) : (
        <div className="rules-grid">
          {rules.map(rule => (
            <div key={rule.id} className={`rule-card ${!rule.enabled ? 'disabled' : ''}`}>
              <div className="rule-header">
                <div className="rule-title">
                  <span className={`status-dot ${rule.enabled ? 'enabled' : 'disabled'}`}></span>
                  <span className="rule-name">{rule.name}</span>
                </div>
                <div className="rule-actions-header">
                  <button
                    className="btn-icon"
                    onClick={() => handleEdit(rule)}
                    title="Edit"
                  >
                    ✏️
                  </button>
                  <button
                    className="btn-icon delete"
                    onClick={() => handleDelete(rule.id)}
                    title={t('suppress.delete')}
                  >
                    🗑️
                  </button>
                </div>
              </div>

              <div className="rule-meta">
                <span className={`scope-badge scope-${rule.scope}`}>
                  {rule.scope === 'global' ? '🌐' : rule.scope === 'user' ? '👤' : '💻'} {rule.scope}
                </span>
                <span className="duration-badge">
                  ⏱️ {getDurationLabel(rule.duration)}
                </span>
                {rule.expires_at && (
                  <span className="expires-badge">
                    📅 {new Date(rule.expires_at).toLocaleDateString()}
                  </span>
                )}
              </div>

              <div className="rule-conditions">
                <label>Conditions:</label>
                <p className="conditions-text">{formatConditions(rule.conditions)}</p>
              </div>

              <div className="rule-footer">
                <span className="created-at">
                  Created: {new Date(rule.created_at).toLocaleDateString()}
                </span>
                <button
                  className={`toggle-btn ${rule.enabled ? 'enabled' : 'disabled'}`}
                  onClick={() => handleToggle(rule.id, rule.enabled)}
                >
                  {rule.enabled ? t('suppress.enabled') : t('suppress.disabled')}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Add Suppress Rule</h3>
              <button className="close-btn" onClick={() => setShowModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Rule Name <span className="required">*</span></label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={e => setFormData({ ...formData, name: e.target.value })}
                  placeholder="e.g. suppress-admin-alerts"
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Scope</label>
                  <select
                    value={formData.scope}
                    onChange={e => setFormData({ ...formData, scope: e.target.value })}
                  >
                    <option value="global">🌐 Global</option>
                    <option value="user">👤 User</option>
                    <option value="computer">💻 Computer</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Duration</label>
                  <select
                    value={formData.duration}
                    onChange={e => setFormData({ ...formData, duration: parseInt(e.target.value) })}
                  >
                    {DURATION_OPTIONS.map(opt => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Expires At (Optional)</label>
                <input
                  type="datetime-local"
                  value={formData.expires_at}
                  onChange={e => setFormData({ ...formData, expires_at: e.target.value })}
                />
              </div>

              {renderConditionInput(formData.conditions, (c: SuppressCondition[]) => setFormData({ ...formData, conditions: c }), true)}
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowModal(false)}>
                {t('common.cancel')}
              </button>
              <button
                className="btn-primary"
                onClick={handleCreate}
                disabled={!formData.name || loading}
              >
                {t('suppress.create')}
              </button>
            </div>
          </div>
        </div>
      )}

      {showEditModal && editingRule && (
        <div className="modal-overlay" onClick={() => setShowEditModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Edit Suppress Rule</h3>
              <button className="close-btn" onClick={() => setShowEditModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Rule Name <span className="required">*</span></label>
                <input
                  type="text"
                  value={editFormData.name}
                  onChange={e => setEditFormData({ ...editFormData, name: e.target.value })}
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Scope</label>
                  <select
                    value={editFormData.scope}
                    onChange={e => setEditFormData({ ...editFormData, scope: e.target.value })}
                  >
                    <option value="global">🌐 Global</option>
                    <option value="user">👤 User</option>
                    <option value="computer">💻 Computer</option>
                  </select>
                </div>
                <div className="form-group">
                  <label>Duration</label>
                  <select
                    value={editFormData.duration}
                    onChange={e => setEditFormData({ ...editFormData, duration: parseInt(e.target.value) })}
                  >
                    {DURATION_OPTIONS.map(opt => (
                      <option key={opt.value} value={opt.value}>{opt.label}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label>Expires At (Optional)</label>
                <input
                  type="datetime-local"
                  value={editFormData.expires_at}
                  onChange={e => setEditFormData({ ...editFormData, expires_at: e.target.value })}
                />
              </div>

              <div className="form-group">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={editFormData.enabled}
                    onChange={e => setEditFormData({ ...editFormData, enabled: e.target.checked })}
                  />
                  <span>Enabled</span>
                </label>
              </div>

              {renderConditionInput(editFormData.conditions, (c: SuppressCondition[]) => setEditFormData({ ...editFormData, conditions: c }), true)}
            </div>
            <div className="modal-footer">
              <button className="btn-secondary" onClick={() => setShowEditModal(false)}>
                {t('common.cancel')}
              </button>
              <button
                className="btn-primary"
                onClick={handleUpdate}
                disabled={!editFormData.name || loading}
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}

      {selectedRule && (
        <div className="modal-overlay" onClick={() => setSelectedRule(null)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Rule Details</h3>
              <button className="close-btn" onClick={() => setSelectedRule(null)}>×</button>
            </div>
            <div className="modal-body">
              <div className="detail-row">
                <span className="detail-label">Name:</span>
                <span className="detail-value">{selectedRule.name}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Scope:</span>
                <span className="detail-value">{selectedRule.scope}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Duration:</span>
                <span className="detail-value">{getDurationLabel(selectedRule.duration)}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Status:</span>
                <span className={`status-badge ${selectedRule.enabled ? 'enabled' : 'disabled'}`}>
                  {selectedRule.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <div className="detail-section">
                <h4>Conditions</h4>
                <p className="detail-description">{formatConditions(selectedRule.conditions)}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="suppress-info">
        <div className="section-header">
          <h3>{t('suppress.about')}</h3>
        </div>
        <div className="info-content">
          <p>{t('suppress.aboutDesc')}</p>
        </div>
      </div>

      <style>{`
        .suppress-page {
          padding: 20px;
          height: 100%;
          display: flex;
          flex-direction: column;
        }
        
        .suppress-toolbar {
          margin-bottom: 20px;
        }
        
        .rules-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
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
        
        .status-dot {
          width: 10px;
          height: 10px;
          border-radius: 50%;
        }
        
        .status-dot.enabled {
          background: #22c55e;
          box-shadow: 0 0 8px #22c55e;
        }
        
        .status-dot.disabled {
          background: #ef4444;
        }
        
        .rule-name {
          font-weight: 600;
          color: #fff;
          font-size: 16px;
        }
        
        .rule-actions-header {
          display: flex;
          gap: 8px;
        }
        
        .btn-icon {
          background: transparent;
          border: 1px solid #333;
          border-radius: 6px;
          padding: 6px 10px;
          cursor: pointer;
          transition: all 0.2s;
        }
        
        .btn-icon:hover {
          border-color: #00d9ff;
        }
        
        .btn-icon.delete:hover {
          border-color: #ef4444;
        }
        
        .rule-meta {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
        }
        
        .scope-badge {
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 12px;
          background: rgba(0, 217, 255, 0.1);
          color: #00d9ff;
        }
        
        .duration-badge, .expires-badge {
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 12px;
          background: rgba(255, 255, 255, 0.05);
          color: #888;
        }
        
        .rule-conditions {
          flex: 1;
        }
        
        .rule-conditions label {
          font-size: 12px;
          color: #666;
          display: block;
          margin-bottom: 4px;
        }
        
        .conditions-text {
          color: #ccc;
          font-size: 13px;
          line-height: 1.4;
          margin: 0;
        }
        
        .rule-footer {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding-top: 12px;
          border-top: 1px solid #333;
        }
        
        .created-at {
          font-size: 12px;
          color: #666;
        }
        
        .toggle-btn {
          padding: 6px 12px;
          border-radius: 6px;
          font-size: 12px;
          cursor: pointer;
          transition: all 0.2s;
          border: 1px solid;
        }
        
        .toggle-btn.enabled {
          background: rgba(34, 197, 94, 0.1);
          border-color: #22c55e;
          color: #22c55e;
        }
        
        .toggle-btn.enabled:hover {
          background: rgba(34, 197, 94, 0.2);
        }
        
        .toggle-btn.disabled {
          background: rgba(239, 68, 68, 0.1);
          border-color: #ef4444;
          color: #ef4444;
        }
        
        .toggle-btn.disabled:hover {
          background: rgba(239, 68, 68, 0.2);
        }
        
        .modal-content {
          max-width: 600px;
        }
        
        .form-row {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
        }
        
        .checkbox-label {
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
        }
        
        .checkbox-label input {
          width: 18px;
          height: 18px;
        }
        
        .conditions-section {
          margin-top: 16px;
          padding: 16px;
          background: rgba(0, 0, 0, 0.2);
          border-radius: 8px;
          border: 1px solid #333;
        }
        
        .conditions-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }
        
        .conditions-header label {
          color: #888;
          font-size: 13px;
          font-weight: 500;
        }
        
        .btn-add-condition {
          background: rgba(0, 217, 255, 0.1);
          border: 1px solid #00d9ff;
          border-radius: 4px;
          color: #00d9ff;
          padding: 4px 12px;
          font-size: 12px;
          cursor: pointer;
        }
        
        .btn-add-condition:hover {
          background: rgba(0, 217, 255, 0.2);
        }
        
        .no-conditions {
          color: #666;
          font-size: 13px;
          margin: 0;
          text-align: center;
          padding: 12px;
        }
        
        .conditions-list {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }
        
        .condition-row {
          display: grid;
          grid-template-columns: 1fr 1fr 2fr auto;
          gap: 8px;
          align-items: center;
        }
        
        .condition-row select,
        .condition-row input {
          padding: 8px 10px;
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid #333;
          border-radius: 4px;
          color: #eee;
          font-size: 13px;
        }
        
        .condition-row select:focus,
        .condition-row input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .btn-remove-condition {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid #ef4444;
          border-radius: 4px;
          color: #ef4444;
          width: 28px;
          height: 28px;
          cursor: pointer;
          font-size: 16px;
        }
        
        .btn-remove-condition:hover {
          background: rgba(239, 68, 68, 0.2);
        }
        
        .detail-row {
          display: flex;
          justify-content: space-between;
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
        
        .detail-section {
          margin-top: 16px;
        }
        
        .detail-section h4 {
          color: #00d9ff;
          margin: 0 0 8px 0;
          font-size: 14px;
        }
        
        .detail-description {
          color: #ccc;
          line-height: 1.5;
          margin: 0;
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
        
        .required {
          color: #ef4444;
        }
      `}</style>
    </div>
  )
}

export default Suppress
