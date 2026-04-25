import { useState, useEffect } from 'react'
import { useI18n } from '../locales/I18n'
import { forensicsAPI } from '../api'

interface HashResult {
  verified: boolean
  expected: string
  actual: string
  path: string
}

interface EvidenceItem {
  evidence_id: string
  timestamp: string
  operator: string
  action: string
  file_count: number
}

interface ChainOfCustodyEntry {
  id: number
  evidence_id: string
  timestamp: string
  operator: string
  action: string
  input_hash?: string
  output_hash?: string
  previous_hash?: string
}

function Forensics() {
  const { t } = useI18n()
  const [collecting, setCollecting] = useState(false)
  const [hashInput, setHashInput] = useState('')
  const [filePath, setFilePath] = useState('')
  const [hashResult, setHashResult] = useState<HashResult | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [calculatingHash, setCalculatingHash] = useState(false)
  const [evidence, setEvidence] = useState<EvidenceItem[]>([])
  const [collectStatus, setCollectStatus] = useState('')
  const [selectedTypes, setSelectedTypes] = useState<string[]>(['eventlogs', 'registry', 'prefetch'])
  const [chainOfCustody, setChainOfCustody] = useState<ChainOfCustodyEntry[]>([])
  const [showChainModal, setShowChainModal] = useState(false)

  useEffect(() => {
    fetchEvidence()
    fetchChainOfCustody()
  }, [])

  const fetchEvidence = () => {
    forensicsAPI.listEvidence()
      .then(res => {
        if (res.data && res.data.evidence) {
          setEvidence(res.data.evidence)
        }
      })
      .catch(err => console.error('Failed to load evidence:', err))
  }

  const fetchChainOfCustody = () => {
    forensicsAPI.chainOfCustody()
      .then(res => {
        if (res.data && res.data.chain) {
          setChainOfCustody(res.data.chain)
        }
      })
      .catch(err => console.error('Failed to load chain of custody:', err))
  }

  const handleCalculateHash = async () => {
    if (!filePath.trim()) return
    
    setCalculatingHash(true)
    try {
      const res = await forensicsAPI.calculateHash(filePath)
      setHashInput(res.data.sha256 || '')
    } catch (error: any) {
      console.error('Failed to calculate hash:', error)
      alert('Failed to calculate hash: ' + (error.response?.data?.error || error.message))
    } finally {
      setCalculatingHash(false)
    }
  }

  const handleCollect = async () => {
    setCollecting(true)
    setCollectStatus('starting')
    
    try {
      const collectFlags: Record<string, { collect_registry?: boolean; collect_prefetch?: boolean; collect_shimcache?: boolean; collect_amcache?: boolean; collect_userassist?: boolean; collect_tasks?: boolean; collect_logs?: boolean }> = {
        'registry': { collect_registry: true },
        'prefetch': { collect_prefetch: true },
        'shimcache': { collect_shimcache: true },
        'amcache': { collect_amcache: true },
        'userassist': { collect_userassist: true },
        'tasks': { collect_tasks: true },
        'eventlogs': { collect_logs: true },
      }
      
      for (const type of selectedTypes) {
        setCollectStatus(`collecting:${type}`)
        const flags = collectFlags[type] || {}
        await forensicsAPI.collect({
          type: type,
          output_path: `/tmp/forensics_${type}`,
          ...flags
        })
      }
      fetchEvidence()
      fetchChainOfCustody()
      setCollectStatus('completed')
    } catch (error) {
      console.error('Collection failed:', error)
      setCollectStatus('error')
    } finally {
      setCollecting(false)
    }
  }

  const handleVerify = async () => {
    if (!hashInput.trim() || !filePath.trim()) return
    
    setVerifying(true)
    setHashResult(null)
    try {
      const res = await forensicsAPI.verifyHash(filePath, hashInput)
      setHashResult({
        verified: res.data.match || false,
        expected: hashInput,
        actual: res.data.hash || hashInput,
        path: filePath
      })
    } catch (error: any) {
      setHashResult({
        verified: false,
        expected: hashInput,
        actual: error.response?.data?.error || 'Hash verification failed',
        path: filePath
      })
    } finally {
      setVerifying(false)
    }
  }

  const toggleType = (type: string) => {
    setSelectedTypes(prev => 
      prev.includes(type) 
        ? prev.filter(t => t !== type)
        : [...prev, type]
    )
  }

  const handleViewEvidence = async (item: EvidenceItem) => {
    try {
      const res = await forensicsAPI.getEvidence(item.evidence_id)
      if (res.data.content) {
        const newWindow = window.open('', '_blank')
        if (newWindow) {
          newWindow.document.write(`<pre>${JSON.stringify(res.data, null, 2)}</pre>`)
          newWindow.document.close()
        }
      } else {
        alert('Evidence content not available')
      }
    } catch (error) {
      console.error('Failed to view evidence:', error)
      alert('Failed to view evidence')
    }
  }

  const handleExportEvidence = async (item: EvidenceItem) => {
    try {
      const res = await forensicsAPI.exportEvidence(item.evidence_id, 'json')
      const blob = new Blob([res.data], { type: res.headers['content-type'] || 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `evidence_${item.action}_${item.evidence_id}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to export evidence:', error)
      alert('Failed to export evidence')
    }
  }

  return (
    <div className="forensics-page">
      <h2>{t('forensics.title')}</h2>
      
      <div className="forensics-grid">
        <div className="forensics-card">
          <h3>{t('forensics.evidenceCollection')}</h3>
          <p className="card-desc">{t('forensics.evidenceCollectionDesc')}</p>
          
          <div className="collection-types">
            <div className="type-item" onClick={() => toggleType('eventlogs')}>
              <div className={`type-checkbox ${selectedTypes.includes('eventlogs') ? 'checked' : ''}`}>
                {selectedTypes.includes('eventlogs') && '✓'}
              </div>
              <div className="type-icon">📋</div>
              <div className="type-info">
                <div className="type-name">{t('forensics.eventLogs')}</div>
                <div className="type-desc">Security, System, Application</div>
              </div>
            </div>
            
            <div className="type-item" onClick={() => toggleType('registry')}>
              <div className={`type-checkbox ${selectedTypes.includes('registry') ? 'checked' : ''}`}>
                {selectedTypes.includes('registry') && '✓'}
              </div>
              <div className="type-icon">🔧</div>
              <div className="type-info">
                <div className="type-name">{t('forensics.registry')}</div>
                <div className="type-desc">Persistence points, Run keys</div>
              </div>
            </div>
            
            <div className="type-item" onClick={() => toggleType('memory')}>
              <div className={`type-checkbox ${selectedTypes.includes('memory') ? 'checked' : ''}`}>
                {selectedTypes.includes('memory') && '✓'}
              </div>
              <div className="type-icon">💾</div>
              <div className="type-info">
                <div className="type-name">{t('forensics.memoryDump')}</div>
                <div className="type-desc">Live memory acquisition</div>
              </div>
            </div>
            
            <div className="type-item" onClick={() => toggleType('prefetch')}>
              <div className={`type-checkbox ${selectedTypes.includes('prefetch') ? 'checked' : ''}`}>
                {selectedTypes.includes('prefetch') && '✓'}
              </div>
              <div className="type-icon">⚡</div>
              <div className="type-info">
                <div className="type-name">{t('forensics.prefetch')}</div>
                <div className="type-desc">Program execution history</div>
              </div>
            </div>
          </div>

          {collectStatus && (
            <div className={`collect-status ${collectStatus}`}>
              {collectStatus === 'starting' && '📡 Initializing collection...'}
              {collectStatus.startsWith('collecting:') && `🔍 Collecting ${collectStatus.split(':')[1]}...`}
              {collectStatus === 'completed' && '✅ Collection completed'}
              {collectStatus === 'error' && '❌ Collection failed'}
            </div>
          )}

          <button 
            className="btn-primary forensics-btn" 
            onClick={handleCollect} 
            disabled={collecting || selectedTypes.length === 0}
          >
            {collecting ? (
              <>
                <span className="btn-spinner"></span>
                Collecting...
              </>
            ) : (
              <>🚀 {t('forensics.startCollection')}</>
            )}
          </button>
        </div>

        <div className="forensics-card">
          <h3>{t('forensics.hashVerification')}</h3>
          <p className="card-desc">{t('forensics.hashVerificationDesc')}</p>
          
          <div className="hash-form">
            <div className="form-group">
              <label>File Path</label>
              <input
                type="text"
                placeholder="C:\Windows\System32\cmd.exe"
                value={filePath}
                onChange={e => setFilePath(e.target.value)}
              />
            </div>
            
            <div className="form-group">
              <label>Expected SHA256 Hash</label>
              <input
                type="text"
                placeholder="e3b0c44298fc1c149afbf4c8996fb924..."
                value={hashInput}
                onChange={e => setHashInput(e.target.value)}
              />
            </div>
            
            <button 
              className="btn-secondary" 
              onClick={handleCalculateHash}
              disabled={calculatingHash || !filePath.trim()}
            >
              {calculatingHash ? 'Calculating...' : 'Calculate Hash'}
            </button>
            <button 
              className="btn-secondary" 
              onClick={handleVerify}
              disabled={verifying || !hashInput.trim() || !filePath.trim()}
            >
              {verifying ? 'Verifying...' : t('forensics.verify')}
            </button>
          </div>

          {hashResult && (
            <div className={`hash-result ${hashResult.verified ? 'match' : 'no-match'}`}>
              <div className="result-icon">{hashResult.verified ? '✅' : '❌'}</div>
              <div className="result-content">
                <div className="result-title">
                  {hashResult.verified ? t('forensics.hashMatch') : t('forensics.hashNoMatch')}
                </div>
                <div className="result-details">
                  <div><strong>File:</strong> {hashResult.path}</div>
                  <div><strong>Expected:</strong> <code>{hashResult.expected.substring(0, 20)}...</code></div>
                  <div><strong>Actual:</strong> <code>{hashResult.actual.substring(0, 20)}...</code></div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="forensics-card full-width">
        <div className="section-header">
          <div>
            <h3>{t('forensics.chainOfCustody')}</h3>
            <p className="card-desc">{t('forensics.chainOfCustodyDesc')}</p>
          </div>
          <button className="btn-secondary" onClick={() => setShowChainModal(true)}>
            View Full Chain
          </button>
        </div>
        
        {evidence.length > 0 ? (
          <div className="evidence-table">
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Collected At</th>
                  <th>Path</th>
                  <th>Size</th>
                  <th>Hash</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map(item => (
                  <tr key={item.evidence_id}>
                    <td><span className="evidence-type">{item.action || 'N/A'}</span></td>
                    <td>{new Date(item.timestamp).toLocaleString()}</td>
                    <td><code className="evidence-path">{item.evidence_id}</code></td>
                    <td>{item.file_count || 0} files</td>
                    <td><code className="evidence-hash">{item.operator || 'N/A'}</code></td>
                    <td>
                      <button className="btn-small" onClick={() => handleViewEvidence(item)}>View</button>
                      <button className="btn-small" onClick={() => handleExportEvidence(item)}>Export</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div className="empty-icon">📦</div>
            <div className="empty-text">{t('forensics.noEvidence')}</div>
            <div className="empty-hint">Collect evidence using the form above</div>
          </div>
        )}
      </div>

      {showChainModal && (
        <div className="modal-overlay" onClick={() => setShowChainModal(false)}>
          <div className="modal-content chain-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{t('forensics.chainOfCustody')}</h3>
              <button className="close-btn" onClick={() => setShowChainModal(false)}>×</button>
            </div>
            <div className="modal-body">
              {chainOfCustody.length > 0 ? (
                <div className="chain-timeline">
                  {chainOfCustody.map((entry, index) => (
                    <div key={entry.id} className="chain-entry">
                      <div className="chain-dot">{index + 1}</div>
                      <div className="chain-content">
                        <div className="chain-action">{entry.action}</div>
                        <div className="chain-details">
                          {entry.input_hash && <div>Input Hash: {entry.input_hash}</div>}
                          {entry.output_hash && <div>Output Hash: {entry.output_hash}</div>}
                          {entry.previous_hash && <div>Previous Hash: {entry.previous_hash}</div>}
                        </div>
                        <div className="chain-meta">
                          <span className="chain-time">{new Date(entry.timestamp).toLocaleString()}</span>
                          {entry.operator && <span className="chain-user">by {entry.operator}</span>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-icon">📋</div>
                  <div className="empty-text">No chain of custody records</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <style>{`
        .forensics-page h2 {
          font-size: 1.8rem;
          color: #00d9ff;
          margin-bottom: 24px;
        }
        
        .forensics-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 20px;
          margin-bottom: 20px;
        }
        
        .forensics-card {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          padding: 24px;
          border: 1px solid #333;
        }
        
        .forensics-card.full-width {
          grid-column: 1 / -1;
        }
        
        .forensics-card h3 {
          color: #00d9ff;
          font-size: 1.2rem;
          margin-bottom: 8px;
        }
        
        .card-desc {
          color: #888;
          font-size: 0.85rem;
          margin-bottom: 20px;
        }
        
        .collection-types {
          display: flex;
          flex-direction: column;
          gap: 12px;
          margin-bottom: 20px;
        }
        
        .type-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          background: rgba(0, 0, 0, 0.2);
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.2s;
          border: 1px solid transparent;
        }
        
        .type-item:hover {
          background: rgba(0, 217, 255, 0.05);
          border-color: rgba(0, 217, 255, 0.2);
        }
        
        .type-checkbox {
          width: 24px;
          height: 24px;
          border-radius: 6px;
          border: 2px solid #444;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 14px;
          color: #00d9ff;
          transition: all 0.2s;
        }
        
        .type-checkbox.checked {
          background: #00d9ff;
          border-color: #00d9ff;
          color: #1a1a2e;
        }
        
        .type-icon {
          font-size: 1.5rem;
        }
        
        .type-name {
          color: #eee;
          font-weight: 500;
        }
        
        .type-desc {
          color: #666;
          font-size: 0.8rem;
        }
        
        .collect-status {
          padding: 12px 16px;
          border-radius: 8px;
          margin-bottom: 16px;
          font-size: 0.9rem;
        }
        
        .collect-status.starting, .collect-status.completed {
          background: rgba(34, 197, 94, 0.1);
          border: 1px solid rgba(34, 197, 94, 0.3);
          color: #22c55e;
        }
        
        .collect-status.error {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
          color: #ef4444;
        }
        
        .collect-status.collecting {
          background: rgba(0, 217, 255, 0.1);
          border: 1px solid rgba(0, 217, 255, 0.3);
          color: #00d9ff;
        }
        
        .btn-primary.forensics-btn {
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
        
        .hash-form {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }
        
        .form-group {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }
        
        .form-group label {
          color: #888;
          font-size: 0.85rem;
        }
        
        .form-group input {
          padding: 12px;
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid #333;
          border-radius: 6px;
          color: #eee;
          font-size: 0.9rem;
          font-family: monospace;
        }
        
        .form-group input:focus {
          outline: none;
          border-color: #00d9ff;
        }
        
        .hash-result {
          display: flex;
          gap: 16px;
          padding: 16px;
          border-radius: 8px;
          margin-top: 16px;
        }
        
        .hash-result.match {
          background: rgba(34, 197, 94, 0.1);
          border: 1px solid rgba(34, 197, 94, 0.3);
        }
        
        .hash-result.no-match {
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .result-icon {
          font-size: 2rem;
        }
        
        .result-title {
          font-size: 1.1rem;
          font-weight: 600;
          margin-bottom: 8px;
        }
        
        .hash-result.match .result-title { color: #22c55e; }
        .hash-result.no-match .result-title { color: #ef4444; }
        
        .result-details {
          font-size: 0.85rem;
          color: #888;
        }
        
        .result-details code {
          font-family: monospace;
          color: #00d9ff;
        }
        
        .evidence-table {
          overflow-x: auto;
        }
        
        .evidence-table table {
          width: 100%;
          border-collapse: collapse;
        }
        
        .evidence-table th,
        .evidence-table td {
          padding: 12px 16px;
          text-align: left;
          border-bottom: 1px solid #333;
        }
        
        .evidence-table th {
          background: rgba(0, 0, 0, 0.2);
          color: #00d9ff;
          font-weight: 600;
          font-size: 0.85rem;
          text-transform: uppercase;
        }
        
        .evidence-table tr:hover {
          background: rgba(0, 217, 255, 0.05);
        }
        
        .evidence-type {
          background: rgba(0, 217, 255, 0.1);
          color: #00d9ff;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 0.85rem;
        }
        
        .evidence-path {
          font-family: monospace;
          font-size: 0.85rem;
          color: #10b981;
        }
        
        .evidence-hash {
          font-family: monospace;
          font-size: 0.85rem;
          color: #f59e0b;
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

        .section-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 16px;
        }

        .section-header h3 {
          margin-bottom: 4px;
        }

        .section-header .btn-secondary {
          padding: 8px 16px;
        }

        .chain-modal {
          max-width: 700px;
          max-height: 80vh;
          overflow-y: auto;
        }

        .chain-timeline {
          position: relative;
          padding-left: 30px;
        }

        .chain-timeline::before {
          content: '';
          position: absolute;
          left: 10px;
          top: 0;
          bottom: 0;
          width: 2px;
          background: #333;
        }

        .chain-entry {
          position: relative;
          margin-bottom: 24px;
        }

        .chain-dot {
          position: absolute;
          left: -34px;
          top: 0;
          width: 24px;
          height: 24px;
          background: #00d9ff;
          color: #1a1a2e;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: 600;
          font-size: 0.8rem;
        }

        .chain-content {
          background: rgba(0, 0, 0, 0.2);
          border-radius: 8px;
          padding: 12px 16px;
          border: 1px solid #333;
        }

        .chain-action {
          color: #fff;
          font-weight: 600;
          margin-bottom: 4px;
        }

        .chain-details {
          color: #888;
          font-size: 0.9rem;
          margin-bottom: 8px;
        }

        .chain-meta {
          display: flex;
          gap: 16px;
          font-size: 0.8rem;
          color: #666;
        }

        .chain-user {
          color: #00d9ff;
        }
      `}</style>
    </div>
  )
}

export default Forensics