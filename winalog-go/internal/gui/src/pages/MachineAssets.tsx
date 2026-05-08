import { useEffect, useState } from 'react'
import { assetsAPI } from '../api'

interface MachineAsset {
  id: string
  name: string
  ip: string
  domain: string
  role: string
  os_version: string
  importance: string
  source: string
  last_seen: string
}

export default function MachineAssets() {
  const [assets, setAssets] = useState<MachineAsset[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  const [showImport, setShowImport] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)

  useEffect(() => {
    fetchAssets()
  }, [search, roleFilter])

  const fetchAssets = () => {
    setLoading(true)
    assetsAPI.list({ keyword: search, role: roleFilter })
      .then(res => {
        setAssets(res.data.assets || [])
        setLoading(false)
      })
      .catch(() => {
        setAssets([])
        setLoading(false)
      })
  }

  const handleSyncDiscovery = () => {
    if (!confirm('同步发现将把日志中出现的主机名添加到资产列表。继续？')) {
      return
    }
    assetsAPI.sync()
      .then(res => {
        alert(`同步完成，发现 ${res.data.discovered || 0} 台新机器`)
        fetchAssets()
      })
      .catch(err => {
        alert(err.message || '同步失败')
      })
  }

  const handleDelete = (id: string) => {
    if (!confirm('确认删除此资产？此操作不可恢复。')) {
      return
    }
    assetsAPI.delete(id)
      .then(() => {
        fetchAssets()
      })
      .catch(err => {
        alert(err.message || '删除失败')
      })
  }

  const handleImport = () => {
    if (!selectedFile) {
      alert('请选择 CSV 文件')
      return
    }

    const formData = new FormData()
    formData.append('file', selectedFile)

    assetsAPI.import(formData)
      .then(res => {
        alert(`导入完成: 成功 ${res.data.success}, 失败 ${res.data.failed}`)
        setShowImport(false)
        setSelectedFile(null)
        fetchAssets()
      })
      .catch(err => {
        alert(err.message || '导入失败')
      })
  }

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'dc': return 'var(--color-danger)'
      case 'server': return 'var(--color-warning)'
      case 'workstation': return 'var(--color-primary)'
      default: return '#888'
    }
  }

  return (
    <div className="machine-assets-page">
      <div className="page-header">
        <h2>机器资产管理</h2>
        <div className="header-actions">
          <button className="btn btn-primary" onClick={() => setShowImport(true)}>导入资产</button>
          <button className="btn btn-secondary" onClick={handleSyncDiscovery}>同步日志发现</button>
          <button className="btn btn-refresh" onClick={fetchAssets}>刷新</button>
        </div>
      </div>

      <div className="filters">
        <input
          type="text"
          className="search-input"
          placeholder="搜索主机名、IP或域..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select value={roleFilter} onChange={e => setRoleFilter(e.target.value)} className="filter-select">
          <option value="">所有角色</option>
          <option value="dc">域控 (DC)</option>
          <option value="server">服务器</option>
          <option value="workstation">工作站</option>
          <option value="unknown">未知</option>
        </select>
      </div>

      {loading ? (
        <div className="loading-state">
          <div className="spinner"></div>
          <div>加载中...</div>
        </div>
      ) : (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>主机名</th>
                <th>IP 地址</th>
                <th>域</th>
                <th>角色</th>
                <th>重要性</th>
                <th>来源</th>
                <th>最后活跃</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {assets.map(asset => (
                <tr key={asset.id}>
                  <td className="highlight">{asset.name}</td>
                  <td className="mono">{asset.ip || '-'}</td>
                  <td>{asset.domain || '-'}</td>
                  <td>
                    <span className="badge" style={{ backgroundColor: getRoleColor(asset.role) }}>
                      {asset.role.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${asset.importance}`}>
                      {asset.importance === 'high' ? '高' : asset.importance === 'medium' ? '中' : '低'}
                    </span>
                  </td>
                  <td>
                    {asset.source === 'manual' ? '手动导入' : '日志发现'}
                  </td>
                  <td className="mono">
                    {asset.last_seen ? new Date(asset.last_seen).toLocaleString() : '-'}
                  </td>
                  <td>
                    <button 
                      className="btn btn-danger btn-sm" 
                      onClick={() => handleDelete(asset.id)}
                    >
                      删除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {assets.length === 0 && (
            <div className="empty-state">
              暂无机器资产数据。请导入资产清单或点击“同步日志发现”。
            </div>
          )}
        </div>
      )}

      {showImport && (
        <div className="modal-overlay" onClick={() => setShowImport(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <h3>导入机器资产 (CSV)</h3>
            <p>格式：主机名, IP, 域, 角色(dc/server/workstation), 操作系统, 重要性(high/medium/low)</p>
            <input 
              type="file" 
              accept=".csv"
              onChange={e => setSelectedFile(e.target.files?.[0] || null)}
              className="file-input"
            />
            <div className="modal-actions">
              <button className="btn" onClick={() => setShowImport(false)}>取消</button>
              <button className="btn btn-primary" onClick={handleImport}>上传并导入</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
