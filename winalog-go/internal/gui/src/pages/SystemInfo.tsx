import { useEffect, useState } from 'react'
import { useI18n } from '../locales/I18n'
import { systemAPI } from '../api'
import { message } from 'antd'

const safeSetItem = (key: string, value: string) => {
  try {
    localStorage.setItem(key, value)
  } catch (e) {
    console.warn(`localStorage write failed for ${key}:`, e)
    try { localStorage.removeItem(key) } catch {}
  }
}

const safeGetItem = (key: string): string | null => {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}

interface SystemInfoData {
  hostname: string
  domain: string
  os_name: string
  os_version: string
  architecture: string
  is_admin: boolean
  timezone: string
  local_time: string
  uptime_seconds: number
  go_version: string
  cpu_count: number
  memory_total_gb: number
  memory_free_gb: number
}

interface ProcessInfo {
  pid: number
  ppid: number
  name: string
  exe: string
  args: string
  user: string
  status: string
  path: string
  command_line: string
  is_signed: boolean
  is_elevated: boolean
  cpu_percent: number
  memory_mb: number
  start_time: string
  hash_sha256: string
  signature?: {
    status: string
    issuer: string
    subject: string
    valid_from: string
    valid_to: string
    thumbprint: string
  }
}

interface NetworkConnInfo {
  pid: number
  protocol: string
  local_addr: string
  local_port: number
  remote_addr: string
  remote_port: number
  state: string
  process_name: string
}

interface RegistryKeyInfo {
  path: string
  name: string
  value: string
  type: string
  source: string
  enabled: boolean
  description?: string
  display_name?: string
  image_path?: string
  debugger?: string
  dll_name?: string
}

interface UserAccountInfo {
  sid: string
  name: string
  domain: string
  full_name: string
  type: string
  enabled: boolean
  last_login: string
  password_expires: boolean
  home_dir: string
  profile_path: string
}

interface DriverInfo {
  name: string
  display_name: string
  description: string
  type: string
  status: string
  started: boolean
  path: string
  hash_sha256: string
  signature: string
  signer: string
}

interface DllInfo {
  process_id: number
  process_name: string
  name: string
  path: string
  size: number
  version: string
  is_signed: boolean
  signer: string
}

interface TaskInfo {
  name: string
  path: string
  state: string
  author?: string
  description?: string
  next_run_time?: string
  last_run_time?: string
  last_result?: number
  run_as_user?: string
  action?: string
  trigger_type?: string
}

function SystemInfo() {
  const { t } = useI18n()
  const [activeTab, setActiveTab] = useState<'system' | 'processes' | 'network' | 'env' | 'dlls' | 'drivers' | 'users' | 'registry' | 'startup' | 'tasks' | 'services' | 'runkeys' | 'userinit'>('system')
  const [info, setInfo] = useState<SystemInfoData | null>(null)
  const [processes, setProcesses] = useState<ProcessInfo[]>([])
  const [networkConnections, setNetworkConnections] = useState<NetworkConnInfo[]>([])
  const [envVars, setEnvVars] = useState<any[]>([])
  const [dlls, setDlls] = useState<DllInfo[]>([])
  const [drivers, setDrivers] = useState<DriverInfo[]>([])
  const [users, setUsers] = useState<UserAccountInfo[]>([])
  const [registry, setRegistry] = useState<RegistryKeyInfo[]>([])
  const [startupFolders, setStartupFolders] = useState<RegistryKeyInfo[]>([])
  const [tasks, setTasks] = useState<TaskInfo[]>([])
  const [services, setServices] = useState<RegistryKeyInfo[]>([])
  const [runKeys, setRunKeys] = useState<RegistryKeyInfo[]>([])
  const [userInit, setUserInit] = useState<RegistryKeyInfo[]>([])
  const [selectedDllPid, setSelectedDllPid] = useState<number | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [moduleErrors, setModuleErrors] = useState<Record<string, string>>({})
  const [enabledModules, setEnabledModules] = useState<Record<string, boolean>>(() => {
    const saved = safeGetItem('systeminfo_enabled_modules')
    if (saved) {
      try {
        return JSON.parse(saved)
      } catch {
        // ignore parse errors
      }
    }
    return {
      processes: false,
      network: false,
      dlls: false,
      drivers: false,
      env: false,
      users: false,
      registry: false,
      tasks: false,
    }
  })
  const [showUnsignedOnly, setShowUnsignedOnly] = useState(false)
  const [showExportMenu, setShowExportMenu] = useState(false)

  useEffect(() => {
    safeSetItem('systeminfo_enabled_modules', JSON.stringify(enabledModules))
  }, [enabledModules])

  useEffect(() => {
    fetchSystemInfo()
  }, [])

  useEffect(() => {
    if (enabledModules.processes && processes.length === 0) {
      fetchProcesses()
    }
    if (enabledModules.network && networkConnections.length === 0) {
      fetchNetwork()
    }
    if (enabledModules.dlls && dlls.length === 0) {
      fetchDlls()
    }
    if (enabledModules.drivers && drivers.length === 0) {
      fetchDrivers()
    }
    if (enabledModules.users && users.length === 0) {
      fetchUsers()
    }
    if (enabledModules.registry && registry.length === 0) {
      fetchRegistry()
    }
    if (enabledModules.tasks && tasks.length === 0) {
      fetchTasks()
    }
  }, [enabledModules])

  const fetchSystemInfo = () => {
    setLoading(true)
    systemAPI.getInfo()
      .then(res => {
        setInfo(res.data)
        setLoading(false)
      })
      .catch(err => {
        setError(err.message || t('common.error'))
        setLoading(false)
      })
  }

  const fetchProcesses = () => {
    const enabled = enabledModules.processes
    if (!enabled) {
      setProcesses([])
      return
    }
    setLoading(true)
    systemAPI.getProcesses(10000, enabled)
      .then(res => {
        const data = res.data.processes || []
        setProcesses(data)
        safeSetItem('systeminfo_processes', JSON.stringify(data))
        setModuleErrors(m => ({ ...m, processes: '' }))
        setLoading(false)
      })
      .catch((err: any) => {
        const msg = err.response?.status === 404
          ? '进程信息不可用（仅支持 Windows）'
          : (err.message || '获取进程信息失败')
        setModuleErrors(m => ({ ...m, processes: msg }))
        setLoading(false)
      })
  }

  const fetchNetwork = () => {
    const enabled = enabledModules.network
    if (!enabled) {
      setNetworkConnections([])
      return
    }
    setLoading(true)
    systemAPI.getNetwork(10000, enabled)
      .then(res => {
        const data = res.data.connections || []
        setNetworkConnections(data)
        safeSetItem('systeminfo_network', JSON.stringify(data))
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const fetchEnvVars = () => {
    if (envVars.length > 0) return
    setLoading(true)
    systemAPI.getEnvVariables()
      .then(res => {
        setEnvVars(res.data.variables || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const fetchDlls = (pid?: number) => {
    const enabled = enabledModules.dlls
    if (!enabled) {
      setDlls([])
      return
    }
    setLoading(true)
    if (pid) {
      setSelectedDllPid(pid)
      systemAPI.getProcessDLLs(pid)
        .then(res => {
          const data = res.data.dlls || []
          setDlls(data)
          safeSetItem('systeminfo_dlls', JSON.stringify(data))
          setLoading(false)
        })
        .catch(() => setLoading(false))
    } else {
      systemAPI.getLoadedDLLs(100000, enabled)
        .then(res => {
          const data = res.data.modules || []
          setDlls(data)
          safeSetItem('systeminfo_dlls', JSON.stringify(data))
          setLoading(false)
        })
        .catch(() => setLoading(false))
    }
  }

  const fetchDrivers = () => {
    const enabled = enabledModules.drivers
    if (!enabled) {
      setDrivers([])
      return
    }
    setLoading(true)
    systemAPI.getDrivers(enabled)
      .then(res => {
        const data = res.data.drivers || []
        setDrivers(data)
        safeSetItem('systeminfo_drivers', JSON.stringify(data))
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const fetchUsers = () => {
    const enabled = enabledModules.users
    if (!enabled) {
      setUsers([])
      return
    }
    setLoading(true)
    systemAPI.getUsers(enabled)
      .then(res => {
        const data = res.data.users || []
        setUsers(data)
        safeSetItem('systeminfo_users', JSON.stringify(data))
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const fetchRegistry = () => {
    const enabled = enabledModules.registry
    if (!enabled) {
      setRegistry([])
      return
    }
    setLoading(true)
    systemAPI.getRegistry(enabled)
      .then(res => {
        const data = res.data
        const allKeys = [
          ...(data.run_keys || []),
          ...(data.services || []),
          ...(data.ifeo || []),
          ...(data.app_init_dlls || []),
          ...(data.known_dlls || []),
          ...(data.boot_execute || []),
          ...(data.appcert_dlls || []),
          ...(data.lsa_settings || []),
          ...(data.shell_extensions || []),
          ...(data.browser_helpers || []),
        ]
        setRegistry(allKeys)
        safeSetItem('systeminfo_registry', JSON.stringify(allKeys))
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const fetchStartupFolders = () => {
    const enabled = enabledModules.registry
    if (!enabled) {
      setStartupFolders([])
      return
    }
    setLoading(true)
    systemAPI.getRegistry(enabled)
      .then(res => {
        setStartupFolders(res.data.startup_folders || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const fetchTasks = () => {
    const enabled = enabledModules.tasks
    if (!enabled) {
      setTasks([])
      return
    }
    setLoading(true)
    systemAPI.getTasks(enabled)
      .then(res => {
        const data = res.data.tasks || []
        setTasks(data)
        safeSetItem('systeminfo_tasks', JSON.stringify(data))
        setLoading(false)
      })
      .catch((err: any) => {
        const msg = err.response?.status === 404
          ? '计划任务信息不可用（仅支持 Windows）'
          : (err.message || '获取计划任务失败')
        setModuleErrors(m => ({ ...m, tasks: msg }))
        setLoading(false)
      })
  }

  const fetchServices = () => {
    const enabled = enabledModules.registry
    if (!enabled) {
      setServices([])
      return
    }
    if (services.length > 0) return
    setLoading(true)
    systemAPI.getRegistry(enabled)
      .then(res => {
        setServices(res.data.services || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const fetchRunKeys = () => {
    const enabled = enabledModules.registry
    if (!enabled) {
      setRunKeys([])
      return
    }
    if (runKeys.length > 0) return
    setLoading(true)
    systemAPI.getRegistry(enabled)
      .then(res => {
        setRunKeys(res.data.run_keys || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const fetchUserInit = () => {
    const enabled = enabledModules.registry
    if (!enabled) {
      setUserInit([])
      return
    }
    if (userInit.length > 0) return
    setLoading(true)
    systemAPI.getRegistry(enabled)
      .then(res => {
        setUserInit(res.data.user_init || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  const handleTabChange = (tab: 'system' | 'processes' | 'network' | 'env' | 'dlls' | 'drivers' | 'users' | 'registry' | 'startup' | 'tasks' | 'services' | 'runkeys' | 'userinit') => {
    setActiveTab(tab)
    if (tab === 'processes' && enabledModules.processes) fetchProcesses()
    if (tab === 'network' && enabledModules.network) fetchNetwork()
    if (tab === 'env' && enabledModules.env) fetchEnvVars()
    if (tab === 'dlls' && enabledModules.dlls) {
      if (processes.length > 0 && !selectedDllPid) {
      } else if (selectedDllPid) {
        fetchDlls(selectedDllPid)
      } else {
        fetchDlls()
      }
    }
    if (tab === 'drivers' && enabledModules.drivers) fetchDrivers()
    if (tab === 'users' && enabledModules.users) fetchUsers()
    if (tab === 'registry' && enabledModules.registry) fetchRegistry()
    if (tab === 'startup' && enabledModules.registry) fetchStartupFolders()
    if (tab === 'tasks' && enabledModules.tasks) fetchTasks()
    if (tab === 'services' && enabledModules.registry) fetchServices()
    if (tab === 'runkeys' && enabledModules.registry) fetchRunKeys()
    if (tab === 'userinit' && enabledModules.registry) fetchUserInit()
  }

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    if (days > 0) return `${days}d ${hours}h ${mins}m`
    if (hours > 0) return `${hours}h ${mins}m`
    return `${mins}m`
  }

  const getStateColor = (state: string) => {
    switch (state?.toUpperCase()) {
      case 'ESTABLISHED': return '#22c55e'
      case 'LISTEN': return '#3b82f6'
      case 'TIME_WAIT': return '#f59e0b'
      case 'CLOSE_WAIT': return '#ef4444'
      default: return '#888'
    }
  }

  const exportToCSV = (data: any[], filename: string, headers: string[]) => {
    if (data.length === 0) {
      message.warning('请先启用并加载数据后再导出')
      return
    }
    const csvContent = [
      headers.join(','),
      ...data.map(row => headers.map(h => {
        const value = row[h] ?? ''
        const str = String(value)
        return str.includes(',') || str.includes('"') || str.includes('\n') 
          ? `"${str.replace(/"/g, '""')}"` 
          : str
      }).join(','))
    ].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${filename}_${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
    URL.revokeObjectURL(url)
    setShowExportMenu(false)
  }

  const handleExport = (type: string) => {
    switch (type) {
      case 'processes':
        exportToCSV(processes, 'processes', ['pid', 'ppid', 'name', 'user', 'exe', 'command_line', 'is_signed'])
        break
      case 'network':
        exportToCSV(networkConnections, 'network', ['protocol', 'local_addr', 'local_port', 'remote_addr', 'remote_port', 'state', 'pid', 'process_name'])
        break
      case 'dlls':
        exportToCSV(dlls, 'dlls', ['process_id', 'process_name', 'name', 'path', 'size', 'version', 'is_signed'])
        break
      case 'drivers':
        exportToCSV(drivers, 'drivers', ['name', 'display_name', 'description', 'path', 'status'])
        break
      case 'users':
        exportToCSV(users, 'users', ['name', 'sid', 'enabled', 'full_name', 'type'])
        break
      case 'registry':
        exportToCSV(registry, 'registry', ['path', 'name', 'value', 'type'])
        break
      case 'tasks':
        exportToCSV(tasks, 'tasks', ['name', 'path', 'state'])
        break
      case 'env':
        exportToCSV(envVars, 'env_variables', ['name', 'value', 'type'])
        break
    }
  }

  const handleExportFromBackend = (type: string) => {
    const url = `/api/system/${type}/export`
    window.open(url, '_blank')
    setShowExportMenu(false)
  }

  if (loading && !info) return (
    <div className="systeminfo-page">
      <div className="loading-state">
        <div className="spinner"></div>
        <div>{t('common.loading')}</div>
      </div>
    </div>
  )

  if (error) return (
    <div className="systeminfo-page">
      <div className="error-state">Error: {error}</div>
    </div>
  )

  return (
    <div className="systeminfo-page">
      <div className="page-header">
        <h2>{t('systemInfo.title')}</h2>
        <div className="header-actions">
          <button className="btn-refresh" onClick={fetchSystemInfo}>
            {t('common.refresh') || '刷新'}
          </button>
          {['processes', 'network', 'dlls', 'drivers', 'users', 'registry', 'tasks', 'env'].includes(activeTab) && (
            <div className="export-dropdown">
              <button className="btn-export" onClick={() => setShowExportMenu(!showExportMenu)}>
                {t('common.export') || '导出'} CSV
              </button>
              {showExportMenu && (
                <div className="export-menu">
                  {activeTab === 'processes' && (
                    <>
                      <button onClick={() => handleExport('processes')}>前端导出（已加载数据）</button>
                      <button onClick={() => handleExportFromBackend('processes')}>后端导出（完整数据）</button>
                    </>
                  )}
                  {activeTab === 'network' && (
                    <>
                      <button onClick={() => handleExport('network')}>前端导出（已加载数据）</button>
                      <button onClick={() => handleExportFromBackend('network')}>后端导出（完整数据）</button>
                    </>
                  )}
                  {activeTab === 'dlls' && (
                    <>
                      <button onClick={() => handleExport('dlls')}>前端导出（已加载数据）</button>
                      <button onClick={() => handleExportFromBackend('dlls')}>后端导出（完整数据）</button>
                    </>
                  )}
                  {activeTab === 'drivers' && (
                    <>
                      <button onClick={() => handleExport('drivers')}>前端导出（已加载数据）</button>
                      <button onClick={() => handleExportFromBackend('drivers')}>后端导出（完整数据）</button>
                    </>
                  )}
                  {activeTab === 'users' && (
                    <>
                      <button onClick={() => handleExport('users')}>前端导出（已加载数据）</button>
                      <button onClick={() => handleExportFromBackend('users')}>后端导出（完整数据）</button>
                    </>
                  )}
                  {activeTab === 'registry' && (
                    <>
                      <button onClick={() => handleExport('registry')}>前端导出（已加载数据）</button>
                      <button onClick={() => handleExportFromBackend('registry')}>后端导出（完整数据）</button>
                    </>
                  )}
                  {activeTab === 'tasks' && (
                    <>
                      <button onClick={() => handleExport('tasks')}>前端导出（已加载数据）</button>
                      <button onClick={() => handleExportFromBackend('tasks')}>后端导出（完整数据）</button>
                    </>
                  )}
                  {activeTab === 'env' && (
                    <>
                      <button onClick={() => handleExport('env')}>前端导出（已加载数据）</button>
                      <button onClick={() => handleExportFromBackend('env')}>后端导出（完整数据）</button>
                    </>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="tab-nav">
        <button
          className={`tab-btn ${activeTab === 'system' ? 'active' : ''}`}
          onClick={() => handleTabChange('system')}
        >
          {t('systemInfo.system') || '系统'}
        </button>
        <button
          className={`tab-btn ${activeTab === 'processes' ? 'active' : ''}`}
          onClick={() => handleTabChange('processes')}
        >
          <span className="tab-label">{t('systemInfo.processes') || '进程'} ({processes.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.processes}
              onChange={() => setEnabledModules(m => ({...m, processes: !m.processes}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'network' ? 'active' : ''}`}
          onClick={() => handleTabChange('network')}
        >
          <span className="tab-label">{t('systemInfo.network') || '网络'} ({networkConnections.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.network}
              onChange={() => setEnabledModules(m => ({...m, network: !m.network}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'env' ? 'active' : ''}`}
          onClick={() => handleTabChange('env')}
        >
          <span className="tab-label">{t('systemInfo.env') || '环境变量'} ({envVars.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.env}
              onChange={() => setEnabledModules(m => ({...m, env: !m.env}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'dlls' ? 'active' : ''}`}
          onClick={() => handleTabChange('dlls')}
        >
          <span className="tab-label">{t('systemInfo.dlls') || '动态链接库'} ({dlls.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.dlls}
              onChange={() => setEnabledModules(m => ({...m, dlls: !m.dlls}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'drivers' ? 'active' : ''}`}
          onClick={() => handleTabChange('drivers')}
        >
          <span className="tab-label">{t('systemInfo.drivers') || '驱动'} ({drivers.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.drivers}
              onChange={() => setEnabledModules(m => ({...m, drivers: !m.drivers}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
<button
          className={`tab-btn ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => handleTabChange('users')}
        >
          <span className="tab-label">{t('systemInfo.users') || '用户'} ({users.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.users}
              onChange={() => setEnabledModules(m => ({...m, users: !m.users}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'registry' ? 'active' : ''}`}
          onClick={() => handleTabChange('registry')}
        >
          <span className="tab-label">{t('systemInfo.registry') || '注册表'} ({registry.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.registry}
              onChange={() => setEnabledModules(m => ({...m, registry: !m.registry}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'startup' ? 'active' : ''}`}
          onClick={() => handleTabChange('startup')}
        >
          <span className="tab-label">{t('systemInfo.startupFolders') || '启动文件夹'} ({startupFolders.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.registry}
              onChange={() => setEnabledModules(m => ({...m, registry: !m.registry}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'tasks' ? 'active' : ''}`}
          onClick={() => handleTabChange('tasks')}
        >
          <span className="tab-label">{t('systemInfo.tasks') || '任务'} ({tasks.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.tasks}
              onChange={() => setEnabledModules(m => ({...m, tasks: !m.tasks}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'services' ? 'active' : ''}`}
          onClick={() => handleTabChange('services')}
        >
          <span className="tab-label">{t('systemInfo.services') || '服务'} ({services.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.registry}
              onChange={() => setEnabledModules(m => ({...m, registry: !m.registry}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'runkeys' ? 'active' : ''}`}
          onClick={() => handleTabChange('runkeys')}
        >
          <span className="tab-label">{t('systemInfo.runKeys') || '自启动'} ({runKeys.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.registry}
              onChange={() => setEnabledModules(m => ({...m, registry: !m.registry}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
        <button
          className={`tab-btn ${activeTab === 'userinit' ? 'active' : ''}`}
          onClick={() => handleTabChange('userinit')}
        >
          <span className="tab-label">{t('systemInfo.userInit') || '登录项'} ({userInit.length || '...'})</span>
          <label className="module-toggle" onClick={e => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={enabledModules.registry}
              onChange={() => setEnabledModules(m => ({...m, registry: !m.registry}))}
            />
            <span className="toggle-slider"></span>
          </label>
        </button>
      </div>

      {activeTab === 'system' && info && (
        <div className="system-grid">
          <div className="system-card os-card">
            <div className="card-header">
              <div className="card-icon">OS</div>
              <h3>{t('systemInfo.operatingSystem')}</h3>
            </div>
            
            <div className="system-status">
              <div className="status-indicator online"></div>
              <span>{t('systemInfo.systemOnline') || '系统在线'}</span>
            </div>
            
            <div className="info-list">
              <div className="info-row">
                <span className="info-label">{t('systemInfo.hostname')}</span>
                <span className="info-value highlight">{info.hostname || t('common.notAvailable') || 'N/A'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">{t('systemInfo.domain')}</span>
                <span className="info-value">{info.domain || 'WORKGROUP'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">{t('systemInfo.osName')}</span>
                <span className="info-value">{info.os_name || t('common.unknown') || 'Unknown'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">{t('systemInfo.osVersion')}</span>
                <span className="info-value">{info.os_version || t('common.unknown') || 'Unknown'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">{t('systemInfo.architecture')}</span>
                <span className="info-value badge">{info.architecture || 'x64'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">{t('systemInfo.timezone')}</span>
                <span className="info-value">{info.timezone || 'UTC'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">{t('systemInfo.admin')}</span>
                <span className={`info-value badge ${info.is_admin ? 'admin' : 'user'}`}>
                  {info.is_admin ? (t('systemInfo.adminUser') || '管理员') : (t('systemInfo.standardUser') || '标准用户')}
                </span>
              </div>
            </div>
          </div>

          <div className="system-card runtime-card">
            <div className="card-header">
              <div className="card-icon">{t('systemInfo.runtime') || '运行时'}</div>
              <h3>{t('systemInfo.runtimeInfo')}</h3>
            </div>
            
            <div className="info-list">
              <div className="info-row">
                <span className="info-label">{t('systemInfo.goVersion')}</span>
                <span className="info-value mono">{info.go_version || t('common.unknown') || 'Unknown'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">{t('systemInfo.cpuCount')}</span>
                <span className="info-value">{info.cpu_count || 0} {t('systemInfo.cores') || '核心'}</span>
              </div>
              <div className="info-row">
                <span className="info-label">{t('systemInfo.uptime')}</span>
                <span className="info-value">{formatUptime(info.uptime_seconds || 0)}</span>
              </div>
            </div>
          </div>

          <div className="system-card resources-card">
            <div className="card-header">
              <div className="card-icon">{t('systemInfo.resources') || '资源'}</div>
              <h3>{t('systemInfo.systemResources') || '系统资源'}</h3>
            </div>
            
            <div className="resource-bars">
              <div className="resource-item">
                <div className="resource-header">
                  <span className="resource-name">{t('systemInfo.memory') || '内存'}</span>
                  <span className="resource-value">
                    {info.memory_free_gb ? (info.memory_total_gb - info.memory_free_gb).toFixed(1) : '0'} / {info.memory_total_gb?.toFixed(1) || '0'} GB
                  </span>
                </div>
                <div className="resource-bar">
                  <div className="resource-fill" style={{
                    width: info.memory_total_gb ? `${((info.memory_total_gb - info.memory_free_gb) / info.memory_total_gb * 100)}%` : '0%'
                  }}></div>
                </div>
              </div>
              
              <div className="resource-item">
                <div className="resource-header">
                  <span className="resource-name">{t('systemInfo.freeMemory') || '可用内存'}</span>
                  <span className="resource-value">{info.memory_free_gb?.toFixed(1) || '0'} GB</span>
                </div>
                <div className="resource-bar">
                  <div className="resource-fill memory" style={{
                    width: info.memory_total_gb ? `${(info.memory_free_gb / info.memory_total_gb * 100)}%` : '0%'
                  }}></div>
                </div>
              </div>
            </div>
          </div>

          <div className="system-card time-card">
            <div className="card-header">
              <div className="card-icon">{t('systemInfo.time') || '时间'}</div>
              <h3>{t('systemInfo.timeInfo') || '时间信息'}</h3>
            </div>
            
            <div className="time-display">
              <div className="current-time">
                {info?.local_time ? new Date(info.local_time).toLocaleTimeString() : new Date().toLocaleTimeString()}
              </div>
              <div className="current-date">
                {info?.local_time ? new Date(info.local_time).toLocaleDateString() : new Date().toLocaleDateString()}
              </div>
            </div>
            
            <div className="info-list">
              <div className="info-row">
                <span className="info-label">UTC {t('systemInfo.time') || '时间'}</span>
                <span className="info-value mono">{new Date().toISOString()}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'processes' && (
        <div className="data-table-container">
          <div className="table-toolbar">
            <label className="unsigned-filter">
              <input
                type="checkbox"
                checked={showUnsignedOnly}
                onChange={() => setShowUnsignedOnly(!showUnsignedOnly)}
              />
              <span>{t('systemInfo.showUnsignedOnly') || '仅显示未签名（黄色高亮）'}</span>
            </label>
            <span className="process-count">
              {showUnsignedOnly 
                ? processes.filter(p => !p.is_signed).length 
                : processes.length} {t('systemInfo.processes') || '进程'}
              {!showUnsignedOnly && processes.filter(p => !p.is_signed).length > 0 && (
                <span className="unsigned-count">
                  ({processes.filter(p => !p.is_signed).length} {t('systemInfo.unsigned') || '未签名'})
                </span>
              )}
            </span>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.pid') || 'PID'}</th>
                <th>{t('systemInfo.ppid') || 'PPID'}</th>
                <th>{t('systemInfo.name') || '名称'}</th>
                <th>{t('systemInfo.user') || '用户'}</th>
                <th>{t('systemInfo.elevated') || '提权'}</th>
                <th>{t('systemInfo.cpuPercent') || 'CPU%'}</th>
                <th>{t('systemInfo.memoryMB') || '内存MB'}</th>
                <th>{t('systemInfo.startTime') || '启动时间'}</th>
                <th>{t('systemInfo.signature') || '签名'}</th>
              </tr>
            </thead>
            <tbody>
              {(showUnsignedOnly ? processes.filter(p => !p.is_signed) : processes).map((proc, idx) => (
                <tr key={`${proc.pid}-${idx}`} className={!proc.is_signed ? 'unsigned-process' : ''}>
                  <td className="mono">{proc.pid}</td>
                  <td className="mono">{proc.ppid || '-'}</td>
                  <td className="highlight">{proc.name}</td>
                  <td>{proc.user || '-'}</td>
                  <td>
                    {proc.is_elevated ? (
                      <span className="status-badge running">✓</span>
                    ) : (
                      <span className="status-badge stopped">-</span>
                    )}
                  </td>
                  <td className="mono">{proc.cpu_percent?.toFixed(1) || '0.0'}%</td>
                  <td className="mono">{proc.memory_mb?.toFixed(1) || '0.0'}</td>
                  <td className="mono">{proc.start_time ? new Date(proc.start_time).toLocaleString() : '-'}</td>
                  <td>
                    {proc.is_signed ? (
                      <span className="signature-badge valid" title={`Subject: ${proc.signature?.subject || 'N/A'}\nIssuer: ${proc.signature?.issuer || 'N/A'}\nThumbprint: ${proc.signature?.thumbprint || 'N/A'}\nValid: ${proc.signature?.valid_from || 'N/A'} ~ ${proc.signature?.valid_to || 'N/A'}`}>
                        ✓ {proc.signature?.subject || t('systemInfo.signed') || '已签名'}
                      </span>
                    ) : (
                      <span className="signature-badge unsigned">
                        ✗ {t('systemInfo.unsigned') || '未签名'}
                    </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {processes.length === 0 && !loading && (
            <div className="empty-state">
              {moduleErrors.processes ? (
                <span className="error-message">{moduleErrors.processes}</span>
              ) : (
                t('systemInfo.noProcessData') || '暂无进程数据'
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'network' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.protocol') || '协议'}</th>
                <th>{t('systemInfo.localAddress') || '本地地址'}</th>
                <th>{t('systemInfo.port') || '端口'}</th>
                <th>{t('systemInfo.remoteAddress') || '远程地址'}</th>
                <th>{t('systemInfo.port') || '端口'}</th>
                <th>{t('systemInfo.state') || '状态'}</th>
                <th>{t('systemInfo.pid') || 'PID'}</th>
                <th>{t('systemInfo.process') || '进程'}</th>
              </tr>
            </thead>
            <tbody>
              {networkConnections.map((conn, idx) => (
                <tr key={`${conn.protocol}-${conn.local_addr}-${conn.local_port}-${idx}`}>
                  <td><span className="protocol-badge">{conn.protocol}</span></td>
                  <td className="mono">{conn.local_addr}</td>
                  <td className="mono">{conn.local_port}</td>
                  <td className="mono">{conn.remote_addr || '-'}</td>
                  <td className="mono">{conn.remote_port || '-'}</td>
                  <td>
                    <span className="state-badge" style={{color: getStateColor(conn.state)}}>
                      {conn.state}
                    </span>
                  </td>
                  <td className="mono">{conn.pid || '-'}</td>
                  <td>{conn.process_name || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {networkConnections.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noNetworkData') || '暂无网络连接数据'}</div>
          )}
        </div>
      )}

      {activeTab === 'env' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.varName') || '变量名'}</th>
                <th>{t('systemInfo.value') || '值'}</th>
                <th>{t('systemInfo.type') || '类型'}</th>
              </tr>
            </thead>
            <tbody>
              {envVars.map((v, idx) => (
                <tr key={`${v.name}-${idx}`}>
                  <td className="mono highlight">{v.name}</td>
                  <td className="truncate" title={v.value}>{v.value}</td>
                  <td><span className="type-badge">{v.type}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {envVars.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noEnvVars') || '暂无环境变量'}</div>
          )}
        </div>
      )}

      {activeTab === 'dlls' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.pid') || 'PID'}</th>
                <th>{t('systemInfo.process') || '进程'}</th>
                <th>{t('systemInfo.dllName') || 'DLL名称'}</th>
                <th>{t('systemInfo.version') || '版本'}</th>
                <th>{t('systemInfo.signed') || '签名'}</th>
                <th>{t('systemInfo.path') || '路径'}</th>
                <th>{t('systemInfo.size') || '大小'}</th>
              </tr>
            </thead>
            <tbody>
              {dlls.map((dll, idx) => (
                <tr key={`${dll.process_id}-${dll.name}-${idx}`}>
                  <td className="mono">{dll.process_id}</td>
                  <td>{dll.process_name}</td>
                  <td className="mono highlight">{dll.name}</td>
                  <td className="mono">{dll.version || '-'}</td>
                  <td>
                    {dll.is_signed ? (
                      <span className="signature-badge signed" title={dll.signer || ''}>
                        ✓ {dll.signer || t('systemInfo.signed') || '已签名'}
                      </span>
                    ) : (
                      <span className="signature-badge unsigned">
                        ✗ {t('systemInfo.unsigned') || '未签名'}
                      </span>
                    )}
                  </td>
                  <td className="truncate" title={dll.path}>{dll.path}</td>
                  <td className="mono">{(dll.size / 1024).toFixed(1)} KB</td>
                </tr>
              ))}
            </tbody>
          </table>
          {dlls.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noDllData') || '暂无DLL信息'}</div>
          )}
        </div>
      )}

      {activeTab === 'drivers' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.name') || '名称'}</th>
                <th>{t('systemInfo.status') || '状态'}</th>
                <th>{t('systemInfo.type') || '类型'}</th>
                <th>{t('systemInfo.signer') || '签名者'}</th>
                <th>{t('systemInfo.path') || '路径'}</th>
              </tr>
            </thead>
            <tbody>
              {drivers.map((driver, idx) => (
                <tr key={`${driver.name}-${idx}`}>
                  <td className="mono highlight">{driver.name}</td>
                  <td>
                    <span className={`status-badge ${driver.status?.toLowerCase() === 'running' ? 'running' : 'stopped'}`}>
                      {driver.status || t('common.unknown')}
                    </span>
                  </td>
                  <td>{driver.type || '-'}</td>
                  <td className="truncate" title={driver.signer}>{driver.signer || '-'}</td>
                  <td className="truncate mono" title={driver.path}>{driver.path || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {drivers.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noDriverData') || '暂无驱动信息'}</div>
          )}
        </div>
      )}

      {activeTab === 'users' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.name') || '名称'}</th>
                <th>{t('systemInfo.domain') || '域'}</th>
                <th>{t('systemInfo.fullName') || '全名'}</th>
                <th>{t('systemInfo.sid') || 'SID'}</th>
                <th>{t('systemInfo.type') || '类型'}</th>
                <th>{t('systemInfo.enabled') || '状态'}</th>
                <th>{t('systemInfo.lastLogin') || '上次登录'}</th>
                <th>{t('systemInfo.passwordExp') || '密码过期'}</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user, idx) => (
                <tr key={`${user.name}-${idx}`}>
                  <td className="highlight">{user.name}</td>
                  <td>{user.domain || '-'}</td>
                  <td>{user.full_name || '-'}</td>
                  <td className="mono">{user.sid || '-'}</td>
                  <td>{user.type || t('systemInfo.user') || '用户'}</td>
                  <td>
                    <span className={`status-badge ${user.enabled ? 'running' : 'stopped'}`}>
                      {user.enabled ? (t('systemInfo.enabled') || '已启用') : (t('systemInfo.disabled') || '已禁用')}
                    </span>
                  </td>
                  <td className="mono">{user.last_login ? new Date(user.last_login).toLocaleString() : '-'}</td>
                  <td>
                    {user.password_expires ? (
                      <span className="status-badge stopped">{t('systemInfo.yes') || '是'}</span>
                    ) : (
                      <span className="status-badge running">{t('systemInfo.no') || '否'}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {users.length === 0 && !loading && (
            <div className="empty-state">
              {moduleErrors.users ? (
                <span className="error-message">{moduleErrors.users}</span>
              ) : (
                t('systemInfo.noUserData') || '暂无用户信息'
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'registry' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.keyPath') || '注册表路径'}</th>
                <th>{t('systemInfo.name') || '名称'}</th>
                <th>{t('systemInfo.value') || '值'}</th>
                <th>{t('systemInfo.type') || '类型'}</th>
                <th>{t('systemInfo.source') || '来源'}</th>
                <th>{t('systemInfo.enabled') || '启用'}</th>
              </tr>
            </thead>
            <tbody>
              {registry.map((key, idx) => (
                <tr key={`${key.path}-${idx}`}>
                  <td className="truncate mono" title={key.path}>{key.path}</td>
                  <td className="highlight">{key.name}</td>
                  <td className="truncate" title={key.value}>{key.value || '-'}</td>
                  <td><span className="type-badge">{key.type}</span></td>
                  <td>{key.source || '-'}</td>
                  <td>
                    {key.enabled ? (
                      <span className="status-badge running">{t('systemInfo.enabled') || '是'}</span>
                    ) : (
                      <span className="status-badge stopped">{t('systemInfo.disabled') || '否'}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {registry.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noRegistryData') || '暂无注册表持久化键'}</div>
          )}
        </div>
      )}

      {activeTab === 'startup' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.keyPath') || '路径'}</th>
                <th>{t('systemInfo.name') || '文件名'}</th>
                <th>{t('systemInfo.value') || '完整路径'}</th>
                <th>{t('systemInfo.type') || '类型'}</th>
                <th>{t('systemInfo.enabled') || '启用'}</th>
              </tr>
            </thead>
            <tbody>
              {startupFolders.map((item, idx) => (
                <tr key={`${item.path}-${idx}`}>
                  <td className="truncate mono" title={item.path}>{item.path}</td>
                  <td className="highlight">{item.name}</td>
                  <td className="truncate" title={item.value}>{item.value || '-'}</td>
                  <td><span className="type-badge">{item.type}</span></td>
                  <td>
                    {item.enabled ? (
                      <span className="status-badge running">{t('systemInfo.enabled') || '是'}</span>
                    ) : (
                      <span className="status-badge stopped">{t('systemInfo.disabled') || '否'}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {startupFolders.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noStartupData') || '暂无启动文件夹项'}</div>
          )}
        </div>
      )}

      {activeTab === 'tasks' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.taskName') || '任务名称'}</th>
                <th>{t('systemInfo.state') || '状态'}</th>
                <th>{t('systemInfo.nextRunTime') || '下次运行'}</th>
                <th>{t('systemInfo.lastRunTime') || '上次运行'}</th>
                <th>{t('systemInfo.runAsUser') || '运行身份'}</th>
                <th>{t('systemInfo.taskAction') || '操作'}</th>
                <th>{t('systemInfo.taskAuthor') || '创建者'}</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((task, idx) => (
                <tr key={`${task.name}-${idx}`}>
                  <td className="highlight" title={task.path}>{task.name}</td>
                  <td>
                    <span className={`status-badge ${task.state?.toLowerCase() === 'running' ? 'running' : 'stopped'}`}>
                      {task.state || t('common.unknown')}
                    </span>
                  </td>
                  <td className="mono">{task.next_run_time || '-'}</td>
                  <td className="mono">{task.last_run_time || '-'}</td>
                  <td className="truncate" title={task.run_as_user}>{task.run_as_user || '-'}</td>
                  <td className="truncate mono" title={task.action}>{task.action || '-'}</td>
                  <td className="truncate" title={task.author}>{task.author || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {tasks.length === 0 && !loading && (
            <div className="empty-state">
              {moduleErrors.tasks ? (
                <span className="error-message">{moduleErrors.tasks}</span>
              ) : (
                t('systemInfo.              noTasksData') || '暂无计划任务'
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'services' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.name') || '名称'}</th>
                <th>{t('systemInfo.displayName') || '显示名称'}</th>
                <th>{t('systemInfo.imagePath') || '程序路径'}</th>
                <th>{t('systemInfo.description') || '描述'}</th>
                <th>{t('systemInfo.type') || '类型'}</th>
              </tr>
            </thead>
            <tbody>
              {services.map((item, idx) => (
                <tr key={`${item.path}-${idx}`}>
                  <td className="highlight">{item.name}</td>
                  <td className="truncate" title={item.display_name}>{item.display_name || '-'}</td>
                  <td className="truncate mono" title={item.image_path}>{item.image_path || '-'}</td>
                  <td className="truncate" title={item.description}>{item.description || '-'}</td>
                  <td><span className="type-badge">{item.type || '-'}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {services.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noServicesData') || '暂无服务信息'}</div>
          )}
        </div>
      )}

      {activeTab === 'runkeys' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.keyPath') || '注册表路径'}</th>
                <th>{t('systemInfo.name') || '名称'}</th>
                <th>{t('systemInfo.value') || '命令'}</th>
                <th>{t('systemInfo.enabled') || '启用'}</th>
              </tr>
            </thead>
            <tbody>
              {runKeys.map((item, idx) => (
                <tr key={`${item.path}-${idx}`}>
                  <td className="truncate mono" title={item.path}>{item.path}</td>
                  <td className="highlight">{item.name}</td>
                  <td className="truncate" title={item.value}>{item.value || '-'}</td>
                  <td>
                    {item.enabled ? (
                      <span className="status-badge running">{t('systemInfo.enabled') || '是'}</span>
                    ) : (
                      <span className="status-badge stopped">{t('systemInfo.disabled') || '否'}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {runKeys.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noRunKeysData') || '暂无自启动项'}</div>
          )}
        </div>
      )}

      {activeTab === 'userinit' && (
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>{t('systemInfo.keyPath') || '注册表路径'}</th>
                <th>{t('systemInfo.name') || '名称'}</th>
                <th>{t('systemInfo.value') || '值'}</th>
                <th>{t('systemInfo.enabled') || '启用'}</th>
              </tr>
            </thead>
            <tbody>
              {userInit.map((item, idx) => (
                <tr key={`${item.path}-${idx}`}>
                  <td className="truncate mono" title={item.path}>{item.path}</td>
                  <td className="highlight">{item.name || '-'}</td>
                  <td className="truncate" title={item.value}>{item.value || '-'}</td>
                  <td>
                    {item.enabled ? (
                      <span className="status-badge running">{t('systemInfo.enabled') || '是'}</span>
                    ) : (
                      <span className="status-badge stopped">{t('systemInfo.disabled') || '否'}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {userInit.length === 0 && !loading && (
            <div className="empty-state">{t('systemInfo.noUserInitData') || '暂无登录项'}</div>
          )}
        </div>
      )}

      <style>{`
        .systeminfo-page {
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
        
        .systeminfo-page h2 {
          font-size: 1.8rem;
          color: #00d9ff;
          margin: 0;
        }
        
        .btn-refresh {
          padding: 8px 16px;
          background: rgba(0, 217, 255, 0.1);
          border: 1px solid #00d9ff;
          border-radius: 6px;
          color: #00d9ff;
          cursor: pointer;
        }
        
        .btn-refresh:hover {
          background: rgba(0, 217, 255, 0.2);
        }

        .btn-export {
          padding: 8px 16px;
          background: rgba(34, 197, 94, 0.1);
          border: 1px solid #22c55e;
          border-radius: 6px;
          color: #22c55e;
          cursor: pointer;
          margin-left: 8px;
        }

        .btn-export:hover {
          background: rgba(34, 197, 94, 0.2);
        }

        .export-dropdown {
          position: relative;
        }

        .export-menu {
          position: absolute;
          top: 100%;
          right: 0;
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border: 1px solid #333;
          border-radius: 8px;
          padding: 8px 0;
          min-width: 150px;
          z-index: 1000;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }

        .export-menu button {
          display: block;
          width: 100%;
          padding: 10px 16px;
          background: none;
          border: none;
          color: #ddd;
          text-align: left;
          cursor: pointer;
        }

        .export-menu button:hover {
          background: rgba(0, 217, 255, 0.1);
          color: #00d9ff;
        }
        
        .tab-nav {
          display: flex;
          flex-wrap: wrap;
          gap: 4px;
          margin-bottom: 20px;
          background: rgba(255,255,255,0.05);
          padding: 8px;
          border-radius: 8px;
          justify-content: center;
        }
        
        .tab-btn {
          padding: 10px 20px;
          background: transparent;
          border: none;
          color: #888;
          cursor: pointer;
          border-radius: 6px;
          transition: all 0.2s;
          flex-shrink: 0;
          white-space: nowrap;
          display: inline-flex;
          align-items: center;
          gap: 8px;
        }
        
        .tab-btn:hover {
          color: #fff;
          background: rgba(255,255,255,0.05);
        }
        
        .tab-btn.active {
          background: #00d9ff;
          color: #000;
        }
        
        .system-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 20px;
        }
        
        .system-card {
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          padding: 24px;
          border: 1px solid #333;
        }
        
        .card-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 20px;
        }
        
        .card-icon {
          font-size: 1.5rem;
          width: 40px;
          height: 40px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(0, 217, 255, 0.1);
          border-radius: 8px;
          color: #00d9ff;
          font-weight: bold;
        }
        
        .card-header h3 {
          color: #00d9ff;
          font-size: 1.1rem;
          margin: 0;
        }
        
        .system-status {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-bottom: 20px;
          padding: 8px 12px;
          background: rgba(34, 197, 94, 0.1);
          border-radius: 6px;
          color: #22c55e;
          font-size: 0.9rem;
        }
        
        .status-indicator {
          width: 8px;
          height: 8px;
          border-radius: 50%;
        }
        
        .status-indicator.online {
          background: #22c55e;
          box-shadow: 0 0 8px #22c55e;
        }
        
        .info-list {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }
        
        .info-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 8px 0;
          border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        
        .info-label {
          color: #888;
          font-size: 0.9rem;
        }
        
        .info-value {
          color: #eee;
          font-weight: 500;
        }
        
        .info-value.highlight {
          color: #00d9ff;
          font-size: 1.1rem;
        }
        
        .info-value.mono {
          font-family: monospace;
          font-size: 0.85rem;
        }
        
        .info-value.badge {
          background: rgba(0, 217, 255, 0.1);
          color: #00d9ff;
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 0.85rem;
        }
        
        .info-value.badge.admin {
          background: rgba(34, 197, 94, 0.1);
          color: #22c55e;
        }
        
        .info-value.badge.user {
          background: rgba(255, 255, 255, 0.1);
          color: #888;
        }
        
        .resource-bars {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }
        
        .resource-item {}
        
        .resource-header {
          display: flex;
          justify-content: space-between;
          margin-bottom: 6px;
        }
        
        .resource-name {
          color: #888;
          font-size: 0.85rem;
        }
        
        .resource-value {
          color: #eee;
          font-size: 0.85rem;
          font-family: monospace;
        }
        
        .resource-bar {
          height: 8px;
          background: rgba(255, 255, 255, 0.1);
          border-radius: 4px;
          overflow: hidden;
        }
        
        .resource-fill {
          height: 100%;
          background: linear-gradient(90deg, #00d9ff, #0099cc);
          border-radius: 4px;
          transition: width 0.3s;
        }
        
        .resource-fill.memory {
          background: linear-gradient(90deg, #22c55e, #16a34a);
        }
        
        .time-display {
          text-align: center;
          padding: 20px 0;
        }
        
        .current-time {
          font-size: 2.5rem;
          font-weight: bold;
          color: #fff;
          font-family: monospace;
        }
        
        .current-date {
          font-size: 1rem;
          color: #888;
          margin-top: 4px;
        }
        
        .loading-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          height: 60vh;
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
        
        .data-table-container {
          flex: 1;
          overflow: auto;
          background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
          border-radius: 12px;
          border: 1px solid #333;
        }
        
        .data-table {
          width: 100%;
          border-collapse: collapse;
        }
        
        .data-table th {
          background: rgba(0, 217, 255, 0.1);
          color: #00d9ff;
          padding: 12px 16px;
          text-align: left;
          font-weight: 600;
          position: sticky;
          top: 0;
        }
        
        .data-table td {
          padding: 10px 16px;
          border-bottom: 1px solid rgba(255,255,255,0.05);
          color: #ddd;
        }
        
        .data-table tr:hover td {
          background: rgba(255,255,255,0.02);
        }
        
        .data-table .mono {
          font-family: monospace;
          color: #888;
        }
        
        .data-table .truncate {
          max-width: 300px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        
        .protocol-badge {
          background: rgba(59, 130, 246, 0.2);
          color: #3b82f6;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 0.8rem;
          font-weight: 600;
        }
        
        .state-badge {
          font-weight: 600;
          font-size: 0.85rem;
        }

        .state-badge.running {
          color: #22c55e;
        }

        .state-badge.stopped {
          color: #ef4444;
        }
        
        .empty-state {
          padding: 40px;
          text-align: center;
          color: #888;
        }

        .empty-state .error-message {
          color: #ef4444;
          display: block;
          padding: 10px;
          background: rgba(239, 68, 68, 0.1);
          border-radius: 6px;
          margin: 10px auto;
          max-width: 400px;
        }

        .data-table .highlight {
          color: #00d9ff;
        }

        .type-badge {
          background: rgba(168, 85, 247, 0.2);
          color: #a855f7;
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 0.8rem;
        }

        .signature-badge {
          padding: 2px 8px;
          border-radius: 4px;
          font-size: 0.75rem;
          font-weight: 600;
        }

        .signature-badge.signed {
          background: rgba(34, 197, 94, 0.2);
          color: #22c55e;
        }

        .signature-badge.unsigned {
          background: rgba(239, 68, 68, 0.2);
          color: #ef4444;
        }

        .content-float-panel {
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          border: 1px solid #00d9ff;
          border-radius: 8px;
          padding: 12px 16px;
          max-width: 600px;
          max-height: 300px;
          overflow: auto;
          box-shadow: 0 4px 20px rgba(0, 217, 255, 0.3);
        }

        .content-float-panel .float-panel-content {
          color: #eee;
          font-family: monospace;
          font-size: 0.9rem;
          white-space: pre-wrap;
          word-break: break-all;
        }
      `}</style>
    </div>
  )
}

export default SystemInfo
