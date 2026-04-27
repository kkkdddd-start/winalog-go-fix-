import axios from 'axios'

let requestTimeout = 1800000 // 30 minutes default

const api = axios.create({
  baseURL: '/api',
  timeout: requestTimeout,
})

api.interceptors.request.use(config => {
  if (!config.timeout || config.timeout === 120000) {
    config.timeout = requestTimeout
  }
  return config
})

api.interceptors.response.use(
  response => response,
  error => {
    console.error('API Error:', error)
    return Promise.reject(error)
  }
)

export const setRequestTimeout = (timeout: number) => {
  requestTimeout = timeout * 1000
}

export default api

export const eventsAPI = {
  list: (page = 1, pageSize = 100, params?: Partial<SearchParams>) => {
    let url = `/events?page=${page}&page_size=${pageSize}`
    if (params) {
      if (params.levels && params.levels.length > 0) {
        params.levels.forEach(l => url += `&levels=${l}`)
      }
      if (params.event_ids && params.event_ids.length > 0) {
        params.event_ids.forEach(id => url += `&event_ids=${id}`)
      }
      if (params.log_names && params.log_names.length > 0) {
        params.log_names.forEach(name => url += `&log_names=${encodeURIComponent(name)}`)
      }
      if (params.sources && params.sources.length > 0) {
        params.sources.forEach(s => url += `&sources=${encodeURIComponent(s)}`)
      }
      if (params.users && params.users.length > 0) {
        params.users.forEach(u => url += `&users=${encodeURIComponent(u)}`)
      }
      if (params.computers && params.computers.length > 0) {
        params.computers.forEach(c => url += `&computers=${encodeURIComponent(c)}`)
      }
      if (params.start_time) url += `&start_time=${encodeURIComponent(params.start_time)}`
      if (params.end_time) url += `&end_time=${encodeURIComponent(params.end_time)}`
      if (params.sort_by) url += `&sort_by=${params.sort_by}`
      if (params.sort_order) url += `&sort_order=${params.sort_order}`
    }
    return api.get(url)
  },
  get: (id: number) =>
    api.get(`/events/${id}`),
  search: (params: SearchParams) =>
    api.post('/events/search', params),
  export: (params: ExportParams) =>
    api.post('/events/export', params, {
      responseType: params.format === 'json' ? 'json' : 'blob',
    }),
}

export interface ExportParams {
  format?: 'json' | 'csv' | 'excel'
  filters?: {
    event_ids?: number[]
    levels?: number[]
    log_names?: string[]
    computers?: string[]
    users?: string[]
    start_time?: string
    end_time?: string
    keywords?: string
    limit?: number
  }
}

export const alertsAPI = {
  list: (page = 1, pageSize = 100, severity?: string) =>
    api.get(`/alerts?page=${page}&page_size=${pageSize}${severity ? `&severity=${severity}` : ''}`),
  get: (id: number) =>
    api.get(`/alerts/${id}`),
  stats: () =>
    api.get('/alerts/stats'),
  trend: (days = 7) =>
    api.get(`/alerts/trend?days=${days}`),
  resolve: (id: number, notes: string) =>
    api.post(`/alerts/${id}/resolve`, { notes }),
  markFalsePositive: (id: number, reason: string) =>
    api.post(`/alerts/${id}/false-positive`, { reason }),
  delete: (id: number) =>
    api.delete(`/alerts/${id}`),
  batchAction: (ids: number[], action: string, notes?: string) =>
    api.post('/alerts/batch', { ids, action, notes }),
  runAnalysis: () =>
    api.post('/alerts/run-analysis'),
  export: (params: {
    format?: 'csv' | 'json'
    severity?: string
    resolved?: string
    false_positive?: string
    rule_name?: string
    start_time?: string
    end_time?: string
    limit?: number
  }) => {
    const queryParams = new URLSearchParams()
    if (params.format) queryParams.append('format', params.format)
    if (params.severity) queryParams.append('severity', params.severity)
    if (params.resolved) queryParams.append('resolved', params.resolved)
    if (params.false_positive) queryParams.append('false_positive', params.false_positive)
    if (params.rule_name) queryParams.append('rule_name', params.rule_name)
    if (params.start_time) queryParams.append('start_time', params.start_time)
    if (params.end_time) queryParams.append('end_time', params.end_time)
    if (params.limit) queryParams.append('limit', String(params.limit))
    const query = queryParams.toString()
    return api.get(`/alerts/export${query ? `?${query}` : ''}`, { responseType: 'blob' })
  },
}

export interface CollectParams {
  sources?: string[]
  formats?: string[]
  excludes?: string[]
  options?: {
    workers?: number
    include_prefetch?: boolean
    include_registry?: boolean
    include_startup?: boolean
    include_system_info?: boolean
    include_shimcache?: boolean
    include_amcache?: boolean
    include_userassist?: boolean
    include_usn_journal?: boolean
    include_tasks?: boolean
    include_logs?: boolean
    include_processes?: boolean
    include_network?: boolean
    include_dlls?: boolean
    include_drivers?: boolean
    include_users?: boolean
    compress?: boolean
    calculate_hash?: boolean
    output_path?: string
  }
}

export const collectAPI = {
  collect: (params: CollectParams) =>
    api.post('/collect', params, { timeout: 1800000 }),
  getChannels: () =>
    api.get('/collect/channels'),
  getStatus: () =>
    api.get('/collect/status'),
  uploadFile: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/collect/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      timeout: 1800000,
    })
  },
  evtx2csv: (filePaths: string[], options?: { output_dir?: string; include_xml?: boolean; calculate_hash?: boolean; limit?: number }) =>
    api.post('/collect/evtx2csv', { file_paths: filePaths, ...options }, { timeout: 1800000 }),
}

export interface ImportOptions {
  enabled_formats?: string[]
  skip_patterns?: string[]
}

export interface ImportFileResult {
  file_path: string
  status: 'imported' | 'failed'
  events_imported: number
  error?: string
}

export interface ImportLogEntry {
  id: number
  file_path: string
  file_hash: string
  events_count: number
  import_time: string
  import_duration: number
  status: string
  error_message: string
}

export interface ImportHistoryResponse {
  total: number
  entries: ImportLogEntry[]
}

export const importAPI = {
  importLogs: (filePaths: string[], options?: ImportOptions) =>
    api.post('/import/logs', { files: filePaths, ...options }, { timeout: 1800000 }),
  importLogsWithAlert: (filePaths: string[]) =>
    api.post('/import/logs', { files: filePaths, alert_on_import: true }, { timeout: 1800000 }),
  getStatus: (path: string) =>
    api.get(`/import/status?path=${encodeURIComponent(path)}`),
  getHistory: (params?: { limit?: number; offset?: number }) => {
    const queryParams = new URLSearchParams()
    if (params?.limit !== undefined) queryParams.append('limit', String(params.limit))
    if (params?.offset !== undefined) queryParams.append('offset', String(params.offset))
    const query = queryParams.toString()
    return api.get(`/import/history${query ? `?${query}` : ''}`)
  },
}

export const liveAPI = {
  getStats: () =>
    api.get('/live/stats'),
  getChannels: () =>
    api.get('/live/channels'),
}

export const systemAPI = {
  health: () =>
    api.get('/health'),
  getInfo: () =>
    api.get('/system/info'),
  getMetrics: () =>
    api.get('/system/metrics'),
  getProcesses: (limit = 100, enabled = true) =>
    api.get(`/system/processes?limit=${limit}&enabled=${enabled}`),
  getNetwork: (limit = 100, enabled = true, protocol?: string) =>
    api.get(`/system/network?limit=${limit}&enabled=${enabled}${protocol ? `&protocol=${protocol}` : ''}`),
  getEnvVariables: () =>
    api.get('/system/env'),
  getLoadedDLLs: (limit = 100, enabled = true) =>
    api.get(`/system/dlls?limit=${limit}&enabled=${enabled}`),
  getProcessDLLs: (pid: number) =>
    api.get(`/system/process/${pid}/dlls`),
  getDrivers: (enabled = true) =>
    api.get(`/system/drivers?enabled=${enabled}`),
  getUsers: (enabled = true) =>
    api.get(`/system/users?enabled=${enabled}`),
  getRegistry: (enabled = true) =>
    api.get(`/system/registry?enabled=${enabled}`),
  getTasks: (enabled = true) =>
    api.get(`/system/tasks?enabled=${enabled}`),
}

export const rulesAPI = {
  list: () =>
    api.get('/rules'),
  get: (name: string) =>
    api.get(`/rules/${name}`),
  toggle: (name: string, enabled: boolean) =>
    api.post(`/rules/${name}/toggle?enabled=${enabled}`),
  save: (rule: Partial<RuleInfo> & { name: string }) =>
    api.post('/rules', rule),
  update: (name: string, rule: Partial<RuleInfo> & { name: string }) =>
    api.put(`/rules/${name}`, rule),
  validate: (rule: Partial<RuleInfo> & { name: string }, content?: string) =>
    api.post('/rules/validate', { rule, content }),
  import: (rules: RuleInfo[]) =>
    api.post('/rules/import', { rules }),
  export: (format: 'json' | 'yaml' = 'json') =>
    api.get(`/rules/export?format=${format}`, { responseType: 'blob' }),
  listTemplates: () =>
    api.get('/rules/templates'),
  getTemplate: (name: string) =>
    api.get(`/rules/templates/${name}`),
  instantiateTemplate: (name: string, params: Record<string, string>) =>
    api.post(`/rules/templates/${name}/instantiate`, { name, params }),
}

export const reportsAPI = {
  list: () =>
    api.get('/reports'),
  generate: (params: ReportParams) =>
    api.post('/reports', params),
  get: (id: string) =>
    api.get(`/reports/${id}`),
  export: (format: 'json' | 'csv' | 'excel' | 'pdf') =>
    api.get(`/reports/export?format=${format}`, { responseType: 'blob' }),
  download: (id: string) =>
    api.get(`/reports/${id}/download`, { responseType: 'blob' }),
}

export interface ReportParams {
  type: string
  format: string
  language?: string
  start_time?: string
  end_time?: string
}

export const forensicsAPI = {
  calculateHash: (path: string) =>
    api.post('/forensics/hash', { path }),
  verifyHash: (path: string, expected: string) =>
    api.get(`/forensics/verify-hash?path=${path}&expected=${expected}`),
  verifySignature: (path: string) =>
    api.get(`/forensics/signature?path=${path}`),
  isSigned: (path: string) =>
    api.get(`/forensics/is-signed?path=${path}`),
  collect: (params: {
    type: string
    output_path?: string
    collect_registry?: boolean
    collect_prefetch?: boolean
    collect_shimcache?: boolean
    collect_amcache?: boolean
    collect_userassist?: boolean
    collect_tasks?: boolean
    collect_logs?: boolean
  }) =>
    api.post('/forensics/collect', params),
  listEvidence: () =>
    api.get('/forensics/evidence'),
  getEvidence: (id: string) =>
    api.get(`/forensics/evidence/${id}`),
  exportEvidence: (id: string, format: string) =>
    api.get(`/forensics/evidence/${id}/export?format=${format}`, { responseType: 'blob' }),
  chainOfCustody: () =>
    api.get('/forensics/chain-of-custody'),
  memoryDump: (pid?: number) =>
    api.get(`/forensics/memory-dump${pid ? `?pid=${pid}` : ''}`),
}

export interface TimelineEntry {
  id: number
  timestamp: string
  type: 'event' | 'alert'
  event_id?: number
  alert_id?: number
  level?: string
  source?: string
  message: string
  severity?: string
  rule_name?: string
  mitre_attack?: string[]
  computer?: string
  log_name?: string
  event_db_ids?: number[]
}

export interface TimelineResponse {
  entries: TimelineEntry[]
  total_count: number
  event_count: number
  alert_count: number
}

export const timelineAPI = {
  get: (limit = 200, startTime?: string, endTime?: string) => {
    let url = `/timeline?limit=${limit}`
    if (startTime) url += `&start_time=${startTime}`
    if (endTime) url += `&end_time=${endTime}`
    return api.get(url)
  },
  deleteAlert: (id: number) =>
    api.delete(`/timeline/alerts/${id}`),
}

export interface CollectionStats {
  total_events: number
  total_size: string
  sources: Record<string, number>
  last_import: string
}

export const dashboardAPI = {
  getCollectionStats: () =>
    api.get('/dashboard/collection-stats'),
  getLogNames: () =>
    api.get('/dashboard/log-names'),
}

export interface AnalyzeParams {
  type: string
  hours?: number
  start_time?: string
  end_time?: string
}

export interface AnalyzeResult {
  type: string
  severity: string
  score: number
  summary: string
  findings: Array<{
    description: string
    severity: string
    score: number
    rule_name?: string
    mitre_attack?: string[]
    metadata?: Record<string, any>
  }>
  timestamp: number
}

export const analyzeAPI = {
  run: (analyzerType: string, params?: { hours?: number }) =>
    api.post(`/analyze/${analyzerType}`, params || {}),
  list: () =>
    api.get('/analyzers'),
  info: (analyzerType: string) =>
    api.get(`/analyzers/${analyzerType}`),
  listRules: () =>
    api.get('/analyzer-rules'),
  getRule: (analyzerType: string) =>
    api.get(`/analyzer-rules/${analyzerType}`),
  updateRule: (rule: {
    name: string
    enabled: boolean
    event_ids?: number[]
    thresholds?: Record<string, number>
    patterns?: string[]
    whitelist?: string[]
  }) =>
    api.put(`/analyzer-rules/${rule.name}`, rule),
}

export interface Settings {
  database_path: string
  log_level: string
  max_events: number
  retention_days: number
  enable_alerting: boolean
  enable_live_collection: boolean
  enable_auto_update: boolean
  api_port: number
  api_host: string
  cors_enabled: boolean
  max_import_file_size: number
  export_directory: string
  parser_workers: number
  memory_limit: number
  request_timeout?: number
}

export const settingsAPI = {
  get: () =>
    api.get('/settings'),
  save: (settings: Partial<Settings>) =>
    api.post('/settings', settings),
  reset: () =>
    api.post('/settings/reset'),
}

export const persistenceAPI = {
  detect: (params?: { category?: string, technique?: string, force?: boolean }) => {
    const queryParts: string[] = []
    if (params?.category) queryParts.push(`category=${encodeURIComponent(params.category)}`)
    if (params?.technique) queryParts.push(`technique=${encodeURIComponent(params.technique)}`)
    if (params?.force) queryParts.push('force=true')
    const query = queryParts.length > 0 ? `?${queryParts.join('&')}` : ''
    return api.get(`/persistence/detect${query}`)
  },
  listCategories: () =>
    api.get('/persistence/categories'),
  listTechniques: () =>
    api.get('/persistence/techniques'),
  listDetectors: () =>
    api.get('/persistence/detectors'),
  updateDetectors: (detectors: { name: string, enabled: boolean }[]) =>
    api.post('/persistence/detectors/config', { detectors }),
  listRules: () =>
    api.get('/persistence/rules'),
  getRule: (name: string) =>
    api.get(`/persistence/rules/${name}`),
  updateRule: (rule: {
    name: string
    enabled: boolean
    suspicious_indicators?: string[]
    whitelist?: string[]
  }) =>
    api.put('/persistence/rules', rule),
  getWhitelist: (name: string) =>
    api.get(`/persistence/whitelist/${name}`),
  updateWhitelist: (whitelist: {
    name: string
    whitelist?: string[]
    dll_whitelist?: string[]
    clsids_whitelist?: string[]
  }) =>
    api.put('/persistence/whitelist', whitelist),
}

export interface SearchParams {
  keywords?: string
  keyword_mode?: 'AND' | 'OR'
  regex?: boolean
  event_ids?: number[]
  levels?: number[]
  log_names?: string[]
  sources?: string[]
  users?: string[]
  computers?: string[]
  start_time?: string
  end_time?: string
  page?: number
  page_size?: number
  sort_by?: string
  sort_order?: string
}

export interface FilterInfo {
  event_ids?: number[]
  levels?: number[]
  log_names?: string[]
  sources?: string[]
  computers?: string[]
  users?: string[]
  keywords?: string[]
  exclude_users?: string[]
  exclude_computers?: string[]
  ip_address?: string
}

export interface RuleInfo {
  id: string
  name: string
  description: string
  enabled: boolean
  severity: string
  score: number
  mitre_attack?: string[]
  tags?: string[]
  is_custom?: boolean
  event_ids?: number[]
  levels?: number[]
  filter?: FilterInfo
  message?: string
  created_at?: string
  updated_at?: string
}

export interface CorrelationParams {
  time_window?: string
  rules?: string[]
}

export interface CorrelationResult {
  rule_name: string
  severity: string
  event_count: number
  start_time: string
  end_time: string
  description: string
}

export interface CorrelationResponse {
  results: CorrelationResult[]
  count: number
}

export const correlationAPI = {
  analyze: (params?: CorrelationParams) =>
    api.post('/correlation/analyze', params || {}),
}

export interface MultiParams {
  time_window?: string
}

export interface MultiResponse {
  machines: Array<{
    id: string
    name: string
    ip: string
    domain: string
    role: string
    os_version: string
    last_seen: string
  }>
  cross_machine_activity: Array<{
    user: string
    machine_count: number
    machines: string[]
    login_count: number
    suspicious: boolean
    severity: string
    recommendation: string
  }>
  lateral_movement: Array<{
    source_machine: string
    target_machine: string
    user: string
    event_id: number
    timestamp: string
    ip_address: string
    severity: string
    description: string
    mitre_attack: string[]
  }>
  summary: string
  suspicious_count: number
  analysis_id: string
}

export const multiAPI = {
  analyze: (params?: MultiParams) =>
    api.post('/multi/analyze', params || {}),
  lateral: () =>
    api.get('/multi/lateral'),
}

export interface QueryParams {
  sql: string
  limit?: number
  offset?: number
}

export interface QueryResponse {
  columns: string[]
  rows: Record<string, any>[]
  count: number
  total: number
}

export const queryAPI = {
  execute: (params: QueryParams) =>
    api.post('/query/execute', params),
}

export interface SuppressRule {
  id: number
  name: string
  conditions: any[]
  duration: number
  scope: string
  enabled: boolean
  expires_at: string
  created_at: string
}

export const suppressAPI = {
  list: () => api.get('/suppress'),
  create: (rule: Partial<SuppressRule>) => api.post('/suppress', rule),
  update: (id: number, rule: Partial<SuppressRule>) => api.put(`/suppress/${id}`, rule),
  delete: (id: number) => api.delete(`/suppress/${id}`),
  toggle: (id: number, enabled: boolean) => api.post(`/suppress/${id}/toggle`, { enabled }),
}

export interface UEBAAnomaly {
  type: string
  user?: string
  severity: string
  score: number
  description: string
  details?: Record<string, any>
  event_ids?: number[]
}

export interface UEBAResponse {
  type: string
  anomalies: UEBAAnomaly[]
  total_anomaly: number
  high_risk_count: number
  medium_risk_count: number
  duration: string
}

export interface UserProfile {
  user: string
  login_count: number
  last_updated: string
  avg_events_per_day: number
}

export const uebaAPI = {
  analyze: (params?: { hours?: number }) => api.post('/ueba/analyze', params || {}),
  profiles: () => api.get('/ueba/profiles'),
}

export interface MonitorStats {
  is_running: boolean
  process_enabled: boolean
  network_enabled: boolean
  process_count: number
  network_count: number
  alert_count: number
  start_time?: string
}

export interface MonitorEvent {
  id: string
  type: 'process' | 'network'
  timestamp: string
  severity: string
  data: Record<string, any>
}

export interface MonitorConfig {
  process_enabled?: boolean
  network_enabled?: boolean
  poll_interval?: number
}

export const monitorAPI = {
  getStats: () =>
    api.get('/monitor/stats'),
  getEvents: (filter?: {
    type?: string
    severity?: string
    limit?: number
    offset?: number
    start_time?: string
    end_time?: string
  }) => {
    let url = '/monitor/events?'
    if (filter) {
      if (filter.type) url += `type=${filter.type}&`
      if (filter.severity) url += `severity=${filter.severity}&`
      if (filter.limit) url += `limit=${filter.limit}&`
      if (filter.offset) url += `offset=${filter.offset}&`
      if (filter.start_time) url += `start_time=${encodeURIComponent(filter.start_time)}&`
      if (filter.end_time) url += `end_time=${encodeURIComponent(filter.end_time)}&`
    }
    return api.get(url)
  },
  updateConfig: (config: MonitorConfig) =>
    api.post('/monitor/config', config),
  startStop: (action: 'start' | 'stop') =>
    api.post('/monitor/action', { action }),
}

export interface LogEntry {
  timestamp: string
  level: string
  message: string
  caller?: string
  module?: string
  status?: number
  latency?: string
  client_ip?: string
  method?: string
  path?: string
  error?: string
  reason?: string
  mem_alloc_mb?: number
  mem_total_mb?: number
  mem_sys_mb?: number
  num_goroutine?: number
  num_cpu?: number
  mem_pause_us?: number
  heap_objects?: number
  category?: string
}

export interface LogFileInfo {
  name: string
  path: string
  size: number
  mod_time: string
  is_main: boolean
}

export interface LogsResponse {
  entries: LogEntry[]
  total: number
  offset: number
  limit: number
  keyword?: string
  level?: string
  category?: string
}

export interface LogFilesResponse {
  files: LogFileInfo[]
  count: number
}

export const logsAPI = {
  getLogs: (params: {
    offset?: number
    limit?: number
    keyword?: string
    level?: string
    category?: string
  }) => {
    const searchParams = new URLSearchParams()
    if (params.offset !== undefined) searchParams.append('offset', String(params.offset))
    if (params.limit !== undefined) searchParams.append('limit', String(params.limit))
    if (params.keyword) searchParams.append('keyword', params.keyword)
    if (params.level && params.level !== 'all') searchParams.append('level', params.level)
    if (params.category && params.category !== 'all') searchParams.append('category', params.category)
    return api.get(`/logs?${searchParams.toString()}`)
  },
  getLogFiles: () =>
    api.get('/logs/files'),
  getLogFileContent: (filename: string) =>
    api.get(`/logs/files/${filename}`),
}
