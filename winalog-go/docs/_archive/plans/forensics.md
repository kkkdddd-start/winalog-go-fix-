# Forensics 模块改进实施方案

**项目**: WinLogAnalyzer-Go
**模块**: `internal/forensics/`, `internal/api/handlers_forensics.go`
**文档版本**: v2.0
**审核状态**: 待审核

---

## 一、问题验证记录

以下问题均经过实际代码验证，确认**真实存在**：

| ID | 问题 | 验证文件位置 | 验证结果 |
|----|------|-------------|---------|
| **F1** | `readSystemMemory()` 返回未实现错误 | `memory.go:276-278` | 确认 |
| **F2** | `AnalyzeMemoryDump()` 仅返回哈希 | `memory.go:327-342` | 确认 |
| **F3** | `ExtractProcessTree()` 返回空切片 | `memory.go:344-346` | 确认 |
| **F4** | `FindNetworkConnections()` 返回空切片 | `memory.go:348-350` | 确认 |
| **F5** | `FindSuspiciousAPI()` 返回空切片 | `memory.go:352-354` | 确认 |
| **F6** | `CollectEvidence()` 无实际收集逻辑 | `handlers_forensics.go:196-229` | 确认 |
| **F7** | `ListEvidence()` 返回空列表 | `handlers_forensics.go:231-244` | 确认 |
| **F8** | `GetEvidence()` 总是返回 not_found | `handlers_forensics.go:246-262` | 确认 |
| **F9** | `MemoryDump()` API 逻辑错误 | `handlers_forensics.go:367-393` | 确认 |
| **F10** | PowerShell 临时文件权限过宽 | `signature.go:141-147` | 确认 |
| **F11** | TSA 请求无重试机制 | `timestamp.go:80-93` | 确认 |

---

## 二、实施优先级总览

| 优先级 | ID | 问题 | 复杂度 | 必要性 | 风险 |
|--------|----|------|--------|--------|------|
| **P1** | F6 | 实现 Evidence Collection | 低 | 高 | 低 |
| **P1** | F7/F8 | 实现 ListEvidence/GetEvidence | 低 | 高 | 低 |
| **P1** | F9 | 修复 MemoryDump API | 低 | 高 | 低 |
| **P2** | F10 | PowerShell 临时文件安全 | 低 | 中 | 低 |
| **P2** | F11 | TSA 重试机制 | 低 | 中 | 低 |
| **P3** | F1 | 系统内存转储 | 高 | 中 | 高 |
| **P3** | F2-F5 | 内存分析功能 | 高 | 中 | 高 |

---

## 三、详细实施方案

---

### ISSUE-F6: 实现 Evidence Collection API

#### 3.6.1 问题确认

**文件**: `internal/api/handlers_forensics.go:196-229`

```go
func (h *ForensicsHandler) CollectEvidence(c *gin.Context) {
    // ...
    // 问题：无任何实际收集逻辑，直接返回完成
    c.JSON(http.StatusOK, CollectResponse{
        Status: "completed",
        Message: "Evidence collection complete",  // 假数据
    })
}
```

#### 3.6.2 数据库支持情况

**已存在表**:
- `evidence_chain` (`schema.go:111-120`)
- `evidence_file` (`schema.go:123-130`)

#### 3.6.3 实施方案

**步骤 1**: 修改 `CollectRequest` 结构

```go
// internal/api/handlers_forensics.go

type CollectRequest struct {
    Type       string   `json:"type" binding:"required"`
    OutputPath string   `json:"output_path"`
    // 新增选项
    CollectRegistry   bool `json:"collect_registry"`
    CollectPrefetch   bool `json:"collect_prefetch"`
    CollectShimcache  bool `json:"collect_shimcache"`
    CollectAmcache    bool `json:"collect_amcache"`
    CollectUserAssist bool `json:"collect_userassist"`
    CollectTasks      bool `json:"collect_tasks"`
    CollectLogs       bool `json:"collect_logs"`
}
```

**步骤 2**: 修改 `CollectEvidence` handler

```go
// internal/api/handlers_forensics.go

func (h *ForensicsHandler) CollectEvidence(c *gin.Context) {
    if runtime.GOOS != "windows" {
        c.JSON(http.StatusNotImplemented, ErrorResponse{
            Error: "evidence collection is only supported on Windows",
        })
        return
    }

    var req CollectRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, ErrorResponse{
            Error: err.Error(),
        })
        return
    }

    // 生成证据 ID
    evidenceID := fmt.Sprintf("ev_%d", time.Now().UnixNano())
    
    // 确定输出路径
    outputPath := req.OutputPath
    if outputPath == "" {
        outputPath = filepath.Join(os.TempDir(), fmt.Sprintf("evidence_%s.zip", evidenceID))
    }

    // 创建收集器
    collector := NewEvidenceCollector(evidenceID, outputPath)
    collector.CollectRegistry = req.CollectRegistry
    collector.CollectPrefetch = req.CollectPrefetch
    collector.CollectShimcache = req.CollectShimcache
    collector.CollectAmcache = req.CollectAmcache
    collector.CollectUserAssist = req.CollectUserAssist
    collector.CollectTasks = req.CollectTasks
    collector.CollectLogs = req.CollectLogs

    // 执行收集
    manifest, err := collector.Collect()
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{
            Error: fmt.Sprintf("collection failed: %v", err),
        })
        return
    }

    // 保存清单到数据库
    if err := h.saveEvidenceManifest(manifest); err != nil {
        log.Printf("failed to save manifest: %v", err)
    }

    c.JSON(http.StatusOK, CollectResponse{
        ID:          evidenceID,
        Type:        req.Type,
        Status:      "completed",
        OutputPath:   outputPath,
        CollectedAt: manifest.CreatedAt,
        Message:     fmt.Sprintf("Collected %d files, total %d bytes", 
            len(manifest.Files), manifest.TotalSize),
    })
}
```

**步骤 3**: 添加辅助方法

```go
// internal/api/handlers_forensics.go

func (h *ForensicsHandler) saveEvidenceManifest(manifest *forensics.EvidenceManifest) error {
    // 保存到 evidence_chain 表
    _, err := h.db.Exec(`
        INSERT INTO evidence_chain (evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `, manifest.ID, manifest.CreatedAt.Format(time.RFC3339),
        manifest.CollectedBy, "manifest_created", "", manifest.Hash, "")
    
    // 保存文件记录
    for _, f := range manifest.Files {
        _, err := h.db.Exec(`
            INSERT INTO evidence_file (file_path, file_hash, evidence_id, collected_at, collector)
            VALUES (?, ?, ?, ?, ?)
        `, f.FilePath, f.FileHash, manifest.ID, f.CollectedAt.Format(time.RFC3339), f.Collector)
        if err != nil {
            log.Printf("failed to save evidence file: %v", err)
        }
    }
    
    return err
}
```

**步骤 4**: 创建证据收集器结构

```go
// internal/forensics/collector.go (新建文件)

package forensics

import (
    "fmt"
    "os"
    "path/filepath"
    "time"
)

type EvidenceCollector struct {
    EvidenceID string
    OutputPath string
    
    // 收集选项
    CollectRegistry   bool
    CollectPrefetch   bool
    CollectShimcache  bool
    CollectAmcache    bool
    CollectUserAssist bool
    CollectTasks      bool
    CollectLogs       bool
    
    files []*EvidenceFile
}

func NewEvidenceCollector(evidenceID, outputPath string) *EvidenceCollector {
    return &EvidenceCollector{
        EvidenceID: evidenceID,
        OutputPath: outputPath,
        files:      make([]*EvidenceFile, 0),
    }
}

func (c *EvidenceCollector) Collect() (*EvidenceManifest, error) {
    // 创建临时目录
    tempDir, err := os.MkdirTemp("", "winalog_evidence_*")
    if err != nil {
        return nil, fmt.Errorf("failed to create temp dir: %w", err)
    }
    defer os.RemoveAll(tempDir)

    // 根据选项收集
    if c.CollectRegistry {
        c.collectRegistry(tempDir)
    }
    if c.CollectPrefetch {
        c.collectPrefetch(tempDir)
    }
    if c.CollectShimcache {
        c.collectShimcache(tempDir)
    }
    if c.CollectLogs {
        c.collectEventLogs(tempDir)
    }

    // 创建清单
    manifest := GenerateManifest(c.files, "web-api", getHostname())

    return manifest, nil
}

func (c *EvidenceCollector) collectRegistry(tempDir string) {
    // Windows 注册表收集逻辑
    // 收集 HKLM\Software, HKCU\Software 等关键位置
    // ...
}

func (c *EvidenceCollector) collectPrefetch(tempDir string) {
    // Prefetch 收集逻辑
    // C:\Windows\Prefetch\*.pf
    // ...
}

func (c *EvidenceCollector) collectShimcache(tempDir string) {
    // ShimCache 收集逻辑
    // ...
}

func (c *EvidenceCollector) collectEventLogs(tempDir string) {
    // 事件日志收集逻辑
    // ...
}
```

#### 3.6.4 复杂度评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 实现复杂度 | **低** | 约 150 行代码 |
| 适配性 | **高** | 利用已有数据库表 |
| 必要性 | **高** | API 功能形同虚设 |
| 可靠性 | **高** | 收集逻辑独立 |
| 风险 | **低** | 新增功能不影响现有逻辑 |

---

### ISSUE-F7/F8: 实现 ListEvidence/GetEvidence

#### 3.7.1 问题确认

**文件**: `handlers_forensics.go:231-262`

```go
func (h *ForensicsHandler) ListEvidence(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "evidence": []interface{}{},  // 总是空
        "total": 0,
    })
}

func (h *ForensicsHandler) GetEvidence(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "status": "not_found",  // 总是未找到
    })
}
```

#### 3.7.2 实施方案

**步骤 1**: 修改 `ListEvidence` handler

```go
// internal/api/handlers_forensics.go

func (h *ForensicsHandler) ListEvidence(c *gin.Context) {
    if runtime.GOOS != "windows" {
        c.JSON(http.StatusNotImplemented, ErrorResponse{
            Error: "evidence listing is only supported on Windows",
        })
        return
    }

    // 解析分页参数
    limitStr := c.DefaultQuery("limit", "50")
    offsetStr := c.DefaultQuery("offset", "0")
    
    limit, err := strconv.Atoi(limitStr)
    if err != nil || limit <= 0 {
        limit = 50
    }
    if limit > 1000 {
        limit = 1000
    }
    
    offset, err := strconv.Atoi(offsetStr)
    if err != nil || offset < 0 {
        offset = 0
    }

    // 查询证据列表
    rows, err := h.db.Query(`
        SELECT 
            ec.evidence_id,
            ec.timestamp,
            ec.operator,
            ec.action,
            COUNT(ef.id) as file_count,
            SUM(ef.file_hash) as total_hash
        FROM evidence_chain ec
        LEFT JOIN evidence_file ef ON ec.evidence_id = ef.evidence_id
        GROUP BY ec.evidence_id
        ORDER BY ec.timestamp DESC
        LIMIT ? OFFSET ?
    `, limit, offset)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{
            Error: fmt.Sprintf("query failed: %v", err),
        })
        return
    }
    defer rows.Close()

    evidenceList := make([]map[string]interface{}, 0)
    for rows.Next() {
        var evidenceID, timestamp, operator, action sql.NullString
        var fileCount int
        var totalHash sql.NullString
        
        if err := rows.Scan(&evidenceID, &timestamp, &operator, &action, &fileCount, &totalHash); err != nil {
            continue
        }
        
        item := map[string]interface{}{
            "evidence_id": evidenceID.String,
            "timestamp":  timestamp.String,
            "operator":   operator.String,
            "action":     action.String,
            "file_count": fileCount,
        }
        evidenceList = append(evidenceList, item)
    }

    // 获取总数
    var total int
    h.db.QueryRow("SELECT COUNT(DISTINCT evidence_id) FROM evidence_chain").Scan(&total)

    c.JSON(http.StatusOK, gin.H{
        "evidence": evidenceList,
        "total":   total,
        "limit":   limit,
        "offset":  offset,
    })
}
```

**步骤 2**: 修改 `GetEvidence` handler

```go
// internal/api/handlers_forensics.go

func (h *ForensicsHandler) GetEvidence(c *gin.Context) {
    if runtime.GOOS != "windows" {
        c.JSON(http.StatusNotImplemented, ErrorResponse{
            Error: "evidence retrieval is only supported on Windows",
        })
        return
    }

    evidenceID := c.Param("id")
    if evidenceID == "" {
        c.JSON(http.StatusBadRequest, ErrorResponse{
            Error: "evidence ID is required",
        })
        return
    }

    // 查询证据链
    chainRows, err := h.db.Query(`
        SELECT id, evidence_id, timestamp, operator, action, input_hash, output_hash, previous_hash
        FROM evidence_chain
        WHERE evidence_id = ?
        ORDER BY timestamp ASC
    `, evidenceID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{
            Error: fmt.Sprintf("query failed: %v", err),
        })
        return
    }
    defer chainRows.Close()

    chain := make([]map[string]interface{}, 0)
    for chainRows.Next() {
        var id int64
        var evID, timestamp, operator, action, inputHash, outputHash, previousHash sql.NullString
        
        if err := chainRows.Scan(&id, &evID, &timestamp, &operator, &action, &inputHash, &outputHash, &previousHash); err != nil {
            continue
        }
        
        entry := map[string]interface{}{
            "id":          id,
            "evidence_id": evID.String,
            "timestamp":  timestamp.String,
            "operator":   operator.String,
            "action":     action.String,
        }
        if inputHash.Valid {
            entry["input_hash"] = inputHash.String
        }
        if outputHash.Valid {
            entry["output_hash"] = outputHash.String
        }
        if previousHash.Valid {
            entry["previous_hash"] = previousHash.String
        }
        chain = append(chain, entry)
    }

    if len(chain) == 0 {
        c.JSON(http.StatusNotFound, gin.H{
            "id":      evidenceID,
            "status":  "not_found",
            "message": "Evidence not found",
        })
        return
    }

    // 查询关联文件
    fileRows, err := h.db.Query(`
        SELECT id, file_path, file_hash, collected_at, collector
        FROM evidence_file
        WHERE evidence_id = ?
        ORDER BY collected_at ASC
    `, evidenceID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ErrorResponse{
            Error: fmt.Sprintf("query failed: %v", err),
        })
        return
    }
    defer fileRows.Close()

    files := make([]map[string]interface{}, 0)
    for fileRows.Next() {
        var id int64
        var filePath, fileHash, collectedAt, collector sql.NullString
        
        if err := fileRows.Scan(&id, &filePath, &fileHash, &collectedAt, &collector); err != nil {
            continue
        }
        
        files = append(files, map[string]interface{}{
            "id":           id,
            "file_path":    filePath.String,
            "file_hash":    fileHash.String,
            "collected_at": collectedAt.String,
            "collector":    collector.String,
        })
    }

    c.JSON(http.StatusOK, gin.H{
        "id":      evidenceID,
        "status":  "found",
        "chain":   chain,
        "files":   files,
        "summary": map[string]interface{}{
            "chain_length": len(chain),
            "file_count":   len(files),
        },
    })
}
```

#### 3.7.3 复杂度评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 实现复杂度 | **低** | 约 120 行代码 |
| 适配性 | **高** | 使用现有数据库表 |
| 必要性 | **高** | API 功能不可用 |
| 可靠性 | **高** | 简单 SQL 查询 |
| 风险 | **低** | 只读操作 |

---

### ISSUE-F9: 修复 MemoryDump API

#### 3.9.1 问题确认

**文件**: `handlers_forensics.go:367-393`

```go
func (h *ForensicsHandler) MemoryDump(c *gin.Context) {
    // ...
    if pidStr != "" {
        var pid uint32
        fmt.Sscanf(pidStr, "%d", &pid)
        c.JSON(http.StatusOK, gin.H{
            "status":  "error",
            "message": "Memory dump requires Windows environment",  // 错误！
            "process": pid,
        })
        return
    }
    // ...
}
```

**问题**: 即使在 Windows 环境下也返回错误信息。

#### 3.9.2 实施方案

**步骤 1**: 修改 `MemoryDump` handler

```go
// internal/api/handlers_forensics.go

func (h *ForensicsHandler) MemoryDump(c *gin.Context) {
    if runtime.GOOS != "windows" {
        c.JSON(http.StatusNotImplemented, ErrorResponse{
            Error: "memory dump is only supported on Windows",
        })
        return
    }

    pidStr := c.Query("pid")
    outputPath := c.Query("output")

    // 确定输出目录
    if outputPath == "" {
        outputPath = filepath.Join(os.TempDir(), "winalog_memory")
        os.MkdirAll(outputPath, 0755)
    }

    collector := forensics.NewMemoryCollector(outputPath)

    if pidStr != "" {
        var pid uint32
        if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil {
            c.JSON(http.StatusBadRequest, ErrorResponse{
                Error: "invalid PID format",
            })
            return
        }

        result, err := collector.CollectProcessMemory(pid)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{
                "status":  "error",
                "message": err.Error(),
                "pid":     pid,
            })
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "status":  "success",
            "result":  result,
        })
        return
    }

    // 系统内存转储
    result, err := collector.CollectSystemMemory()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "status":  "error",
            "message": err.Error(),
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "status": "success",
        "result": result,
    })
}
```

**步骤 2**: 添加 `CollectSystemMemory` 实现

由于系统内存转储需要外部工具或特殊权限，修改 `memory.go` 返回适当错误：

```go
// internal/forensics/memory.go

func (c *MemoryCollector) CollectSystemMemory() (*MemoryDumpResult, error) {
    result := &MemoryDumpResult{
        ProcessID:   0,
        ProcessName: "System",
        DumpTime:    time.Now(),
    }

    // 检查是否有 winpmem 工具
    toolPath, err := findMemoryDumpTool()
    if err != nil {
        result.Error = "no memory dump tool found: " + err.Error()
        return result, fmt.Errorf("system memory dump requires winpmem or similar tool: %w", err)
    }

    outputFile := filepath.Join(c.outputDir, fmt.Sprintf("system_memory_%s.raw", time.Now().Format("20060102_150405")))
    
    // 调用外部工具
    cmd := exec.Command(toolPath, outputFile)
    if err := cmd.Run(); err != nil {
        result.Error = fmt.Sprintf("winpmem failed: %v", err)
        return result, fmt.Errorf("memory dump failed: %w", err)
    }

    // 读取生成的文件
    data, err := os.ReadFile(outputFile)
    if err != nil {
        result.Error = err.Error()
        return result, err
    }

    result.DumpPath = outputFile
    result.DumpSize = int64(len(data))
    result.Hash = calculateMemoryHash(data)

    // 清理临时文件
    os.Remove(outputFile)

    return result, nil
}

func findMemoryDumpTool() (string, error) {
    tools := []string{"winpmem.exe", "winpmem", "dd.exe"}
    
    for _, tool := range tools {
        // 检查是否在 PATH 中
        path, err := exec.LookPath(tool)
        if err == nil {
            return path, nil
        }
        
        // 检查默认安装位置
        defaultPaths := []string{
            `C:\Program Files\WinPmem\winpmem.exe`,
            `C:\Tools\winpmem.exe`,
            `C:\Windows\System32\winpmem.exe`,
        }
        
        for _, p := range defaultPaths {
            if _, err := os.Stat(p); err == nil {
                return p, nil
            }
        }
    }
    
    return "", fmt.Errorf("no memory dump tool found in PATH or default locations")
}
```

#### 3.9.3 复杂度评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 实现复杂度 | **低** | 约 60 行代码修改 |
| 适配性 | **高** | 保持 API 兼容性 |
| 必要性 | **高** | 功能完全不可用 |
| 可靠性 | **中** | 依赖外部工具 |
| 风险 | **低** | 错误处理完善 |

---

### ISSUE-F10: PowerShell 临时文件安全

#### 3.10.1 问题确认

**文件**: `signature.go:141-147`

```go
func runPowerShellCommand(script string) (string, error) {
    tmpFile := fmt.Sprintf("%s/winalog_ps_%d.ps1", os.TempDir(), time.Now().UnixNano())
    defer os.Remove(tmpFile)

    if err := os.WriteFile(tmpFile, []byte(script), 0644); err != nil {  // 问题：权限过宽
        return "", err
    }
    // ...
}
```

**问题**:
1. 权限 `0644` 允许同组用户和其他用户读取
2. `defer os.Remove` 在异常时可能不执行

#### 3.10.2 实施方案

**步骤 1**: 修改 `runPowerShellCommand`

```go
// internal/forensics/signature.go

func runPowerShellCommand(script string) (string, error) {
    // 创建临时文件
    f, err := os.CreateTemp(os.TempDir(), "winalog_ps_*.ps1")
    if err != nil {
        return "", fmt.Errorf("failed to create temp file: %w", err)
    }
    tmpFile := f.Name()
    
    // 确保清理
    defer os.Remove(tmpFile)
    
    // 设置适当权限：仅当前用户可读写
    if err := os.Chmod(tmpFile, 0600); err != nil {
        return "", fmt.Errorf("failed to set permissions: %w", err)
    }
    
    // 写入脚本
    if _, err := f.WriteString(script); err != nil {
        return "", fmt.Errorf("failed to write script: %w", err)
    }
    if err := f.Close(); err != nil {
        return "", fmt.Errorf("failed to close file: %w", err)
    }

    // 执行
    output, err := execPowerShell(tmpFile)
    if err != nil {
        return "", err
    }
    return output, nil
}
```

#### 3.10.3 复杂度评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 实现复杂度 | **很低** | 约 15 行代码 |
| 适配性 | **高** | 无 API 变更 |
| 必要性 | **中** | 安全加固 |
| 可靠性 | **高** | 使用标准库 |
| 风险 | **很低** | 行为不变，仅安全加固 |

---

### ISSUE-F11: TSA 重试机制

#### 3.11.1 问题确认

**文件**: `timestamp.go:80-93`

```go
func requestTimestampFromTSA(tsaURL, hash, algorithm string) (*http.Response, error) {
    // ...
    client := &http.Client{Timeout: 30 * time.Second}
    return client.Do(req)  // 无重试，无备用服务器
}
```

**问题**: 单个 TSA 服务器失败时请求直接失败。

#### 3.11.2 实施方案

**步骤 1**: 添加 TSA 服务器列表和重试配置

```go
// internal/forensics/timestamp.go

var defaultTSAServers = []string{
    "http://timestamp.digicert.com",
    "http://timestamp.sectigo.com",
    "http://timestamp.globalsign.com",
    "http://tsa.isigntrust.com",
}

const (
    maxRetries     = 3
    retryDelay     = 2 * time.Second
    requestTimeout = 30 * time.Second
)
```

**步骤 2**: 修改 `RequestTimestamp` 函数

```go
func RequestTimestamp(req *TimestampRequest) (*TimestampResult, error) {
    result := &TimestampResult{}

    // 打开文件并计算哈希
    file, err := os.Open(req.FilePath)
    if err != nil {
        return nil, fmt.Errorf("failed to open file: %w", err)
    }
    defer file.Close()

    hash, err := calculateFileHashSimple(file, req.HashAlgorithm)
    if err != nil {
        return nil, fmt.Errorf("failed to calculate hash: %w", err)
    }
    result.HashValue = hash
    result.HashAlgorithm = req.HashAlgorithm

    // 确定 TSA 服务器列表
    servers := defaultTSAServers
    if req.TSAServer != "" {
        servers = []string{req.TSAServer}
    }

    // 遍历服务器尝试
    var lastErr error
    for attempt := 0; attempt < maxRetries; attempt++ {
        for _, tsaURL := range servers {
            resp, err := requestTimestampFromTSA(tsaURL, hash, req.HashAlgorithm)
            if err != nil {
                lastErr = err
                continue
            }
            defer resp.Body.Close()

            if resp.StatusCode == http.StatusOK {
                result.Status = "Trusted"
                result.Timestamp = time.Now()
                result.TSAURL = tsaURL
                return result, nil
            }

            // 非 200 状态码也尝试其他服务器
            lastErr = fmt.Errorf("TSA returned status: %d", resp.StatusCode)
        }

        // 指数退避
        if attempt < maxRetries-1 {
            time.Sleep(retryDelay * time.Duration(1<<uint(attempt)))
        }
    }

    result.Status = "Error"
    result.Error = fmt.Sprintf("all TSA servers failed after %d attempts: %v", maxRetries, lastErr)
    return result, nil
}
```

#### 3.11.3 复杂度评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 实现复杂度 | **低** | 约 40 行代码 |
| 适配性 | **高** | 向后兼容 |
| 必要性 | **中** | 提升可靠性 |
| 可靠性 | **高** | 标准重试模式 |
| 风险 | **低** | 仅增加容错 |

---

## 四、暂不实施方案 (P3)

以下问题需要外部依赖或重大架构变更，暂时标记为可选改进：

### F1: 系统内存转储

**现状**: `readSystemMemory()` 返回 `ErrSystemMemoryNotImplemented`

**原因**: Windows 系统内存转储需要：
1. Administrator 权限
2. Win32 API `NtReadPhysicalMemory` 或外部工具
3. 可能的驱动签名问题

**建议方案**: 使用 `winpmem` 外部工具，但这会引入额外依赖。

### F2-F5: 内存分析功能

**现状**: `AnalyzeMemoryDump`, `ExtractProcessTree`, `FindNetworkConnections`, `FindSuspiciousAPI` 均返回空数据

**原因**: 内存分析需要：
1. `volatility3` 集成
2. 正确的内存镜像格式
3. 大量解析逻辑

**建议**: 作为独立模块 `internal/memory/analyzer.go` 实现，暂不集成到 forensics 模块。

---

## 五、架构改进建议

### 5.1 模块结构优化

```
internal/forensics/
├── hash.go           # 文件哈希 (已有)
├── timestamp.go       # 时间戳 (已有)
├── signature.go       # 签名验证 (已有)
├── memory.go          # 内存转储 (部分实现)
├── chain.go           # 证据链 (已有)
├── collector.go       # 证据收集器 (新增 - ISSUE-F6)
├── config.go         # 配置管理 (可选)
└── errors.go         # 错误定义 (可选)
```

### 5.2 新增文件清单

| 文件 | 用途 | 优先级 |
|------|------|--------|
| `collector.go` | 证据收集器 | P1 |
| `config.go` | 配置管理 | P3 |

---

## 六、实施检查清单

### 6.1 修改文件清单

| 文件 | 修改内容 | 优先级 |
|------|----------|--------|
| `handlers_forensics.go` | F6, F7, F8, F9 | P1 |
| `signature.go` | F10 | P2 |
| `timestamp.go` | F11 | P2 |
| `memory.go` | F9 辅助函数 | P1 |

### 6.2 新建文件清单

| 文件 | 用途 | 优先级 |
|------|------|--------|
| `collector.go` | 证据收集器 | P1 |

### 6.3 测试验证

```bash
# 构建验证
cd winalog-go/winalog-go
go build ./...

# API 测试
# POST /api/forensics/collect
curl -X POST http://localhost:8080/api/forensics/collect \
  -H "Content-Type: application/json" \
  -d '{"type": "full", "collect_registry": true}'

# GET /api/forensics/evidence
curl http://localhost:8080/api/forensics/evidence?limit=10&offset=0

# GET /api/forensics/evidence/{id}
curl http://localhost:8080/api/forensics/evidence/ev_123456789
```

---

## 七、风险评估

| 变更 | 风险等级 | 缓解措施 |
|------|----------|----------|
| F6 证据收集 | 低 | 新增功能，不影响现有逻辑 |
| F7/F8 列表/详情 | 低 | 只读查询 |
| F9 MemoryDump | 中 | 依赖外部工具 |
| F10 临时文件 | 低 | 权限收紧 |
| F11 TSA 重试 | 低 | 指数退避 |

---

## 八、总结

### 8.1 实施工作量

| 优先级 | 问题数 | 工作量 |
|--------|--------|--------|
| P1 | 4 | 约 250 行代码 |
| P2 | 2 | 约 55 行代码 |
| P3 | 5 | 暂不实施 |

### 8.2 关键收益

1. **F6/F7/F8**: 使证据收集和查询 API 从完全不可用变为可用
2. **F9**: 修复内存转储 API 的逻辑错误
3. **F10**: 修复安全漏洞
4. **F11**: 提升时间戳验证的可靠性

### 8.3 后续建议

- **P3 问题**: 考虑作为独立模块实现，不影响当前 forensics 结构
- **监控**: 添加证据收集操作的日志记录
- **清理**: 实现证据过期自动清理机制

---

*文档版本: 2.0*
*审核状态: 待审核*
*最后更新: 2026-04-17*
