# 取证模块 (Forensics)

## 概述

取证模块提供证据收集和完整性验证功能,包括证据链构建、SHA256 哈希校验、数字签名验证和时间戳服务。

## 目录

- [核心结构](#核心结构)
- [EvidenceChain](#evidencechain)
- [EvidenceManifest](#evidencemanifest)
- [EvidenceFile](#evidencefile)
- [哈希与签名](#哈希与签名)

## 核心结构

### EvidenceChain

证据链中的单个环节,使用 SHA256 哈希链接保证不可篡改性:

```go
// internal/forensics/chain.go
type EvidenceChain struct {
    ID           string    `json:"id"`
    Timestamp    time.Time `json:"timestamp"`
    Operator     string    `json:"operator"`
    Action       string    `json:"action"`
    InputHash    string    `json:"input_hash"`
    OutputHash   string    `json:"output_hash"`
    PreviousHash string    `json:"previous_hash"`  // 前一环节的哈希
    FilePath     string    `json:"file_path,omitempty"`
    Description  string    `json:"description,omitempty"`
}
```

### EvidenceManifest

证据清单,包含文件列表和完整的证据链:

```go
type EvidenceManifest struct {
    ID          string           `json:"id"`
    CreatedAt   time.Time        `json:"created_at"`
    CollectedBy string           `json:"collected_by"`
    MachineID   string           `json:"machine_id"`
    Files       []*EvidenceFile  `json:"files"`
    Chain       []*EvidenceChain `json:"chain"`
    TotalSize   int64            `json:"total_size"`
    Hash        string           `json:"manifest_hash"`
}
```

### EvidenceFile

单个证据文件的记录:

```go
type EvidenceFile struct {
    ID          string    `json:"id"`
    FilePath    string    `json:"file_path"`
    FileHash    string    `json:"file_hash"`
    Size        int64     `json:"size"`
    CollectedAt time.Time `json:"collected_at"`
    Collector   string    `json:"collector"`
}
```

## EvidenceChain

### 构造函数

```go
func NewEvidenceChain(operator, action, inputHash string) *EvidenceChain
```

- `operator`: 操作者
- `action`: 操作描述
- `inputHash`: 输入数据的 SHA256 哈希

### 核心方法

| 方法 | 说明 |
|------|------|
| `CalculateHash()` | 计算当前环节的 SHA256 哈希 |
| `Link(previousHash)` | 链接到前一环节,设置 `PreviousHash` 并计算 `OutputHash` |

### 哈希计算

```go
func (e *EvidenceChain) CalculateHash() string {
    data := fmt.Sprintf("%s|%s|%s|%s|%d",
        e.ID, e.Operator, e.Action, e.InputHash, e.Timestamp.UnixNano())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
```

哈希内容包含: ID + 操作者 + 操作 + 输入哈希 + 时间戳

### 链式链接

```go
func (e *EvidenceChain) Link(previousHash string) {
    e.PreviousHash = previousHash
    e.OutputHash = e.CalculateHash()
}
```

## EvidenceManifest

### 生成函数

```go
func GenerateManifest(files []*EvidenceFile, collectedBy, machineID string) *EvidenceManifest
```

创建新的证据清单,自动计算文件总大小和清单哈希。

### 核心方法

| 方法 | 说明 |
|------|------|
| `AddChainEntry(entry)` | 添加证据链环节,自动链接到前一环节 |
| `CalculateHash()` | 计算清单的 SHA256 哈希 |

### 清单哈希计算

```go
func (m *EvidenceManifest) CalculateHash() string {
    data := fmt.Sprintf("%s|%s|%s|%d|%d|%d",
        m.ID, m.CollectedBy, m.MachineID, fileCount, m.TotalSize, m.CreatedAt.UnixNano())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}
```

## ID 生成

使用 `crypto/rand` 生成 16 字节随机 ID:

```go
func generateID() string {
    bytes := make([]byte, 16)
    if _, err := rand.Read(bytes); err != nil {
        // 回退方案:使用时间戳哈希
        timestamp := fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
        hash := sha256.Sum256([]byte(timestamp))
        return hex.EncodeToString(hash[:])[:16]
    }
    return hex.EncodeToString(bytes)
}
```

## 哈希与签名

### 安全特性

| 特性 | 实现方式 |
|------|---------|
| 证据完整性 | SHA256 哈希链 (每个环节链接前一环节) |
| 清单完整性 | 清单整体 SHA256 哈希 |
| 文件完整性 | 每个证据文件的 SHA256 哈希 |
| ID 安全性 | 密码学安全的随机数 (crypto/rand) |

### 取证文件

| 文件 | 说明 |
|------|------|
| `chain.go` | EvidenceChain, EvidenceManifest, EvidenceFile |
| `signatures.go` | 数字签名验证 |
| `timestamp.go` | 时间戳服务 (TSA) |
| `collector.go` | 证据收集器 (注册表/预取/日志) |
