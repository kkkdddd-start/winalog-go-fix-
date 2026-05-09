# Forensics 模块

**路径**: `internal/forensics/`

取证功能模块，提供文件哈希、数字签名验证、证据链和内存转储功能。

## 组件

| 组件 | 文件 | 说明 |
|------|------|------|
| `hash.go` | 文件哈希计算 | SHA256/MD5/SHA1 |
| `signature.go` | Authenticode 签名验证 | Windows 平台 |
| `chain.go` | 证据链 | 区块链式存储 |
| `timestamp.go` | RFC 3161 时间戳 | 可信时间戳 |
| `memory.go` | 内存转储 | Process/System |

## Hash 文件哈希

### HashResult

```go
type HashResult struct {
    FilePath string `json:"file_path"`
    SHA256   string `json:"sha256"`
    MD5      string `json:"md5,omitempty"`
    SHA1     string `json:"sha1,omitempty"`
    Size     int64  `json:"size"`
}
```

### 计算文件哈希

```go
func CalculateFileHash(path string) (*HashResult, error)
```

**示例**:

```go
result, err := forensics.CalculateFileHash("C:\\Windows\\System32\\cmd.exe")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("SHA256: %s\n", result.SHA256)
fmt.Printf("MD5: %s\n", result.MD5)
fmt.Printf("Size: %d bytes\n", result.Size)
```

### 验证文件哈希

```go
func VerifyFileHash(path, expectedSHA256 string) (bool, *HashResult, error)
```

**示例**:

```go
match, result, err := forensics.VerifyFileHash("file.exe", "abc123...")
if match {
    fmt.Println("File hash matches")
}
```

## Signature 签名验证

### SignatureResult

```go
type SignatureResult struct {
    Status      string     `json:"status"`
    Signer      string     `json:"signer,omitempty"`
    Issuer      string     `json:"issuer,omitempty"`
    Thumbprint  string     `json:"thumbprint,omitempty"`
    NotBefore   *time.Time `json:"not_before,omitempty"`
    NotAfter    *time.Time `json:"not_after,omitempty"`
    Description string     `json:"description,omitempty"`
}
```

**Status 值**:
| 值 | 说明 |
|-----|------|
| `Valid` | 签名有效 |
| `Invalid` | 签名无效 |
| `Unsupported` | 平台不支持 |
| `None` | 未签名 |
| `Error` | 验证错误 |

### 验证签名

```go
var (
    ErrPlatformNotSupported = fmt.Errorf("signature verification is only supported on Windows")
    ErrPathIsDirectory      = fmt.Errorf("path is a directory")
)

func VerifySignature(path string) (*SignatureResult, error)
func IsSigned(path string) (bool, *SignatureResult, error)
```

**注意**: Authenticode 验证需要 Windows API，仅在 Windows 平台可用。

## Chain 证据链

基于区块链思想的证据完整性验证。

### EvidenceChain

```go
type EvidenceChain struct {
    ID           string    `json:"id"`
    Timestamp    time.Time `json:"timestamp"`
    Operator     string    `json:"operator"`
    Action       string    `json:"action"`
    InputHash    string    `json:"input_hash"`
    OutputHash   string    `json:"output_hash"`
    PreviousHash string    `json:"previous_hash"`
    FilePath     string    `json:"file_path,omitempty"`
    Description  string    `json:"description,omitempty"`
}
```

**哈希计算**:

```go
func (e *EvidenceChain) CalculateHash() string {
    data := fmt.Sprintf("%s|%s|%s|%s|%d",
        e.ID, e.Operator, e.Action, e.InputHash, e.Timestamp.UnixNano())
    hash := sha256.Sum256([]byte(data))
    return hex.EncodeToString(hash[:])
}

func (e *EvidenceChain) Link(previousHash string) {
    e.PreviousHash = previousHash
    e.OutputHash = e.CalculateHash()
}
```

### EvidenceManifest

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

type EvidenceFile struct {
    ID          string    `json:"id"`
    FilePath    string    `json:"file_path"`
    FileHash    string    `json:"file_hash"`
    Size        int64     `json:"size"`
    CollectedAt time.Time `json:"collected_at"`
    Collector   string    `json:"collector"`
}
```

### 创建证据链

```go
// 创建证据项
chain := forensics.NewEvidenceChain("operator", "collect", "input_hash")
chain.Link("")  // 链接到前一个 (空表示创始块)

// 创建证据清单
manifest := forensics.GenerateManifest(files, "collector_name", "machine_id")

// 添加链条目
manifest.AddChainEntry(chain)
```

## Timestamp RFC 3161

可信时间戳服务。

```go
type TimestampResult struct {
    Timestamp   time.Time
    HashAlgorithm string
    Hash         string
    SerialNumber string
}

func RequestTimestamp(data []byte, TSAUrl string) (*TimestampResult, error)
func VerifyTimestamp(data []byte, result *TimestampResult) (bool, error)
```

## Memory 内存转储

### MemoryDumpResult

```go
type MemoryDumpResult struct {
    ProcessID   uint32            `json:"process_id"`
    ProcessName string            `json:"process_name"`
    DumpPath    string            `json:"dump_path"`
    DumpSize    int64             `json:"dump_size"`
    DumpTime    time.Time         `json:"dump_time"`
    Hash        string            `json:"hash"`
    Modules     []MemoryModule    `json:"modules,omitempty"`
    Permissions MemoryPermissions `json:"permissions"`
    Error       string            `json:"error,omitempty"`
}

type MemoryModule struct {
    BaseAddress uint64 `json:"base_address"`
    Size        uint64 `json:"size"`
    Name        string `json:"name"`
    Path        string `json:"path"`
}

type MemoryPermissions struct {
    Readable    bool `json:"readable"`
    Writable    bool `json:"writable"`
    Executable  bool `json:"executable"`
    CopyOnWrite bool `json:"copy_on_write"`
}
```

### MemoryCollector

```go
type MemoryCollector struct {
    outputDir      string
    includeModules bool
    includeStacks  bool
}

func NewMemoryCollector(outputDir string) *MemoryCollector
func (c *MemoryCollector) SetIncludeModules(include bool)
func (c *MemoryCollector) SetIncludeStacks(include bool)
func (c *MemoryCollector) CollectProcessMemory(pid uint32) (*MemoryDumpResult, error)
func (c *MemoryCollector) CollectSystemMemory() (*MemoryDumpResult, error)
```

**注意**: 内存转储需要 Windows API，当前实现返回 `ErrProcessMemoryNotImplemented` 或 `ErrSystemMemoryNotImplemented`。

## 错误定义

```go
var (
    ErrProcessMemoryNotImplemented = fmt.Errorf("process memory dump not implemented: requires windows API calls")
    ErrSystemMemoryNotImplemented  = fmt.Errorf("system memory dump not implemented: requires windows API calls")
)
```

## 使用示例

```go
// 1. 计算证据文件哈希
result, err := forensics.CalculateFileHash("evidence.log")
if err != nil {
    log.Fatal(err)
}

// 2. 验证签名 (Windows)
isSigned, sig, err := forensics.IsSigned("file.exe")
if err != nil {
    log.Printf("Signature check failed: %v", err)
} else if !isSigned {
    fmt.Println("File is not signed")
}

// 3. 创建证据链
chain := forensics.NewEvidenceChain("analyst", "hash_verification", result.SHA256)
manifest := forensics.GenerateManifest([]*forensics.EvidenceFile{
    {
        FilePath:    "evidence.log",
        FileHash:    result.SHA256,
        Size:        result.Size,
        CollectedAt: time.Now(),
        Collector:   "analyst",
    },
}, "analyst", "WORKSTATION-01")

manifest.AddChainEntry(chain)
```
