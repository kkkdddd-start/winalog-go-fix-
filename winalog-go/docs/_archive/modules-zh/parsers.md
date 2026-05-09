# Parsers 模块

**路径**: `internal/parsers/`

日志解析器注册表与实现，支持多种 Windows 日志格式。

## Parser 接口

```go
type Parser interface {
    // CanParse 判断是否能解析该文件
    CanParse(path string) bool
    
    // Parse 返回事件流 Channel
    Parse(path string) <-chan *types.Event
    
    // ParseBatch 批量解析
    ParseBatch(path string) ([]*types.Event, error)
    
    // GetType 返回解析器类型
    GetType() string
}
```

## ParserRegistry

```go
type ParserRegistry struct {
    parsers map[string]Parser
}

func NewParserRegistry() *ParserRegistry

// 注册解析器
func (r *ParserRegistry) Register(p Parser)

// 根据路径获取解析器 (自动选择)
func (r *ParserRegistry) Get(path string) Parser

// 根据类型获取解析器
func (r *ParserRegistry) GetByType(parserType string) Parser

// 列出所有解析器
func (r *ParserRegistry) List() []Parser

// 列出所有解析器类型
func (r *ParserRegistry) ListTypes() []string
```

## 支持的格式

| 格式 | Parser | 文件扩展名 | 说明 |
|------|--------|-----------|------|
| Windows Event Log | `EvtxParser` | .evtx | Windows 事件日志 |
| Event Trace Log | `EtlParser` | .etl | ETW 跟踪日志 |
| CSV/LOG | `CsvParser` | .csv, .log, .txt | 自定义格式 |
| IIS W3C Extended | `IISParser` | .log | IIS 日志 |
| Sysmon | `SysmonParser` | .evtx | Sysmon 事件 |

## EVTX 解析器

**路径**: `internal/parsers/evtx/parser.go`

解析 Windows Event Log 文件 (`.evtx`)。

```go
type EvtxParser struct{}

func NewEvtxParser() *EvtxParser
```

**特点**:
- 使用 `richardlehane/mscfb` 库解析
- 流式解析，内存占用低
- 支持批量解析

## ETL 解析器

**路径**: `internal/parsers/etl/parser.go`

解析 Event Trace Log 文件 (`.etl`)。

```go
type EtlParser struct{}

func NewEtlParser() *EtlParser
```

## CSV 解析器

**路径**: `internal/parsers/csv/parser.go`

解析 CSV/LOG/TXT 文件。

```go
type CsvParser struct {
    Delimiter rune
    HasHeader bool
}

func NewCsvParser() *CsvParser
```

**配置**:
```go
parser := csv.NewCsvParser()
parser.Delimiter = ','  // 自定义分隔符
parser.HasHeader = true // 首行为表头
```

## IIS 解析器

**路径**: `internal/parsers/iis/parser.go`

解析 IIS W3C Extended 日志格式。

```go
type IISParser struct{}

func NewIISParser() *IISParser
```

**支持的字段**:
- date, time, s-ip, cs-method, cs-uri-stem, cs-uri-query
- s-port, cs-username, c-ip, cs(User-Agent)
- cs(Referer), sc-status, sc-substatus, sc-win32-status

## Sysmon 解析器

**路径**: `internal/parsers/sysmon/parser.go`

解析 Sysmon 事件 (Event ID 1-22)。

```go
type SysmonParser struct{}

func NewSysmonParser() *SysmonParser
```

**支持的 Event ID**:
| Event ID | 说明 |
|----------|------|
| 1 | Process Create |
| 2 | File Create Time |
| 3 | Network Connection |
| 5 | Process Terminated |
| 6 | Driver Loaded |
| 7 | Image Loaded |
| 8 | CreateRemoteThread |
| 9 | RawAccessRead |
| 10 | ProcessAccess |
| 11 | FileCreate |
| 12 | RegistryEvent |
| 13 | RegistryEvent |
| 14 | RegistryEvent |
| 15 | FileCreateStreamHash |
| 17 | PipeEvent |
| 18 | PipeEvent |
| 19 | WmiEvent |
| 20 | WmiEvent |
| 21 | WmiEvent |
| 22 | DNS Query |

## 使用示例

### 自动选择解析器

```go
registry := parsers.NewParserRegistry()
registry.Register(evtx.NewEvtxParser())
registry.Register(etl.NewEtlParser())
registry.Register(csv.NewCsvParser())

parser := registry.Get("security.evtx")
if parser == nil {
    return fmt.Errorf("no parser for this file")
}

events := parser.Parse("security.evtx")
for event := range events {
    // 处理事件
}
```

### 批量解析

```go
events, err := parser.ParseBatch("security.evtx")
if err != nil {
    return err
}
for _, event := range events {
    // 处理事件
}
```

### 解析多个文件

```go
files := []string{"security.evtx", "system.evtx", "application.evtx"}

for _, file := range files {
    parser := registry.Get(file)
    if parser == nil {
        continue
    }
    
    for event := range parser.Parse(file) {
        // 处理事件
    }
}
```
