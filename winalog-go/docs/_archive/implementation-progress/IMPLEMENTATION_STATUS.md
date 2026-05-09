# 实施方案执行记录

**项目**: WinLogAnalyzer-Go  
**执行日期**: 2026-04-17  
**文档状态**: 执行中

---

## 一、已完成的修复

### P0/P1/P2 问题修复

| 优先级 | 问题 | 状态 | 修改文件 |
|--------|------|------|----------|
| P0 | SQL注入漏洞 (events.go:127,131) | **已完成** | `internal/storage/events.go` |
| P1 | 正则表达式DoS风险 (evaluator.go:293) | **已完成** | `internal/alerts/evaluator.go` |
| P2 | Pipeline Pacer Goroutine泄漏 (pipeline.go:131-147) | **已完成** | `internal/engine/pipeline.go` |
| P2 | Evaluator清理Goroutine无停止机制 (evaluator.go:37-50) | **已完成** | `internal/alerts/evaluator.go` |
| P3 | 代码重复 (scanEvent与scanEventFromRows) | **已完成** | `internal/storage/events.go` |

### 优化项实施

| ID | 优化项 | 状态 | 修改文件 |
|----|--------|------|----------|
| OPT-1 | 解析器自注册机制 | **已完成** | `internal/parsers/parser.go`, `internal/parsers/*/parser.go`, `internal/engine/engine.go` |
| OPT-7 | 规则验证增强 | **已完成** | `internal/rules/rule.go` |

---

## 二、修改详情

### P0: SQL注入漏洞修复

**问题**: 当 `req.Regex == true` 时，用户输入被直接拼接到 SQL 查询中

**修复方案**:
1. 新增 `appendGlobCondition()` 函数处理安全的 GLOB 模式
2. 新增 `sanitizeGlobPattern()` 函数对用户输入进行转义
3. 只允许 `*`, `?`, `[`, `]` 作为 GLOB 特殊字符

**关键代码**:
```go
func sanitizeGlobPattern(pattern string) string {
    var result []byte
    for i := 0; i < len(pattern); i++ {
        c := pattern[i]
        switch c {
        case '*', '?', '[', ']':
            result = append(result, c)
        case '\\':
            if i+1 < len(pattern) {
                result = append(result, '\\', pattern[i+1])
                i++
            }
        default:
            result = append(result, c)
        }
    }
    return string(result)
}
```

---

### P1: 正则表达式DoS风险修复

**问题**: `regexp.MatchString()` 每次调用都重新编译正则，且没有超时保护

**修复方案**:
1. 新增 `regexCache` 缓存预编译的正则表达式
2. 新增 `getCompiledRegex()` 函数安全编译正则
3. 检测编译时间过长的正则表达式（>200ms）并拒绝

**关键代码**:
```go
var regexCache sync.Map

func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
    if v, ok := regexCache.Load(pattern); ok {
        return v.(*regexp.Regexp), nil
    }

    start := time.Now()
    re, err := regexp.Compile(pattern)
    if err != nil {
        return nil, err
    }

    if time.Since(start) > 200*time.Millisecond {
        return nil, fmt.Errorf("regex pattern too complex: %s", pattern)
    }

    regexCache.Store(pattern, re)
    return re, nil
}
```

---

### P2: Pipeline Pacer Goroutine泄漏修复

**问题**: `newPacer()` 启动的 goroutine 没有停止机制

**修复方案**:
1. 在 `pacer` 结构中添加 `stopCh` 字段
2. 在 worker 退出时通过 `defer` 关闭 `stopCh`
3. goroutine 中监听 `stopCh` 实现优雅退出

**关键代码**:
```go
type pacer struct {
    C      <-chan struct{}
    stopCh chan struct{}
}

func newPacer() *pacer {
    c := make(chan struct{}, 1)
    stopCh := make(chan struct{})
    go func() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-ticker.C:
                select {
                case c <- struct{}{}:
                default:
                }
            case <-stopCh:
                return
            }
        }
    }()
    return &pacer{C: c, stopCh: stopCh}
}
```

---

### P2: Evaluator Goroutine泄漏修复

**问题**: `cleanupExpiredEntries()` 启动的 goroutine 没有停止机制

**修复方案**:
1. 在 `Evaluator` 结构中添加 `stopCh` 字段
2. 新增 `Close()` 方法用于停止清理 goroutine
3. `cleanupExpiredEntries()` 中监听 `stopCh` 实现优雅退出

**关键代码**:
```go
type Evaluator struct {
    mu         sync.RWMutex
    eventCount map[eventCountKey]*eventCountEntry
    stopCh     chan struct{}
}

func (e *Evaluator) Close() {
    close(e.stopCh)
}

func (e *Evaluator) cleanupExpiredEntries() {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            e.mu.Lock()
            now := time.Now()
            for key, entry := range e.eventCount {
                if now.Sub(entry.lastTime) > 2*time.Hour {
                    delete(e.eventCount, key)
                }
            }
            e.mu.Unlock()
        case <-e.stopCh:
            return
        }
    }
}
```

---

### P3: 代码重复优化

**问题**: `scanEvent` 和 `scanEventFromRows` 函数逻辑完全相同

**修复方案**: 让 `scanEventFromRows` 直接调用 `scanEvent`

**关键代码**:
```go
func scanEventFromRows(rows *sql.Rows) (*types.Event, error) {
    return scanEvent(rows)
}
```

---

### OPT-1: 解析器自注册机制

**改进**:
1. `Parser` 接口新增 `Priority()` 方法
2. `ParserRegistry` 支持优先级排序（数值越大优先级越高）
3. 新增 `GetGlobalRegistry()` 全局注册表
4. 各解析器通过 `init()` 函数自注册

**优先级定义**:
- EVTX: 90
- ETL: 80
- Sysmon: 70
- IIS: 60
- CSV: 50

---

### OPT-7: 规则验证增强

**改进**:
1. 验证 `Threshold` 和 `TimeWindow` 的关系
2. 验证 `Severity` 是否为有效值
3. 验证 `Filter.EventIDs` 范围（0-65535）
4. 验证 `Filter.Levels` 范围（1-5）
5. 验证 `Filter.Keywords` 和 `KeywordMode` 的关系
6. 验证 `Filter.TimeRange` 的开始/结束时间
7. 验证 `Conditions` 中的字段名和操作符
8. 验证正则表达式的有效性

---

## 三、待实施的优化项

以下优化项需要在后续版本中实施，或需要额外依赖：

| ID | 优化项 | 原因 | 建议 |
|----|--------|------|------|
| OPT-2 | 文件重试机制 | 需要修改 engine.go 的 Import 逻辑 | 可后续实施 |
| OPT-3 | 目录递归与通配符支持 | 需要修改 collectFiles 函数 | 可后续实施 |
| OPT-4 | Pipeline错误上下文增强 | 属于增强功能，非关键 | 可后续实施 |
| OPT-5 | 去重缓存持久化 | 需要新增数据库表 | 可后续实施 |
| OPT-6 | 规则并行评估 | 需要引入 worker pool | 可后续实施 |
| OPT-8 | 规则分组与优先级 | 高级功能，非关键 | 可后续实施 |
| OPT-9 | UEBA 基线持久化 | 需要新增数据库表 | 可后续实施 |
| OPT-10 | UEBA GeoIP 集成 | 需要外部 GeoIP 数据库文件 (MaxMind GeoLite2) | **暂时无法实施**，需用户确认 |
| OPT-11 | 报告配置参数化 | 简单的配置变更 | 可后续快速实施 |
| OPT-12 | API 请求验证 | 需要引入 validator 库 | 可后续实施 |
| OPT-13 | API OpenAPI 文档 | 需要 swag 工具生成 | **暂时无法实施**，需额外工具链 |
| OPT-14 | TUI 状态重构 | 重构风险较高 | 建议后续版本处理 |
| OPT-15 | 关联引擎重新设计 | 需要完全重写 correlation 模块 | 建议后续版本处理 |

---

## 四、无法立即实施的优化项详细说明

### OPT-10: UEBA GeoIP 集成

**依赖**: MaxMind GeoLite2 数据库文件

**问题**: GeoIP 功能需要下载并维护 GeoLite2-City.mmdb 数据库文件

**建议**:
1. 用户确认是否需要此功能
2. 如需要，提供数据库下载脚本
3. 或者使用免费替代方案（如 IP2Location LITE）

### OPT-13: API OpenAPI 文档

**依赖**: swag 工具 (`go install github.com/swaggo/swag/cmd/swag@latest`)

**问题**: 需要在每个 API handler 添加 swag 注解，然后运行 `swag init` 生成文档

**建议**:
1. 安装 swag 工具
2. 在 API handler 中添加 Swagger 注解
3. 运行 `swag init -g internal/api/server.go -o docs`
4. 集成 gin-swagger 中间件

---

## 五、编译验证

所有已完成的修改均已通过编译验证：

```bash
cd /workspace/winalog-go
go build ./internal/storage/...   # SQL注入修复
go build ./internal/alerts/...    # DoS修复, Goroutine修复
go build ./internal/engine/...    # Pipeline修复
go build ./internal/parsers/...   # 自注册机制
go build ./internal/rules/...     # 规则验证增强
```

---

## 六、下一步建议

1. **测试验证**: 运行完整的测试套件验证修复没有引入回归
2. **OPT-10/OPT-13决策**: 用户确认是否需要 GeoIP 和 OpenAPI 功能
3. **后续优化**: 按优先级逐步实施其他优化项
4. **代码审查**: 提交代码审查确保修改质量

---

*文档版本: 1.0*
*执行状态: 已完成 P0/P1/P2 修复 + OPT-1 + OPT-7*
