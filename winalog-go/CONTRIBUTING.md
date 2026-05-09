# 贡献指南

欢迎为 WinLogAnalyzer-Go 贡献代码！本文档将指导你如何有效地参与项目。

---

## 🚀 快速开始

### 1. Fork 仓库

在 GitHub 上点击 "Fork" 按钮创建你自己的副本。

### 2. 克隆仓库

```bash
git clone https://github.com/YOUR_USERNAME/winalog-go.git
cd winalog-go
```

### 3. 添加上游仓库

```bash
git remote add upstream https://github.com/kkkdddd-start/winalog-go-fix-.git
git fetch upstream
```

### 4. 创建分支

```bash
git checkout -b feature/your-feature-name
# 或
git checkout -b fix/issue-123
```

### 5. 开发并测试

```bash
# 安装依赖
go mod download
cd internal/gui && npm install

# 运行测试
make test

# 构建
make build
```

### 6. 提交并推送

```bash
git add .
git commit -m "feat: add amazing feature"
git push origin feature/your-feature-name
```

### 7. 创建 Pull Request

在 GitHub 上创建 Pull Request，描述你的更改。

---

## 📝 代码规范

### Go 代码

遵循 [Effective Go](https://golang.org/doc/effective_go.html) 和 [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)。

**命名规范**:
```go
// ✅ 好的命名
type QueryHandler struct { ... }
func validateSQL(sql string) error { ... }
var allowedTables = map[string]bool{ ... }

// ❌ 避免的命名
type queryHandler struct { ... }  // 类型名应大写开头
func ValidateSQL(sql string) error { ... }  // 函数名小写开头 (私有)
var tbl = map[string]bool{ ... }  // 避免缩写
```

**错误处理**:
```go
// ✅ 好的错误处理
if err != nil {
    return fmt.Errorf("failed to query database: %w", err)
}

// ❌ 避免的做法
if err != nil {
    log.Fatal(err)  // 不要直接退出
}
```

**注释**:
```go
// ✅ 好的注释
// validateSQL 验证 SQL 查询的安全性
// 返回 error 如果查询包含禁止的操作
func validateSQL(sql string) error { ... }

// ❌ 避免的注释
// 验证 SQL
func validateSQL(sql string) error { ... }  // 太简单
```

### TypeScript/React 代码

**命名规范**:
```typescript
// ✅ 好的命名
interface QueryRequest { ... }
const validateSQL = (sql: string) => { ... }
function Dashboard() { ... }

// ❌ 避免的命名
interface queryRequest { ... }  // 接口名应大写开头
const validate_sql = (sql: string) => { ... }  // 使用驼峰式
```

**React Hooks**:
```typescript
// ✅ 好的实践
const [loading, setLoading] = useState(false)
useEffect(() => {
  fetchData()
}, [dependency])

// ❌ 避免的做法
const [data, setData] = useState(null)  // 使用类型安全的默认值
useEffect(() => {
  fetchData()
}, [])  // 避免空依赖，除非确实只需要执行一次
```

---

## 🧪 测试要求

### 单元测试

所有新功能必须包含单元测试：

```go
func TestValidateSQL(t *testing.T) {
    tests := []struct {
        name    string
        sql     string
        wantErr bool
    }{
        {"valid select", "SELECT * FROM users", false},
        {"invalid drop", "DROP TABLE users", true},
        {"invalid comment", "SELECT * FROM users--", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validateSQL(tt.sql)
            if (err != nil) != tt.wantErr {
                t.Errorf("validateSQL() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### 运行测试

```bash
# 运行所有测试
make test

# 运行特定包测试
go test ./internal/api/...

# 带覆盖率
go test -cover ./...
```

---

## 📋 Pull Request 流程

### PR 标题格式

```
<type>(<scope>): <description>

示例:
feat(api): add SQL injection protection
fix(dashboard): prevent crash when entries is null
docs(readme): update security configuration
```

**类型说明**:
- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式 (不影响功能)
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建/工具链

### PR 描述模板

```markdown
## 变更说明
简要描述此 PR 的目的。

## 相关问题
Fixes #123

## 测试步骤
1. ...
2. ...
3. ...

## 截图 (如适用)
如果有 UI 变更，请提供截图。

## 检查清单
- [ ] 代码通过测试
- [ ] 添加/更新单元测试
- [ ] 更新文档
- [ ] 遵循代码规范
```

---

## 📚 文档更新

### 何时更新文档

- **用户文档**: 功能变更影响用户时
- **开发文档**: API 或架构变更时
- **CHANGELOG.md**: 每次 PR 都需要

### 文档位置

| 文档类型 | 位置 |
|----------|------|
| 用户指南 | `docs/user/USER_GUIDE.md` |
| 快速开始 | `docs/user/QUICKSTART.md` |
| API 参考 | `docs/developer/API.md` |
| 架构设计 | `docs/developer/ARCHITECTURE.md` |
| 功能清单 | `docs/reference/FEATURES.md` |

---

## 🔍 代码审查

### 审查标准

审查者将关注：

1. **功能正确性**
   - 代码是否实现预期功能
   - 边界条件是否处理
   - 错误处理是否完善

2. **代码质量**
   - 是否遵循 DRY 原则
   - 命名是否清晰
   - 函数是否单一职责

3. **性能影响**
   - 是否有明显的性能瓶颈
   - 是否有内存泄漏风险
   - 数据库查询是否优化

4. **安全性**
   - 是否有 SQL 注入风险
   - 是否有 XSS 风险
   - 是否泄露敏感信息

5. **测试覆盖**
   - 是否包含单元测试
   - 测试用例是否全面
   - 测试是否通过

### 响应时间

- **工作日**: 24 小时内响应
- **周末**: 48 小时内响应
- **紧急修复**: 尽快响应

---

## 🐛 报告问题

### Bug 报告模板

```markdown
**描述**
清晰简洁地描述 bug。

**复现步骤**
1. 执行 '...'
2. 点击 '...'
3. 看到错误 '...'

**预期行为**
期望发生什么。

**实际行为**
实际发生了什么。

**环境信息**
- 版本：v2.5.0
- 平台：Windows 11 / Linux Ubuntu 22.04
- 配置文件：(如相关)

**截图**
如适用，添加截图帮助说明问题。

**日志**
```
粘贴相关日志内容
```
```

### 提交 Bug 报告

1. 搜索现有 issues，避免重复
2. 使用 Bug 报告模板
3. 提供尽可能多的信息
4. 标注优先级 (P0/P1/P2/P3)

---

## 💡 功能建议

### 功能建议模板

```markdown
**功能描述**
清晰简洁地描述建议的功能。

**使用场景**
什么情况下需要这个功能？

**替代方案**
是否考虑过其他实现方式？

**附加信息**
任何额外的上下文、截图或示例。
```

---

## 🏷️ 分支策略

### 分支命名

```
main                 # 主分支 (受保护)
├── feature/xxx      # 新功能
├── fix/xxx          # Bug 修复
├── docs/xxx         # 文档更新
├── refactor/xxx     # 重构
└── release/v2.5.0   # 发布分支
```

### 提交信息规范

```
<type>(<scope>): <subject>

<body>

<footer>
```

**示例**:
```
feat(api): add SQL injection protection

Implement whitelist-based SQL validation:
- Only allow SELECT/EXPLAIN/WITH prefixes
- Block SQL comments (--, /*, #)
- Block UNION and file operations

Fixes #456

Co-authored-by: Name <email@example.com>
```

---

## 📞 联系方式

- **GitHub Issues**: https://github.com/kkkdddd-start/winalog-go-fix-/issues
- **讨论区**: https://github.com/kkkdddd-start/winalog-go-fix-/discussions

---

## 🎯 贡献者权利与义务

### 权利

- 代码被公平审查
- 不同意见被尊重
- 获得建设性反馈

### 义务

- 遵循代码规范
- 尊重其他贡献者
- 及时响应审查意见
- 保持 PR 更新

---

感谢你的贡献！🎉

**版本**: v2.5.0  
**最后更新**: 2026-05-09
