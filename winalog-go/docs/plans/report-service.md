# R7: 统一报告服务层 - 完整实施计划

## 问题摘要

当前报告生成逻辑分散在 3 个位置，共约 **2299 行代码**，存在约 **400 行重复代码**。

## 代码统计

| 文件 | 行数 | 功能 |
|------|------|------|
| `internal/reports/generator.go` | ~1017 | 报告生成核心逻辑 |
| `internal/reports/html.go` | ~69 | HTML 导出器 |
| `internal/reports/json.go` | ~211 | JSON 导出器 |
| `internal/api/handlers_reports.go` | ~842 | API 报告处理（**大量重复**） |
| `cmd/winalog/commands/report.go` | ~160 | CLI 报告命令 |

## 重复类型对比

| 类型 | reports 包 | api 包 | 处理方式 |
|------|------------|--------|----------|
| `TimeRange` | ✅ | ✅ (完全相同) | 统一使用 reports 包 |
| `ReportRequest` | ✅ | ✅ (字段不同) | API 用适配器转换 |
| `ReportSummary` | ✅ | ✅ (字段交集) | API 用适配器转换 |
| `ReportAlert` | ❌ | ✅ | 保留在 api 包用于 JSON |
| `ReportEvent` | ❌ | ✅ | 保留在 api 包用于 JSON |
| `ReportTimeline` | ❌ | ✅ | 保留在 api 包用于 JSON |

---

# 完整实施计划

## 阶段总览

| 阶段 | 周期 | 交付物 | 风险 |
|------|------|--------|------|
| Phase 1 | Day 1 | `service.go` + PDF 支持 | 中 |
| Phase 2 | Day 2 | 重构 `handlers_reports.go` | 低 |
| Phase 3 | Day 3 | 测试 + CLI 优化（可选） | 低 |

---

## Phase 1: 创建统一服务层

### Day 1 - 实施任务

#### 任务 1.1: 创建 `internal/reports/service.go`

**文件**: `internal/reports/service.go` (新建，约 150 行)

```go
package reports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"text/template"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

type ReportService struct {
	db        *storage.DB
	generator *Generator
}

func NewReportService(db *storage.DB) *ReportService {
	return &ReportService{
		db:        db,
		generator: NewGenerator(db),
	}
}

func (s *ReportService) Generate(req *ReportRequest) (*Report, error) {
	return s.generator.Generate(req)
}

func (s *ReportService) ExportHTML(req *ReportRequest, w io.Writer) error {
	report, err := s.Generate(req)
	if err != nil {
		return err
	}

	htmlReport := NewHTMLReport(report)
	return htmlReport.Write(w)
}

func (s *ReportService) ExportJSON(req *ReportRequest) ([]byte, error) {
	report, err := s.Generate(req)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(report, "", "  ")
}

func (s *ReportService) ExportPDF(req *ReportRequest, w io.Writer) error {
	report, err := s.Generate(req)
	if err != nil {
		return err
	}

	return generatePDF(report, w)
}

func (s *ReportService) GenerateAsync(req *ReportRequest, callback func(*Report, error)) {
	go func() {
		report, err := s.Generate(req)
		callback(report, err)
	}()
}

func generatePDF(report *Report, w io.Writer) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.AddPage()

	pdf.SetFillColor(22, 33, 62)
	pdf.Rect(0, 0, 210, 40, "F")
	pdf.SetTextColor(0, 217, 255)
	pdf.SetFont("Arial", "B", 20)
	pdf.SetXY(15, 12)
	pdf.Cell(180, 10, report.Title)

	pdf.SetTextColor(136, 136, 136)
	pdf.SetFont("Arial", "", 10)
	pdf.SetXY(15, 28)
	pdf.Cell(180, 6, fmt.Sprintf("Generated: %s", report.GeneratedAt.Format("2006-01-02 15:04:05")))

	pdf.SetTextColor(51, 51, 51)
	pdf.SetY(50)

	if report.Summary.TotalEvents > 0 {
		addSummaryToPDF(pdf, report.Summary)
	}

	if len(report.TopAlerts) > 0 {
		addAlertsToPDF(pdf, report.TopAlerts)
	}

	return pdf.Output(w)
}

func addSummaryToPDF(pdf *gofpdf.Fpdf, summary ReportSummary) {
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 217, 255)
	pdf.Cell(0, 10, "Security Summary")
	pdf.Ln(12)

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(51, 51, 51)

	metrics := []struct {
		label string
		value int64
	}{
		{"Total Events", summary.TotalEvents},
		{"Total Alerts", summary.TotalAlerts},
		{"Critical Events", summary.CriticalEvents},
		{"High Alerts", summary.HighAlerts},
	}

	for _, m := range metrics {
		pdf.SetFont("Arial", "B", 10)
		pdf.Cell(60, 7, m.label+":")
		pdf.SetFont("Arial", "", 10)
		pdf.Cell(0, 7, fmt.Sprintf("%d", m.value))
		pdf.Ln(7)
	}
	pdf.Ln(5)
}

func addAlertsToPDF(pdf *gofpdf.Fpdf, alerts []*types.Alert) {
	pdf.SetFont("Arial", "B", 14)
	pdf.SetTextColor(0, 217, 255)
	pdf.Cell(0, 10, "Alert Details")
	pdf.Ln(12)

	tableWidth := []float64{25, 40, 25, 70}
	headers := []string{"Severity", "Rule Name", "Count", "Message"}

	pdf.SetFont("Arial", "B", 9)
	pdf.SetFillColor(0, 217, 255)
	pdf.SetTextColor(255, 255, 255)
	for i, h := range headers {
		pdf.Cell(tableWidth[i], 8, h)
	}
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 8)
	pdf.SetTextColor(51, 51, 51)
	fill := false
	for i, alert := range alerts {
		if i >= 20 {
			pdf.Cell(0, 7, "... and more alerts")
			break
		}
		if fill {
			pdf.SetFillColor(245, 245, 245)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.Cell(tableWidth[0], 6, string(alert.Severity))
		pdf.Cell(tableWidth[1], 6, truncateString(alert.RuleName, 25))
		pdf.Cell(tableWidth[2], 6, fmt.Sprintf("%d", alert.Count))
		pdf.Cell(tableWidth[3], 6, truncateString(alert.Message, 45))
		pdf.Ln(6)
		fill = !fill
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
```

#### 任务 1.2: 创建 `internal/reports/api_adapter.go`

**文件**: `internal/reports/api_adapter.go` (新建，约 80 行)

```go
package reports

import (
	"fmt"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/api"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func AdaptAPIRequest(apiReq *api.ReportRequest) (*ReportRequest, error) {
	req := &ReportRequest{
		Title:      apiReq.Title,
		Format:     ReportFormat(apiReq.Format),
		IncludeRaw: apiReq.IncludeRaw,
	}

	if apiReq.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, apiReq.StartTime); err == nil {
			req.StartTime = t
		}
	}

	if apiReq.EndTime != "" {
		if t, err := time.Parse(time.RFC3339, apiReq.EndTime); err == nil {
			req.EndTime = t
		}
	}

	return req, nil
}

func AdaptReportContent(report *Report) *api.ReportContent {
	content := &api.ReportContent{}

	if report.Summary.TotalEvents > 0 {
		content.Summary = &api.ReportSummary{
			TotalEvents:    report.Summary.TotalEvents,
			TotalAlerts:    report.Summary.TotalAlerts,
			CriticalAlerts: report.Summary.CriticalEvents,
			HighAlerts:     report.Summary.HighAlerts,
		}
	}

	for _, alert := range report.TopAlerts {
		content.Alerts = append(content.Alerts, &api.ReportAlert{
			ID:        alert.ID,
			RuleName:  alert.RuleName,
			Severity:  string(alert.Severity),
			Message:   alert.Message,
			Count:     alert.Count,
			FirstSeen: alert.FirstSeen,
			LastSeen:  alert.LastSeen,
		})
	}

	return content
}
```

#### 任务 1.3: 添加 gofpdf 依赖

```bash
go get github.com/jung-kurt/gofpdf
```

#### 任务 1.4: 编写单元测试

**文件**: `internal/reports/service_test.go` (新建，约 100 行)

```go
package reports

import (
	"testing"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/storage"
)

func TestReportService_Generate(t *testing.T) {
	db, err := storage.NewDB(":memory:")
	if err != nil {
		t.Skip("skipping test: %v", err)
	}
	defer db.Close()

	svc := NewReportService(db)

	req := &ReportRequest{
		Title:     "Test Report",
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
	}

	report, err := svc.Generate(req)
	if err != nil {
		t.Errorf("Generate() error = %v", err)
		return
	}

	if report.Title != req.Title {
		t.Errorf("report.Title = %v, want %v", report.Title, req.Title)
	}
}

func TestReportService_ExportJSON(t *testing.T) {
	db, err := storage.NewDB(":memory:")
	if err != nil {
		t.Skip("skipping test: %v", err)
	}
	defer db.Close()

	svc := NewReportService(db)

	req := &ReportRequest{
		Title:     "Test Report",
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
	}

	data, err := svc.ExportJSON(req)
	if err != nil {
		t.Errorf("ExportJSON() error = %v", err)
		return
	}

	if len(data) == 0 {
		t.Error("ExportJSON() returned empty data")
	}
}
```

### Day 1 验收标准

| 验收项 | 标准 |
|--------|------|
| `service.go` 编译通过 | `go build ./internal/reports/` 无错误 |
| `api_adapter.go` 编译通过 | `go build ./internal/reports/` 无错误 |
| `Generate()` 返回有效报告 | 单元测试通过 |
| `ExportJSON()` 输出有效 JSON | 单元测试验证 JSON 格式 |
| PDF 生成不崩溃 | `ExportPDF()` 能生成文件头 |

---

## Phase 2: 重构 Web API

### Day 2 - 实施任务

#### 任务 2.1: 修改 `internal/api/handlers_reports.go`

**预估修改**: 约 100 行
**预估删除**: 约 400 行

**修改点 1**: 添加 ReportService 到 ReportsHandler

```go
type ReportsHandler struct {
	db     *storage.DB
	svc    *reports.ReportService  // 新增
}
```

**修改点 2**: NewReportsHandler 使用 ReportService

```go
func NewReportsHandler(db *storage.DB) *ReportsHandler {
	return &ReportsHandler{
		db:  db,
		svc: reports.NewReportService(db),  // 新增
	}
}
```

**修改点 3**: GenerateReport 使用 ReportService

```go
func (h *ReportsHandler) GenerateReport(c *gin.Context) {
	var req ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	reportID := fmt.Sprintf("report_%s_%d", req.Type, time.Now().UnixNano())

	generatedAt := time.Now()
	_, err := h.db.Exec(`
		INSERT INTO reports (id, report_type, format, title, description, status, generated_at, query_params)
		VALUES (?, ?, ?, ?, ?, 'generating', ?, ?)`,
		reportID, req.Type, req.Format, req.Title, req.Description, generatedAt, "")

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// 使用 ReportService 异步生成
	apiReq := &reports.ReportRequest{
		Title:      req.Title,
		Format:     reports.ReportFormat(req.Format),
		StartTime:  parseTime(req.StartTime),
		EndTime:    parseTime(req.EndTime),
		IncludeRaw: req.IncludeRaw,
	}

	h.svc.GenerateAsync(apiReq, func(report *reports.Report, err error) {
		if err != nil {
			h.db.Exec(`UPDATE reports SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?`,
				err.Error(), time.Now(), reportID)
			return
		}

		reportDir := filepath.Join(os.TempDir(), "winalog_reports")
		os.MkdirAll(reportDir, 0755)
		fileName := fmt.Sprintf("%s.%s", reportID, req.Format)
		filePath := filepath.Join(reportDir, fileName)

		if req.Format == "pdf" {
			if f, err := os.Create(filePath); err == nil {
				h.svc.ExportPDF(apiReq, f)
				f.Close()
			}
		} else {
			if data, err := h.svc.ExportJSON(apiReq); err == nil {
				os.WriteFile(filePath, data, 0644)
			}
		}

		if fi, _ := os.Stat(filePath); fi != nil {
			h.db.Exec(`UPDATE reports SET status = 'completed', completed_at = ?, file_path = ?, file_size = ? WHERE id = ?`,
				time.Now(), filePath, fi.Size(), reportID)
		}
	})

	c.JSON(http.StatusOK, gin.H{
		"id":           reportID,
		"type":         req.Type,
		"format":       req.Format,
		"status":       "generating",
		"generated_at": generatedAt,
		"message":      "Report generation started",
	})
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
```

**修改点 4**: 删除以下重复方法（约 400 行）

需要删除的方法：
- `buildSecuritySummary()` - 第 476-507 行
- `buildAlertReport()` - 第 509-554 行
- `buildEventReport()` - 第 556-597 行
- `buildTimelineReport()` - 第 599-660 行
- `buildReportContent()` - 第 430-474 行
- `generatePDF()` - 第 238-279 行
- `addSummaryToPDF()` - 第 281-311 行
- `addAlertsToPDF()` - 第 313-352 行
- `addEventsToPDF()` - 第 354-393 行
- `addTimelineToPDF()` - 第 395-421 行
- `truncateString()` - 第 423-428 行

#### 任务 2.2: 更新 `internal/api/handlers_reports.go` 导入

```go
import (
	// ... existing imports ...
	"github.com/kkkdddd-start/winalog-go/internal/reports"  // 新增
)
```

### Day 2 验收标准

| 验收项 | 标准 |
|--------|------|
| API 编译通过 | `go build ./internal/api/` 无错误 |
| `GET /api/reports` 正常 | 返回报告列表 |
| `POST /api/reports/generate` 正常 | 触发报告生成 |
| PDF 生成正常 | 生成有效 PDF 文件 |
| JSON 格式与之前一致 | API 响应字段不变 |
| 异步生成正常 | 报告状态更新正确 |

---

## Phase 3: 测试与优化

### Day 3 - 实施任务

#### 任务 3.1: 集成测试

**文件**: `internal/api/reports_integration_test.go` (新建)

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReportsHandler_GenerateReport(t *testing.T) {
	setupTestDB(t)
	defer closeTestDB()

	body := map[string]interface{}{
		"type":        "security_summary",
		"format":      "json",
		"start_time":  "",
		"end_time":    "",
		"include_raw": false,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/reports/generate", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler := NewReportsHandler(testDB)
	handler.GenerateReport(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["status"] != "generating" {
		t.Errorf("expected status 'generating', got %v", resp["status"])
	}
}

func TestReportsHandler_ListReports(t *testing.T) {
	setupTestDB(t)
	defer closeTestDB()

	req := httptest.NewRequest("GET", "/api/reports", nil)
	w := httptest.NewRecorder()

	handler := NewReportsHandler(testDB)
	handler.ListReports(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}
```

#### 任务 3.2: 手动测试清单

- [ ] CLI `report generate security_summary --format html` 正常工作
- [ ] CLI `report generate security_summary --format json` 正常工作
- [ ] Web API `POST /api/reports/generate` 生成 JSON 报告
- [ ] Web API `POST /api/reports/generate` 生成 PDF 报告
- [ ] Web API `GET /api/reports` 列出报告
- [ ] 报告统计数据一致（CLI 和 API 生成的结果相同）

#### 任务 3.3: 性能验证

- [ ] 生成 1000 条事件的报告 < 5 秒
- [ ] 生成 10000 条事件的报告 < 15 秒

---

## 详细时间估算

| 任务 | 预估时间 | 实际时间 | 备注 |
|------|----------|----------|------|
| **Phase 1: 服务层** | | | |
| 任务 1.1: service.go | 2 小时 | | |
| 任务 1.2: api_adapter.go | 1 小时 | | |
| 任务 1.3: 添加依赖 | 15 分钟 | | |
| 任务 1.4: 单元测试 | 1.5 小时 | | |
| **Phase 1 小计** | **5 小时** | | |
| **Phase 2: Web API** | | | |
| 任务 2.1: 修改 handlers | 4 小时 | | |
| 任务 2.2: 编译调试 | 1 小时 | | |
| **Phase 2 小计** | **5 小时** | | |
| **Phase 3: 测试** | | | |
| 任务 3.1: 集成测试 | 2 小时 | | |
| 任务 3.2: 手动测试 | 1 小时 | | |
| 任务 3.3: 性能验证 | 1 小时 | | |
| **Phase 3 小计** | **4 小时** | | |
| **总计** | **14 小时** | | 约 2 个工作日 |

---

## 文件修改清单

### 新增文件

| 文件路径 | 行数 | 说明 |
|----------|------|------|
| `internal/reports/service.go` | ~150 | ReportService 核心实现 |
| `internal/reports/api_adapter.go` | ~80 | API 请求/响应适配器 |
| `internal/reports/service_test.go` | ~100 | 单元测试 |
| `internal/api/reports_integration_test.go` | ~80 | 集成测试 |

### 修改文件

| 文件路径 | 修改类型 | 删除行 | 新增行 | 说明 |
|----------|----------|--------|--------|------|
| `internal/api/handlers_reports.go` | 重构 | ~400 | ~100 | 使用 ReportService |
| `go.mod` | 修改 | 0 | 1 | 添加 gofpdf 依赖 |

### 不需要修改的文件

| 文件路径 | 说明 |
|----------|------|
| `cmd/winalog/commands/report.go` | CLI 已正确使用 reports 包 |
| `internal/reports/generator.go` | 核心逻辑保持不变 |
| `internal/reports/html.go` | 保持不变 |
| `internal/reports/json.go` | 保持不变 |

---

## 验收标准汇总

### 功能验收

| 功能 | 验收方法 |
|------|----------|
| JSON 报告生成 | CLI 和 API 生成相同结构 |
| HTML 报告生成 | CLI 和 API 生成相同 HTML |
| PDF 报告生成 | API 生成有效 PDF 文件 |
| 报告统计数据 | 两处计算结果一致 |
| 异步生成 | API 报告状态正确更新 |

### 代码质量验收

| 标准 | 验收方法 |
|------|----------|
| 无编译错误 | `go build ./...` |
| 无 vet 警告 | `go vet ./...` |
| 单元测试通过 | `go test ./internal/reports/...` |
| 集成测试通过 | `go test ./internal/api/...` |

### 性能验收

| 场景 | 目标 |
|------|------|
| 1000 事件报告 | < 5 秒 |
| 10000 事件报告 | < 15 秒 |

---

## 向后兼容策略

### API 响应字段保持不变

当前 API 返回:
```json
{
  "id": "report_xxx",
  "type": "security_summary",
  "format": "json",
  "status": "generating"
}
```

重构后保持完全一致。

### 新增字段可选

ReportService 可以提供额外字段（如 `reports.Report.ComplianceStatus`），但 API 可以选择不返回。

---

## 风险缓解措施

| 风险 | 缓解措施 | 验证方法 |
|------|----------|----------|
| PDF 格式变化 | Phase 1 单独测试 PDF | 对比新旧 PDF 文件结构 |
| 统计数据不一致 | 使用同一个 ReportService | 编写对比测试 |
| API 响应格式变化 | 保留 api.ReportContent | 适配器转换 |
| 性能下降 | 性能基准测试 | 对比重构前后时间 |

---

## 实施检查清单

### Day 1 结束检查

- [ ] `service.go` 存在且可编译
- [ ] `api_adapter.go` 存在且可编译
- [ ] 单元测试存在且可通过
- [ ] gofpdf 依赖已添加

### Day 2 结束检查

- [ ] `handlers_reports.go` 已重构
- [ ] 约 400 行重复代码已删除
- [ ] API 编译无错误
- [ ] `go vet` 无警告

### Day 3 结束检查

- [ ] 集成测试存在且通过
- [ ] CLI 报告命令正常
- [ ] API 报告端点正常
- [ ] PDF 生成正常
- [ ] 统计数据一致

---

## 状态

**待实施** - 需要技术评审后执行

## 优先级

**P1** - 重要且紧急，建议本季度完成

## 历史版本

| 版本 | 日期 | 作者 | 变更 |
|------|------|------|------|
| v1.0 | 2026-04-17 | MonkeyCode AI | 初始版本（问题分析） |
| v2.0 | 2026-04-17 | MonkeyCode AI | 补充完整实施计划 |