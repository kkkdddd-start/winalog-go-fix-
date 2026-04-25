# Exporters 模块

**路径**: `internal/exporters/`

数据导出器，支持多种格式。

## Exporter 接口

```go
type Exporter interface {
    Export(events []*types.Event, writer io.Writer) error
    ContentType() string
    FileExtension() string
}
```

## ExporterFactory

```go
type ExporterFactory struct{}

func (f *ExporterFactory) Create(format string) Exporter
```

**支持的格式**:

| 格式 | 返回类型 | Content-Type | 文件扩展名 |
|------|----------|--------------|-----------|
| `csv` | `*CsvExporter` | text/csv | .csv |
| `excel`, `xlsx` | `*ExcelExporter` | application/vnd.openxmlformats | .xlsx |
| `json` | `*JsonExporter` | application/json | .json |
| `timeline-csv` | `*TimelineExporter` | text/csv | .csv |
| `timeline-json` | `*TimelineJSONExporter` | application/json | .json |
| `timeline-html` | `*TimelineHTMLExporter` | text/html | .html |

## JsonExporter

JSON 格式导出。

```go
type JsonExporter struct {
    prettyPrint bool
}

func NewJsonExporter(prettyPrint bool) *JsonExporter

func (e *JsonExporter) Export(events []*types.Event, writer io.Writer) error
func (e *JsonExporter) ContentType() string  // "application/json"
func (e *JsonExporter) FileExtension() string // ".json"
```

**示例**:

```go
exporter := exporters.NewJsonExporter(true)
err := exporter.Export(events, os.Stdout)
// Pretty print 输出，带缩进
```

## CsvExporter

CSV 格式导出。

```go
type CsvExporter struct {
    delimiter rune
    headers   []string
}

func NewCsvExporter() *CsvExporter

func (e *CsvExporter) SetDelimiter(delimiter rune)
func (e *CsvExporter) SetHeaders(headers []string)
func (e *CsvExporter) Export(events []*types.Event, writer io.Writer) error
func (e *CsvExporter) ContentType() string  // "text/csv"
func (e *CsvExporter) FileExtension() string // ".csv"
```

**示例**:

```go
exporter := exporters.NewCsvExporter()
exporter.SetDelimiter(',')
err := exporter.Export(events, file)
```

## ExcelExporter

Excel 2007+ 格式导出。

```go
type ExcelExporter struct{}

func NewExcelExporter() *ExcelExporter

func (e *ExcelExporter) Export(events []*types.Event, writer io.Writer) error
func (e *ExcelExporter) ContentType() string  // "application/vnd.openxmlformats"
func (e *ExcelExporter) FileExtension() string // ".xlsx"
```

**注意**: 需要 `github.com/xuri/excelize/v2` 库。

## TimelineExporter

时间线专用 CSV 导出。

```go
type TimelineExporter struct{}

func NewTimelineExporter() *TimelineExporter

func (e *TimelineExporter) Export(events []*types.Event, writer io.Writer) error
func (e *TimelineExporter) ContentType() string  // "text/csv"
func (e *TimelineExporter) FileExtension() string // ".csv"
```

**导出字段**:
- Timestamp
- EventID
- Level
- Category
- Source
- Computer
- User
- Message
- MITREAttack

## TimelineJSONExporter

时间线专用 JSON 导出。

```go
type TimelineJSONExporter struct {
    prettyPrint bool
}

func NewTimelineJSONExporter() *TimelineJSONExporter

func (e *TimelineJSONExporter) Export(events []*types.Event, writer io.Writer) error
func (e *TimelineJSONExporter) ContentType() string  // "application/json"
func (e *TimelineJSONExporter) FileExtension() string // ".json"
```

## TimelineHTMLExporter

时间线专用 HTML 导出，带可视化。

```go
type TimelineHTMLExporter struct{}

func NewTimelineHTMLExporter() *TimelineHTMLExporter

func (e *TimelineHTMLExporter) Export(events []*types.Event, writer io.Writer) error
func (e *TimelineHTMLExporter) ContentType() string  // "text/html"
func (e *TimelineHTMLExporter) FileExtension() string // ".html"
```

## 使用示例

```go
// 创建导出器工厂
factory := &exporters.ExporterFactory{}

// 导出为 JSON
jsonExporter := factory.Create("json")
jsonExporter.Export(events, os.Stdout)

// 导出为 CSV
csvExporter := factory.Create("csv")
file, _ := os.Create("events.csv")
defer file.Close()
csvExporter.Export(events, file)

// 导出为 Excel
excelExporter := factory.Create("xlsx")
excelExporter.Export(events, file)

// 导出为时间线 HTML
timelineExporter := factory.Create("timeline-html")
timelineExporter.Export(events, os.Stdout)
```

## 自定义导出

如果需要自定义导出格式，实现 Exporter 接口:

```go
type CustomExporter struct{}

func (e *CustomExporter) Export(events []*types.Event, writer io.Writer) error {
    for _, event := range events {
        _, err := fmt.Fprintf(writer, "%s|%d|%s\n",
            event.Timestamp, event.EventID, event.Message)
        if err != nil {
            return err
        }
    }
    return nil
}

func (e *CustomExporter) ContentType() string {
    return "text/custom"
}

func (e *CustomExporter) FileExtension() string {
    return ".custom"
}
```
