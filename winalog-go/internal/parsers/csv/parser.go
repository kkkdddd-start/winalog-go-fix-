package csv

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kkkdddd-start/winalog-go/internal/parsers"
	"github.com/kkkdddd-start/winalog-go/internal/types"
)

func init() {
	parsers.GetGlobalRegistry().Register(NewCsvParser())
}

type CsvParser struct {
	Delimiter string
	HasHeader bool
	Columns   []string
}

func NewCsvParser() *CsvParser {
	return &CsvParser{
		Delimiter: ",",
		HasHeader: true,
	}
}

func (p *CsvParser) Priority() int {
	return 50
}

func (p *CsvParser) CanParse(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".csv" {
		return true
	}
	// .log/.txt 需要内容嗅探确认是 CSV 格式
	if ext == ".log" || ext == ".txt" {
		file, err := os.Open(path)
		if err != nil {
			return false
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for i := 0; i < 3 && scanner.Scan(); i++ {
			line := scanner.Text()
			if strings.Count(line, ",") >= 3 || strings.Count(line, "\t") >= 3 {
				return true
			}
		}
		return false
	}
	return false
}

func (p *CsvParser) GetType() string {
	return "csv"
}

func (p *CsvParser) Parse(path string) <-chan *types.Event {
	return p.ParseWithError(path).Events
}

func (p *CsvParser) ParseWithError(path string) parsers.ParseResult {
	events := make(chan *types.Event, 100)
	errChan := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errChan)

		csvEvents, err := p.parseCSV(path)
		if err != nil {
			errChan <- err
			return
		}

		for _, e := range csvEvents {
			events <- e
		}
	}()

	return parsers.ParseResult{Events: events, ErrCh: errChan}
}

func (p *CsvParser) ParseBatch(path string) ([]*types.Event, error) {
	return p.parseCSV(path)
}

func (p *CsvParser) parseCSV(path string) ([]*types.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if p.HasHeader && len(p.Columns) == 0 {
		bom := make([]byte, 3)
		n, _ := file.Read(bom)
		if n < 3 || bom[0] != 0xEF || bom[1] != 0xBB || bom[2] != 0xBF {
			file.Seek(0, 0)
		}
	}

	reader := csv.NewReader(file)
	if p.Delimiter != "," {
		reader.Comma = rune(p.Delimiter[0])
	}

	if p.HasHeader {
		header, err := reader.Read()
		if err != nil {
			return nil, err
		}
		if len(p.Columns) == 0 {
			p.Columns = GuessColumns(header)
		}
	}

	events := make([]*types.Event, 0)
	lineNum := 0

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		lineNum++

		event := p.recordToEvent(record, lineNum)
		if event != nil {
			events = append(events, event)
		}
	}

	return events, nil
}

func (p *CsvParser) recordToEvent(record []string, lineNum int) *types.Event {
	if len(record) < 3 {
		return nil
	}

	event := &types.Event{
		Source:     "CSV",
		LogName:    "Custom",
		Level:      types.EventLevelInfo,
		ImportTime: time.Now(),
	}

	if len(p.Columns) > 0 {
		for i, col := range record {
			if i >= len(p.Columns) {
				break
			}
			switch strings.ToLower(p.Columns[i]) {
			case "timestamp", "time", "date":
				if t, err := time.Parse(time.RFC3339, col); err == nil {
					event.Timestamp = t
				} else if t, err := time.Parse("2006-01-02 15:04:05", col); err == nil {
					event.Timestamp = t
				}
			case "eventid", "event_id", "id":
				if id, err := strconv.ParseInt(col, 10, 32); err == nil {
					event.EventID = int32(id)
				}
			case "level":
				if lvl, err := strconv.Atoi(col); err == nil {
					event.Level = types.EventLevelFromInt(lvl)
				} else if strings.Contains(strings.ToLower(col), "error") {
					event.Level = types.EventLevelError
				} else if strings.Contains(strings.ToLower(col), "warn") {
					event.Level = types.EventLevelWarning
				}
			case "source":
				event.Source = col
			case "logname", "log_name", "log":
				event.LogName = col
			case "computer", "hostname":
				event.Computer = col
			case "user":
				event.User = &col
			case "message", "msg":
				event.Message = col
			}
		}
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	if event.Message == "" && len(record) > 0 {
		event.Message = strings.Join(record, " ")
	}

	return event
}

func (p *CsvParser) SetColumns(columns []string) {
	p.Columns = columns
}

func (p *CsvParser) SetDelimiter(delimiter string) {
	p.Delimiter = delimiter
}

func (p *CsvParser) SetHasHeader(hasHeader bool) {
	p.HasHeader = hasHeader
}

func GuessColumns(firstRecord []string) []string {
	columns := make([]string, len(firstRecord))
	for i, val := range firstRecord {
		lower := strings.ToLower(val)
		switch {
		case strings.Contains(lower, "timestamp") || strings.Contains(lower, "time") || strings.Contains(lower, "date"):
			columns[i] = "timestamp"
		case strings.Contains(lower, "event") && strings.Contains(lower, "id"):
			columns[i] = "eventid"
		case strings.Contains(lower, "level"):
			columns[i] = "level"
		case strings.Contains(lower, "source"):
			columns[i] = "source"
		case strings.Contains(lower, "computer") || strings.Contains(lower, "host"):
			columns[i] = "computer"
		case strings.Contains(lower, "user"):
			columns[i] = "user"
		case strings.Contains(lower, "message") || strings.Contains(lower, "msg"):
			columns[i] = "message"
		default:
			columns[i] = fmt.Sprintf("column%d", i)
		}
	}
	return columns
}
