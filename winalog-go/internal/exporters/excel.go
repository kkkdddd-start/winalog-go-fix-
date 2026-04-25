package exporters

import (
	"fmt"
	"io"

	"github.com/kkkdddd-start/winalog-go/internal/types"
	"github.com/xuri/excelize/v2"
)

type ExcelExporter struct{}

func NewExcelExporter() *ExcelExporter {
	return &ExcelExporter{}
}

func (e *ExcelExporter) Export(events []*types.Event, writer io.Writer) error {
	f := excelize.NewFile()
	defer f.Close()

	sheet := "Events"
	index, err := f.NewSheet(sheet)
	if err != nil {
		return err
	}
	f.SetActiveSheet(index)

	headers := []string{
		"ID",
		"Timestamp",
		"EventID",
		"Level",
		"Source",
		"LogName",
		"Computer",
		"User",
		"Message",
	}

	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheet, cell, h)
	}

	for rowIdx, event := range events {
		rowNum := rowIdx + 2
		f.SetCellValue(sheet, fmt.Sprintf("A%d", rowNum), event.ID)
		f.SetCellValue(sheet, fmt.Sprintf("B%d", rowNum), event.Timestamp.Format("2006-01-02 15:04:05"))
		f.SetCellValue(sheet, fmt.Sprintf("C%d", rowNum), event.EventID)
		f.SetCellValue(sheet, fmt.Sprintf("D%d", rowNum), event.Level.String())
		f.SetCellValue(sheet, fmt.Sprintf("E%d", rowNum), event.Source)
		f.SetCellValue(sheet, fmt.Sprintf("F%d", rowNum), event.LogName)
		f.SetCellValue(sheet, fmt.Sprintf("G%d", rowNum), event.Computer)
		f.SetCellValue(sheet, fmt.Sprintf("H%d", rowNum), nilToString(event.User))
		f.SetCellValue(sheet, fmt.Sprintf("I%d", rowNum), event.Message)
	}

	return f.Write(writer)
}

func (e *ExcelExporter) ContentType() string {
	return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
}

func (e *ExcelExporter) FileExtension() string {
	return "xlsx"
}
