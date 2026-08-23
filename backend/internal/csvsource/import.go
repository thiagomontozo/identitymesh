package csvsource

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
)

type Mapping struct{ EmployeeID, DisplayName, Email, Department, ManagerID, Status string }
type Row struct {
	Number                                                        int
	EmployeeID, DisplayName, Email, Department, ManagerID, Status string
}
type Preview struct {
	Rows      []Row
	Errors    []string
	Truncated bool
}

func ParsePreview(input io.Reader, mapping Mapping, maxBytes int64, maxRows int) (Preview, error) {
	if maxBytes <= 0 || maxRows <= 0 {
		return Preview{}, errors.New("positive limits are required")
	}
	reader := csv.NewReader(bufio.NewReader(io.LimitReader(input, maxBytes+1)))
	reader.ReuseRecord = true
	reader.FieldsPerRecord = -1
	head, err := reader.Read()
	if err != nil {
		return Preview{}, fmt.Errorf("read UTF-8 CSV header: %w", err)
	}
	index := map[string]int{}
	for i, h := range head {
		index[strings.TrimSpace(h)] = i
	}
	for _, required := range []string{mapping.EmployeeID, mapping.DisplayName, mapping.Status} {
		if _, ok := index[required]; !ok {
			return Preview{}, fmt.Errorf("required mapped column %q is missing", required)
		}
	}
	preview := Preview{Rows: make([]Row, 0, min(maxRows, 100))}
	for n := 2; ; n++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			preview.Errors = append(preview.Errors, fmt.Sprintf("row %d: %v", n, err))
			continue
		}
		if len(preview.Rows) >= maxRows {
			preview.Truncated = true
			break
		}
		get := func(name string) string {
			if i, ok := index[name]; ok && i < len(record) {
				return strings.TrimSpace(record[i])
			}
			return ""
		}
		row := Row{Number: n, EmployeeID: get(mapping.EmployeeID), DisplayName: get(mapping.DisplayName), Email: get(mapping.Email), Department: get(mapping.Department), ManagerID: get(mapping.ManagerID), Status: strings.ToUpper(get(mapping.Status))}
		if row.EmployeeID == "" || row.DisplayName == "" {
			preview.Errors = append(preview.Errors, fmt.Sprintf("row %d: employee_id and display_name are required", n))
			continue
		}
		if !validStatus(row.Status) {
			preview.Errors = append(preview.Errors, fmt.Sprintf("row %d: invalid lifecycle status", n))
			continue
		}
		preview.Rows = append(preview.Rows, row)
	}
	return preview, nil
}
func validStatus(v string) bool {
	switch v {
	case "PRE_HIRE", "ACTIVE", "LEAVE", "SUSPENDED", "TERMINATED", "UNKNOWN":
		return true
	}
	return false
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// EscapeSpreadsheetCell prevents exported values from becoming formulas.
func EscapeSpreadsheetCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@", rune(v[0])) {
		return "'" + v
	}
	return v
}
