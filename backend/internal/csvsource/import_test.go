package csvsource

import (
	"strings"
	"testing"
)

func TestPreviewValidationAndLimit(t *testing.T) {
	csv := "employee_id,display_name,email,status\nE1,Alex Morgan,alex@identitymesh.test,TERMINATED\nE2,Jordan Lee,jordan@identitymesh.test,ACTIVE\n"
	p, err := ParsePreview(strings.NewReader(csv), Mapping{EmployeeID: "employee_id", DisplayName: "display_name", Email: "email", Status: "status"}, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rows) != 1 || !p.Truncated {
		t.Fatalf("unexpected preview: %+v", p)
	}
}
func TestExportFormulaInjection(t *testing.T) {
	if got := EscapeSpreadsheetCell("=cmd|' /C calc'!A0"); got[0] != '\'' {
		t.Fatalf("formula was not escaped: %q", got)
	}
}
