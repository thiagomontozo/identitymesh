package reports

import (
	"bytes"
	"testing"
	"time"
)

func TestOffboardingPDF(t *testing.T) {
	pdf := OffboardingPDF(OffboardingReport{CaseID: "case-1", PersonName: "Alex Morgan", VerificationStatus: "VERIFIED", GeneratedAt: time.Unix(0, 0), Actions: []string{"SCIM: disabled"}})
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) || !bytes.Contains(pdf, []byte("Alex Morgan")) || !bytes.Contains(pdf, []byte("outside the observed scope")) {
		t.Fatalf("unexpected PDF export: %q", pdf[:min(80, len(pdf))])
	}
}
