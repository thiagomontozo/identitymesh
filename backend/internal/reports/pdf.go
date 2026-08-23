// Package reports renders deliberately small, dependency-free assurance reports.
// The generated PDF is an export artifact, not a forensic or legal certificate.
package reports

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

const Disclaimer = "This report reflects the systems connected to IdentityMesh and successfully reconciled at the time of verification. It does not prove the absence of identities or access in systems outside the observed scope."

type OffboardingReport struct {
	CaseID, PersonName, LifecycleStatus, VerificationStatus string
	GeneratedAt                                             time.Time
	ConnectedSystems, ManagedIdentities                     int
	DisabledIdentities, ActiveIdentities                    int
	UnresolvedIdentities, UnavailableConnectors             int
	Actions, Evidence                                       []string
}

func OffboardingPDF(report OffboardingReport) []byte {
	lines := []string{
		"IdentityMesh - Offboarding Verification Report",
		"Generated: " + report.GeneratedAt.UTC().Format(time.RFC3339),
		"Case: " + report.CaseID,
		"Person: " + report.PersonName,
		"Lifecycle status: " + report.LifecycleStatus,
		"Verification status: " + report.VerificationStatus,
		fmt.Sprintf("Connected systems checked: %d", report.ConnectedSystems),
		fmt.Sprintf("Known managed identities: %d", report.ManagedIdentities),
		fmt.Sprintf("Disabled identities: %d", report.DisabledIdentities),
		fmt.Sprintf("Active remaining identities: %d", report.ActiveIdentities),
		fmt.Sprintf("Unresolved identities: %d", report.UnresolvedIdentities),
		fmt.Sprintf("Unavailable connectors: %d", report.UnavailableConnectors),
		"Actions and observed states:",
	}
	lines = append(lines, report.Actions...)
	lines = append(lines, "Evidence:")
	lines = append(lines, report.Evidence...)
	lines = append(lines, "Limitations:")
	lines = append(lines, wrap(Disclaimer, 92)...)
	lines = append(lines, "Integrity metadata can help detect unintended evidence changes; it is not a forensic certification.")
	return render(lines)
}

func wrap(value string, width int) []string {
	words := strings.Fields(value)
	var out []string
	line := ""
	for _, word := range words {
		if len(line)+len(word)+1 > width && line != "" {
			out = append(out, line)
			line = word
			continue
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

func pdfString(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '-'
		}
		return r
	}, value)
	return strings.NewReplacer("\\", "\\\\", "(", "\\(", ")", "\\)").Replace(value)
}

func render(lines []string) []byte {
	var content strings.Builder
	content.WriteString("BT /F1 16 Tf 54 756 Td 0 -22 Td\n")
	for i, line := range lines {
		if i == 1 {
			content.WriteString("/F1 9 Tf\n")
		}
		content.WriteString("(")
		content.WriteString(pdfString(line))
		content.WriteString(") Tj 0 -14 Td\n")
	}
	content.WriteString("ET")
	stream := content.String()
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for i := 1; i <= len(objects); i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&out, "trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}
