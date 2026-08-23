package correlation

import (
	"strings"

	"github.com/thiagomontozo/identitymesh/backend/internal/domain"
)

type Result struct {
	Automatic  bool
	Confidence string
	Reasons    []string
}

func Evaluate(person domain.Person, account domain.IdentityAccount, trustedDomains map[string]bool, emailUnique bool) Result {
	if person.EmployeeNumber != "" && account.EmployeeNumber != "" && strings.EqualFold(strings.TrimSpace(person.EmployeeNumber), strings.TrimSpace(account.EmployeeNumber)) {
		return Result{Automatic: true, Confidence: "HIGH", Reasons: []string{"exact immutable employee identifier"}}
	}
	personEmail, accountEmail := normalizeEmail(person.PrimaryEmail), normalizeEmail(account.PrimaryEmail)
	if personEmail != "" && personEmail == accountEmail && emailUnique {
		domainPart := strings.SplitN(personEmail, "@", 2)[1]
		if trustedDomains[domainPart] {
			return Result{Automatic: true, Confidence: "HIGH", Reasons: []string{"exact unique email in trusted domain"}}
		}
		return Result{Automatic: false, Confidence: "MEDIUM", Reasons: []string{"exact email outside trusted domain requires review"}}
	}
	if person.DisplayName != "" && strings.EqualFold(strings.TrimSpace(person.DisplayName), strings.TrimSpace(account.DisplayName)) {
		return Result{Automatic: false, Confidence: "LOW", Reasons: []string{"name-only similarity is never auto-linked"}}
	}
	return Result{Automatic: false, Confidence: "LOW", Reasons: []string{"no deterministic identity signal"}}
}

func normalizeEmail(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if strings.Count(v, "@") != 1 {
		return ""
	}
	parts := strings.SplitN(v, "@", 2)
	if parts[0] == "" || parts[1] == "" {
		return ""
	}
	return v
}
