package httpapi

import "testing"

func TestPrivilegedMFARolePolicy(t *testing.T) {
	for _, role := range []string{"OWNER", "IDENTITY_ADMIN", "SECURITY_ADMIN", "OPERATOR"} {
		if !privilegedRoles([]string{role}) {
			t.Fatalf("%s must be covered by privileged MFA policy", role)
		}
	}
	for _, role := range []string{"ACCESS_REVIEWER", "AUDITOR", "VIEWER"} {
		if privilegedRoles([]string{role}) {
			t.Fatalf("%s must not be classified as a mutating privileged role", role)
		}
	}
}
