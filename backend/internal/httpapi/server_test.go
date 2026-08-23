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

func TestValidateLDAPConfiguration(t *testing.T) {
	valid := map[string]any{"bindDN": "cn=reader,dc=example,dc=test", "searchBase": "dc=example,dc=test", "userFilter": "(objectClass=person)", "groupFilter": "(objectClass=groupOfNames)", "pageSize": float64(200)}
	if err := validateLDAPConfiguration(valid); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	for name, values := range map[string]map[string]any{
		"missing base":   {"bindDN": "x", "userFilter": "(x=y)", "groupFilter": "(x=y)"},
		"newline filter": {"bindDN": "x", "searchBase": "dc=x", "userFilter": "(x=y)\n(|(x=*))", "groupFilter": "(x=y)"},
		"excessive page": {"bindDN": "x", "searchBase": "dc=x", "userFilter": "(x=y)", "groupFilter": "(x=y)", "pageSize": float64(9000)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateLDAPConfiguration(values); err == nil {
				t.Fatal("unsafe LDAP configuration accepted")
			}
		})
	}
}
