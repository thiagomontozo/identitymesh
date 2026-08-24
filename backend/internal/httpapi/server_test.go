package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type allowLimiter struct{}

func (allowLimiter) Allow(context.Context, string, int, time.Duration) (bool, time.Duration, error) {
	return true, 0, nil
}

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

func TestRateLimitPublicEndpointDoesNotRequireSession(t *testing.T) {
	server := &Server{RateLimiter: allowLimiter{}}
	handler := server.rate(1, time.Minute, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	response := httptest.NewRecorder()
	handler(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestClientIPWalksTrustedProxyChainFromRight(t *testing.T) {
	server := New(nil, nil, nil, nil, "", false, false, 0, nil, nil, nil, "", nil, []string{"10.0.0.0/8"})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.20:1234"
	request.Header.Set("X-Forwarded-For", "192.0.2.99, 203.0.113.7, 10.0.0.10")
	if got := server.clientIP(request); got != "203.0.113.7" {
		t.Fatalf("clientIP=%q", got)
	}
	request.RemoteAddr = "198.51.100.4:1234"
	if got := server.clientIP(request); got != "198.51.100.4" {
		t.Fatalf("untrusted peer accepted forwarded chain: %q", got)
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

func TestLDAPWritesRequireExplicitSafeStrategies(t *testing.T) {
	if err := validateLDAPWriteConfiguration(map[string]any{}, []string{"DISABLE_ACCOUNT"}); err == nil {
		t.Fatal("disable capability accepted without a strategy")
	}
	if err := validateLDAPWriteConfiguration(map[string]any{"disableStrategy": "PPOLICY_LOCK"}, []string{"DISABLE_ACCOUNT"}); err != nil {
		t.Fatalf("safe disable strategy rejected: %v", err)
	}
	if err := validateLDAPWriteConfiguration(map[string]any{}, []string{"REMOVE_MEMBERSHIP"}); err == nil {
		t.Fatal("membership write accepted without an attribute")
	}
	if err := validateLDAPWriteConfiguration(map[string]any{"membershipAttribute": "member"}, []string{"REMOVE_MEMBERSHIP"}); err != nil {
		t.Fatalf("safe membership strategy rejected: %v", err)
	}
}

func TestConnectorCapabilityMatrixPreventsUnsafeWrites(t *testing.T) {
	for connectorType, capability := range map[string]string{
		"ENTRA_ID": "DISABLE_ACCOUNT", "OKTA": "DISABLE_ACCOUNT", "GOOGLE_WORKSPACE": "DISABLE_ACCOUNT",
		"GITHUB": "REMOVE_MEMBERSHIP", "LDAP_DIRECTORY": "DISABLE_ACCOUNT", "SCIM_2_0": "DISABLE_ACCOUNT",
	} {
		if !connectorCapabilityAllowed(connectorType, capability) {
			t.Fatalf("%s should support %s", connectorType, capability)
		}
	}
	for connectorType, capability := range map[string]string{
		"GITHUB": "DISABLE_ACCOUNT", "CSV_AUTHORITATIVE_SOURCE": "DISABLE_ACCOUNT", "ENTRA_ID": "ADD_MEMBERSHIP",
	} {
		if connectorCapabilityAllowed(connectorType, capability) {
			t.Fatalf("%s must not accept %s", connectorType, capability)
		}
	}
}
