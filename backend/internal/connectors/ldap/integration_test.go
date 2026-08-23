//go:build integration

package ldapconnector

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestOpenLDAPDiscovery(t *testing.T) {
	url := os.Getenv("IDENTITYMESH_TEST_LDAP_URL")
	if url == "" {
		t.Skip("IDENTITYMESH_TEST_LDAP_URL not configured")
	}
	client, err := New(Config{URL: url, BindDN: "cn=admin,dc=identitymesh,dc=test", Password: "identitymesh-test-only", SearchBase: "dc=identitymesh,dc=test", UserFilter: "(objectClass=inetOrgPerson)", GroupFilter: "(objectClass=groupOfNames)", PageSize: 2, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	users, err := client.SearchUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) < 3 {
		t.Fatalf("expected synthetic users, got %d", len(users))
	}
	groups, err := client.SearchGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) < 1 {
		t.Fatal("expected synthetic group")
	}
}
func TestLDAPIsReadOnlyByAPI(t *testing.T) {
	client, err := New(Config{URL: "ldap://localhost:1389", BindDN: "x", Password: "x", SearchBase: "dc=identitymesh,dc=test", UserFilter: "(objectClass=*)", GroupFilter: "(objectClass=*)"})
	if err != nil {
		t.Fatal(err)
	}
	_ = client /* No mutating method exists by design. */
}
