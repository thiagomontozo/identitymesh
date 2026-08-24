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
func TestLDAPWriteRequiresExplicitStrategy(t *testing.T) {
	client, err := New(Config{URL: "ldap://localhost:1389", BindDN: "x", Password: "x", SearchBase: "dc=identitymesh,dc=test", UserFilter: "(objectClass=*)", GroupFilter: "(objectClass=*)"})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.DisableUser(context.Background(), "uid=alex,dc=identitymesh,dc=test"); err == nil {
		t.Fatal("LDAP write without an explicit strategy must fail")
	}
}

func TestOpenLDAPControlledMembershipRemoval(t *testing.T) {
	endpoint := os.Getenv("IDENTITYMESH_TEST_LDAP_URL")
	if endpoint == "" {
		t.Skip("IDENTITYMESH_TEST_LDAP_URL not configured")
	}
	client, err := New(Config{URL: endpoint, BindDN: "cn=admin,dc=identitymesh,dc=test", Password: "identitymesh-test-only", SearchBase: "dc=identitymesh,dc=test", UserFilter: "(objectClass=inetOrgPerson)", GroupFilter: "(objectClass=groupOfNames)", MembershipAttribute: "member", Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.RemoveMembership(context.Background(), "cn=directory-users,ou=groups,dc=identitymesh,dc=test", "uid=jordan.lee,ou=people,dc=identitymesh,dc=test"); err != nil {
		t.Fatal(err)
	}
	groups, err := client.SearchGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range groups[0].Attributes["member"] {
		if member == "uid=jordan.lee,ou=people,dc=identitymesh,dc=test" {
			t.Fatal("LDAP membership remained after controlled removal")
		}
	}
}
