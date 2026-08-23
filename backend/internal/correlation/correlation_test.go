package correlation

import (
	"github.com/thiagomontozo/identitymesh/backend/internal/domain"
	"testing"
)

func TestEmployeeIDAutoLinkHigh(t *testing.T) {
	r := Evaluate(domain.Person{EmployeeNumber: "E-101", DisplayName: "Alex Morgan"}, domain.IdentityAccount{EmployeeNumber: "e-101", DisplayName: "Different"}, map[string]bool{}, true)
	if !r.Automatic || r.Confidence != "HIGH" {
		t.Fatalf("unexpected result: %+v", r)
	}
}
func TestUniqueTrustedEmailAutoLink(t *testing.T) {
	r := Evaluate(domain.Person{PrimaryEmail: "Alex@IdentityMesh.Test"}, domain.IdentityAccount{PrimaryEmail: "alex@identitymesh.test"}, map[string]bool{"identitymesh.test": true}, true)
	if !r.Automatic || r.Confidence != "HIGH" {
		t.Fatalf("unexpected result: %+v", r)
	}
}
func TestNameOnlyNeverAutoLinks(t *testing.T) {
	r := Evaluate(domain.Person{DisplayName: "John Smith", PrimaryEmail: "john.one@test"}, domain.IdentityAccount{DisplayName: "John Smith", PrimaryEmail: "john.two@test"}, map[string]bool{}, true)
	if r.Automatic {
		t.Fatal("name-only match must never auto-link")
	}
	if r.Reasons[0] != "name-only similarity is never auto-linked" {
		t.Fatalf("reason must be explicit: %+v", r)
	}
}
