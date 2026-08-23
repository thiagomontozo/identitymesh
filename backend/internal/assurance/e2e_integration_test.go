//go:build integration

package assurance

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	ldapconnector "github.com/thiagomontozo/identitymesh/backend/internal/connectors/ldap"
	"github.com/thiagomontozo/identitymesh/backend/internal/csvsource"
	"github.com/thiagomontozo/identitymesh/backend/internal/database"
	"github.com/thiagomontozo/identitymesh/backend/internal/domain"
)

func TestSyntheticDiscoveryCorrelationOffboardingAndEvidence(t *testing.T) {
	dbURL, scimA, scimB, ldapURL := integrationEnvironment(t)
	ctx := context.Background()
	db, err := database.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	resetProvider(t, scimA)
	resetProvider(t, scimB)
	svc := &Service{DB: db, Clock: RealClock{}, AllowHTTP: true, Timeout: 2 * time.Second}
	org, user, source, a, b, ldapID := seedTenant(t, db, scimA, scimB, ldapURL)
	if count, err := svc.ImportPeople(ctx, org, source, peopleFixture(t)); err != nil || count != 5 {
		t.Fatalf("CSV import count=%d err=%v", count, err)
	}
	if result, err := svc.SyncSCIM(ctx, org, a, uuid.NewString()); err != nil || result.AccountsDiscovered < 4 {
		t.Fatalf("SCIM A: %+v %v", result, err)
	}
	if result, err := svc.SyncSCIM(ctx, org, b, uuid.NewString()); err != nil || result.AccountsDiscovered < 4 {
		t.Fatalf("SCIM B: %+v %v", result, err)
	}
	ldapCfg := ldapconnector.Config{URL: ldapURL, BindDN: "cn=admin,dc=identitymesh,dc=test", Password: "identitymesh-test-only", SearchBase: "dc=identitymesh,dc=test", UserFilter: "(objectClass=inetOrgPerson)", GroupFilter: "(objectClass=groupOfNames)", PageSize: 2, Timeout: 5 * time.Second}
	if result, err := svc.SyncLDAP(ctx, org, ldapID, uuid.NewString(), ldapCfg); err != nil || result.AccountsDiscovered < 3 {
		t.Fatalf("LDAP: %+v %v", result, err)
	}
	var alex string
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM people WHERE organization_id=$1 AND external_person_id='E1001'`, org).Scan(&alex); err != nil {
		t.Fatal(err)
	}
	var linked, orphan, candidates int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM identity_links WHERE organization_id=$1 AND person_id=$2`, org, alex).Scan(&linked)
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM identity_findings WHERE organization_id=$1 AND type='ORPHAN_ACCOUNT'`, org).Scan(&orphan)
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM correlation_candidates WHERE organization_id=$1 AND status='PENDING'`, org).Scan(&candidates)
	if linked != 3 || orphan < 1 || candidates < 1 {
		t.Fatalf("linked=%d orphan=%d candidates=%d", linked, orphan, candidates)
	}
	caseID, err := svc.CreateCase(ctx, org, alex, user)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := svc.PlanCase(ctx, org, caseID, user)
	if err != nil || len(preview) != 3 {
		t.Fatalf("plan=%+v err=%v", preview, err)
	}
	if _, err = svc.ExecuteAndVerify(ctx, org, caseID, user); err == nil || !strings.Contains(err.Error(), "FORBIDDEN_STATE") {
		t.Fatalf("approval not enforced: %v", err)
	}
	if err = svc.ApproveCase(ctx, org, caseID, user); err != nil {
		t.Fatal(err)
	}
	status, err := svc.ExecuteAndVerify(ctx, org, caseID, user)
	if err != nil {
		t.Fatal(err)
	}
	if status != domain.Verified {
		t.Fatalf("expected VERIFIED, got %s", status)
	}
	var snapshots, evidence int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM verification_snapshots WHERE organization_id=$1 AND case_id=$2`, org, caseID).Scan(&snapshots)
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM identity_evidence WHERE organization_id=$1 AND lifecycle_case_id=$2`, org, caseID).Scan(&evidence)
	if snapshots != 1 || evidence != 3 {
		t.Fatalf("snapshots=%d evidence=%d", snapshots, evidence)
	}
}

func TestUnavailableProviderNeverReturnsVerified(t *testing.T) {
	dbURL, aURL, bURL, _ := integrationEnvironment(t)
	ctx := context.Background()
	db, err := database.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	resetProvider(t, aURL)
	resetProvider(t, bURL)
	svc := &Service{DB: db, Clock: RealClock{}, AllowHTTP: true, Timeout: 1200 * time.Millisecond}
	org, user, source, a, b, _ := seedTenant(t, db, aURL, bURL, "")
	_, _ = svc.ImportPeople(ctx, org, source, peopleFixture(t))
	if _, err = svc.SyncSCIM(ctx, org, a, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.SyncSCIM(ctx, org, b, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	var jordan string
	_ = db.Pool.QueryRow(ctx, `SELECT id FROM people WHERE organization_id=$1 AND external_person_id='E1002'`, org).Scan(&jordan)
	caseID, err := svc.CreateCase(ctx, org, jordan, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.PlanCase(ctx, org, caseID, user); err != nil {
		t.Fatal(err)
	}
	if err = svc.ApproveCase(ctx, org, caseID, user); err != nil {
		t.Fatal(err)
	}
	setMode(t, bURL, "500")
	status, err := svc.ExecuteAndVerify(ctx, org, caseID, user)
	if err != nil {
		t.Fatal(err)
	}
	if status != domain.Inconclusive {
		t.Fatalf("unavailable provider must be INCONCLUSIVE, got %s", status)
	}
}

func TestPatchSuccessButObservedActiveFailsVerification(t *testing.T) {
	dbURL, aURL, _, _ := integrationEnvironment(t)
	ctx := context.Background()
	db, err := database.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	resetProvider(t, aURL)
	svc := &Service{DB: db, Clock: RealClock{}, AllowHTTP: true, Timeout: 2 * time.Second}
	org, user, source, a, _, _ := seedTenant(t, db, aURL, "", "")
	_, _ = svc.ImportPeople(ctx, org, source, peopleFixture(t))
	if _, err = svc.SyncSCIM(ctx, org, a, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	var alex string
	_ = db.Pool.QueryRow(ctx, `SELECT id FROM people WHERE organization_id=$1 AND external_person_id='E1001'`, org).Scan(&alex)
	caseID, err := svc.CreateCase(ctx, org, alex, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.PlanCase(ctx, org, caseID, user); err != nil {
		t.Fatal(err)
	}
	if err = svc.ApproveCase(ctx, org, caseID, user); err != nil {
		t.Fatal(err)
	}
	setMode(t, aURL, "patch-success-no-change")
	status, err := svc.ExecuteAndVerify(ctx, org, caseID, user)
	if err != nil {
		t.Fatal(err)
	}
	if status != domain.Failed {
		t.Fatalf("provider mismatch must fail, got %s", status)
	}
	if _, err = svc.ExecuteAndVerify(ctx, org, caseID, user); err == nil {
		t.Fatal("terminal case executed twice")
	}
}

func TestAccessReviewKeepAndRevokeOnlyProposesApprovedWork(t *testing.T) {
	dbURL, _, _, _ := integrationEnvironment(t)
	ctx := context.Background()
	db, err := database.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db, Clock: RealClock{}}
	org, user, source, _, _, _ := seedTenant(t, db, "", "", "")
	if _, err = svc.ImportPeople(ctx, org, source, peopleFixture(t)); err != nil {
		t.Fatal(err)
	}
	var alex, jordan string
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM people WHERE organization_id=$1 AND external_person_id='E1001'`, org).Scan(&alex); err != nil {
		t.Fatal(err)
	}
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM people WHERE organization_id=$1 AND external_person_id='E1002'`, org).Scan(&jordan); err != nil {
		t.Fatal(err)
	}
	campaign, keepItem, revokeItem := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO access_review_campaigns(id,organization_id,name,scope_type,reviewer_user_id,status,created_by) VALUES($1,$2,'Synthetic quarterly review','ORGANIZATION',$3,'ACTIVE',$3)`, campaign, org, user); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `INSERT INTO access_review_items(id,organization_id,campaign_id,person_id) VALUES($1,$2,$3,$4),($5,$2,$3,$6)`, keepItem, org, campaign, alex, revokeItem, jordan); err != nil {
		t.Fatal(err)
	}
	if err = svc.DecideReview(ctx, org, keepItem, user, "KEEP", "Access remains appropriate"); err != nil {
		t.Fatal(err)
	}
	if err = svc.DecideReview(ctx, org, revokeItem, user, "REVOKE", "Propose removal for approval"); err != nil {
		t.Fatal(err)
	}
	var decisions, proposed, actions int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM access_review_decisions WHERE organization_id=$1`, org).Scan(&decisions)
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE organization_id=$1 AND type='ACCESS_REVIEW_REVOCATION_PROPOSED'`, org).Scan(&proposed)
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM lifecycle_actions WHERE organization_id=$1`, org).Scan(&actions)
	if decisions != 2 || proposed != 1 || actions != 0 {
		t.Fatalf("decisions=%d proposed=%d remoteActions=%d", decisions, proposed, actions)
	}
}

func TestCrossOrganizationLifecycleCaseIsRejected(t *testing.T) {
	dbURL, _, _, _ := integrationEnvironment(t)
	ctx := context.Background()
	db, err := database.Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: db, Clock: RealClock{}}
	orgA, userA, sourceA, _, _, _ := seedTenant(t, db, "", "", "")
	orgB, _, sourceB, _, _, _ := seedTenant(t, db, "", "", "")
	if _, err = svc.ImportPeople(ctx, orgA, sourceA, peopleFixture(t)); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.ImportPeople(ctx, orgB, sourceB, peopleFixture(t)); err != nil {
		t.Fatal(err)
	}
	var personB string
	if err = db.Pool.QueryRow(ctx, `SELECT id FROM people WHERE organization_id=$1 AND external_person_id='E1001'`, orgB).Scan(&personB); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.CreateCase(ctx, orgA, personB, userA); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-organization case creation was not rejected: %v", err)
	}
	var cases int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM lifecycle_cases WHERE organization_id=$1`, orgA).Scan(&cases)
	if cases != 0 {
		t.Fatalf("cross-organization case was persisted: %d", cases)
	}
}

func integrationEnvironment(t *testing.T) (string, string, string, string) {
	t.Helper()
	db, a, b, l := os.Getenv("IDENTITYMESH_TEST_DATABASE_URL"), os.Getenv("IDENTITYMESH_TEST_SCIM_URL"), os.Getenv("IDENTITYMESH_TEST_SCIM_B_URL"), os.Getenv("IDENTITYMESH_TEST_LDAP_URL")
	if db == "" || a == "" || b == "" || l == "" {
		t.Skip("integration environment not configured")
	}
	return db, a, b, l
}
func peopleFixture(t *testing.T) []csvsource.Row {
	t.Helper()
	f, err := os.Open("../../../test/fixtures/people.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := csvsource.ParsePreview(f, csvsource.Mapping{EmployeeID: "employee_id", DisplayName: "display_name", Email: "email", Department: "department", ManagerID: "manager_id", Status: "status"}, 1<<20, 100)
	if err != nil || len(p.Errors) > 0 {
		t.Fatalf("fixture errors=%v err=%v", p.Errors, err)
	}
	return p.Rows
}
func seedTenant(t *testing.T, db *database.Store, aURL, bURL, ldapURL string) (string, string, string, string, string, string) {
	t.Helper()
	ctx := context.Background()
	org, user, source, a, b, l := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,$2)`, org, "Synthetic "+org); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO users(id,organization_id,email,display_name,password_hash) VALUES($1,$2,$3,'Synthetic Owner','not-used')`, user, org, "owner-"+org+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO identity_connectors(id,organization_id,name,type,write_enabled,capabilities) VALUES($1,$2,'CSV Source','CSV_AUTHORITATIVE_SOURCE',false,'["DISCOVER_USERS"]')`, source, org); err != nil {
		t.Fatal(err)
	}
	if aURL != "" {
		_, err := db.Pool.Exec(ctx, `INSERT INTO identity_connectors(id,organization_id,name,type,base_url,write_enabled,capabilities) VALUES($1,$2,'SCIM A','SCIM_2_0',$3,true,'["DISCOVER_USERS","DISCOVER_GROUPS","DISABLE_ACCOUNT"]')`, a, org, aURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	if bURL != "" {
		_, err := db.Pool.Exec(ctx, `INSERT INTO identity_connectors(id,organization_id,name,type,base_url,write_enabled,capabilities) VALUES($1,$2,'SCIM B','SCIM_2_0',$3,true,'["DISCOVER_USERS","DISCOVER_GROUPS","DISABLE_ACCOUNT"]')`, b, org, bURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	if ldapURL != "" {
		_, err := db.Pool.Exec(ctx, `INSERT INTO identity_connectors(id,organization_id,name,type,base_url,write_enabled,capabilities) VALUES($1,$2,'LDAP','LDAP_DIRECTORY',$3,false,'["DISCOVER_USERS","DISCOVER_GROUPS","DISCOVER_MEMBERSHIPS"]')`, l, org, ldapURL)
		if err != nil {
			t.Fatal(err)
		}
	}
	return org, user, source, a, b, l
}
func controlURL(scimURL, path string) string { return strings.TrimSuffix(scimURL, "/scim/v2") + path }
func resetProvider(t *testing.T, url string) {
	t.Helper()
	if url == "" {
		return
	}
	resp, err := http.Post(controlURL(url, "/__test/reset"), "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("reset status %d", resp.StatusCode)
	}
}
func setMode(t *testing.T, url, mode string) {
	t.Helper()
	resp, err := http.Post(controlURL(url, "/__test/mode/"+mode), "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("mode status %d", resp.StatusCode)
	}
}
