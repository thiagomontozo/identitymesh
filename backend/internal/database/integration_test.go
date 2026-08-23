//go:build integration

package database

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestMigrationsAndOrganizationIsolation(t *testing.T) {
	url := os.Getenv("IDENTITYMESH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("IDENTITYMESH_TEST_DATABASE_URL not configured")
	}
	ctx := context.Background()
	store, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Migrate(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	orgA, orgB := uuid.NewString(), uuid.NewString()
	if _, err = store.Pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,$2),($3,$4)`, orgA, "Isolation A "+orgA, orgB, "Isolation B "+orgB); err != nil {
		t.Fatal(err)
	}
	personB := uuid.NewString()
	if _, err = store.Pool.Exec(ctx, `INSERT INTO people(id,organization_id,external_person_id,display_name,lifecycle_status) VALUES($1,$2,'B-1','Private Person','ACTIVE')`, personB, orgB); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.GetPerson(ctx, orgA, personB); err != pgx.ErrNoRows {
		t.Fatalf("cross-organization access occurred: %v", err)
	}
}

func TestProductCompletionMigrationAndTenantScopedReports(t *testing.T) {
	url := os.Getenv("IDENTITYMESH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("IDENTITYMESH_TEST_DATABASE_URL not configured")
	}
	ctx := context.Background()
	store, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Migrate(ctx, "../../../migrations"); err != nil {
		t.Fatal(err)
	}
	var migrated bool
	if err = store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version='002_product_completion')`).Scan(&migrated); err != nil || !migrated {
		t.Fatalf("completion migration missing: %v", err)
	}
	orgA, orgB := uuid.NewString(), uuid.NewString()
	_, err = store.Pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,$2),($3,$4)`, orgA, "Product A "+orgA, orgB, "Product B "+orgB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Pool.Exec(ctx, `INSERT INTO organization_settings(organization_id,trusted_email_domains) VALUES($1,'["a.example"]'),($2,'["b.example"]')`, orgA, orgB)
	if err != nil {
		t.Fatal(err)
	}
	var domains []byte
	err = store.Pool.QueryRow(ctx, `SELECT trusted_email_domains FROM organization_settings WHERE organization_id=$1`, orgA).Scan(&domains)
	if err != nil || string(domains) != `["a.example"]` {
		t.Fatalf("tenant settings mismatch: %s %v", domains, err)
	}
	err = store.Pool.QueryRow(ctx, `SELECT trusted_email_domains FROM organization_settings WHERE organization_id=$1 AND organization_id=$2`, orgA, orgB).Scan(&domains)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-organization settings visible: %v", err)
	}
}
