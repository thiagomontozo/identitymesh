//go:build integration

package database

import (
	"context"
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
