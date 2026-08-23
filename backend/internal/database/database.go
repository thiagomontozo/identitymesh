package database

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/identitymesh/backend/internal/auth"
	"github.com/thiagomontozo/identitymesh/backend/internal/domain"
)

type Store struct{ Pool *pgxpool.Pool }
type Session struct {
	ID, OrganizationID, UserID, Email, DisplayName string
	Roles                                          []string
	CSRFHash                                       []byte
	ExpiresAt                                      time.Time
}
type Dashboard struct{ People, ConnectedSystems, KnownIdentities, ActiveIdentities, OrphanAccounts, UnresolvedIdentities, TerminatedWithActive, PrivilegedAccounts, OffboardingsInProgress, OffboardingsFailed, RecentlyVerified, ConnectorsDegraded, AccessReviewsOverdue int }

func Open(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{Pool: pool}, nil
}
func (s *Store) Close() { s.Pool.Close() }
func (s *Store) Migrate(ctx context.Context, dir string) error {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// Serialize migration runners across application instances and concurrent
	// integration packages. The lock is session-scoped and always released.
	const migrationLock int64 = 4815162342
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLock); err != nil {
		return err
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrationLock) }()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		version := strings.TrimSuffix(entry.Name(), ".sql")
		var applied bool
		err = conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='schema_migrations') AND EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)", version).Scan(&applied)
		if err != nil {
			applied = false
		}
		if applied {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		if _, err = conn.Exec(ctx, string(raw)); err != nil {
			return fmt.Errorf("migration %s: %w", entry.Name(), err)
		}
	}
	return nil
}
func (s *Store) Bootstrap(ctx context.Context, email, password string) error {
	if email == "" || password == "" {
		return nil
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var orgID, userID uuid.UUID
	err = tx.QueryRow(ctx, "INSERT INTO organizations(name) VALUES('IdentityMesh Demo') ON CONFLICT DO NOTHING RETURNING id").Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, "SELECT id FROM organizations WHERE name='IdentityMesh Demo' LIMIT 1").Scan(&orgID)
	}
	if err != nil {
		return err
	}
	err = tx.QueryRow(ctx, "INSERT INTO users(organization_id,email,display_name,password_hash) VALUES($1,lower($2),'Demo Owner',$3) ON CONFLICT(organization_id,email) DO UPDATE SET email=EXCLUDED.email RETURNING id", orgID, email, hash).Scan(&userID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO user_roles(organization_id,user_id,role_id) SELECT $1,$2,id FROM roles WHERE name='OWNER' ON CONFLICT DO NOTHING", orgID, userID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Authenticate(ctx context.Context, email, password string) (Session, error) {
	var out Session
	var hash string
	err := s.Pool.QueryRow(ctx, "SELECT u.id,u.organization_id,u.email,u.display_name,u.password_hash FROM users u WHERE lower(u.email)=lower($1) AND NOT u.disabled", email).Scan(&out.UserID, &out.OrganizationID, &out.Email, &out.DisplayName, &hash)
	if err != nil || !auth.VerifyPassword(hash, password) {
		return Session{}, errors.New("invalid credentials")
	}
	rows, err := s.Pool.Query(ctx, "SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.organization_id=$1 AND ur.user_id=$2", out.OrganizationID, out.UserID)
	if err != nil {
		return Session{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			return Session{}, err
		}
		out.Roles = append(out.Roles, role)
	}
	return out, rows.Err()
}
func (s *Store) CreateSession(ctx context.Context, base Session, tokenHash, csrfHash []byte, expires time.Time) (Session, error) {
	base.ID = uuid.NewString()
	base.CSRFHash = csrfHash
	base.ExpiresAt = expires
	_, err := s.Pool.Exec(ctx, "INSERT INTO sessions(id,organization_id,user_id,token_hash,csrf_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6)", base.ID, base.OrganizationID, base.UserID, tokenHash, csrfHash, expires)
	return base, err
}
func (s *Store) SessionByToken(ctx context.Context, token string) (Session, error) {
	h := sha256.Sum256([]byte(token))
	var out Session
	err := s.Pool.QueryRow(ctx, "SELECT s.id,s.organization_id,s.user_id,u.email,u.display_name,s.csrf_hash,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND s.expires_at>now() AND NOT u.disabled", h[:]).Scan(&out.ID, &out.OrganizationID, &out.UserID, &out.Email, &out.DisplayName, &out.CSRFHash, &out.ExpiresAt)
	if err != nil {
		return out, err
	}
	rows, err := s.Pool.Query(ctx, "SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.organization_id=$1 AND ur.user_id=$2", out.OrganizationID, out.UserID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			return out, err
		}
		out.Roles = append(out.Roles, role)
	}
	_, _ = s.Pool.Exec(ctx, "UPDATE sessions SET last_seen_at=now() WHERE id=$1", out.ID)
	return out, rows.Err()
}
func (s *Store) RevokeSession(ctx context.Context, orgID, sessionID string) error {
	tag, err := s.Pool.Exec(ctx, "UPDATE sessions SET revoked_at=now() WHERE organization_id=$1 AND id=$2 AND revoked_at IS NULL", orgID, sessionID)
	if err == nil && tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return err
}
func (s *Store) ChangePassword(ctx context.Context, orgID, userID, current, next string) error {
	var hash string
	if err := s.Pool.QueryRow(ctx, "SELECT password_hash FROM users WHERE organization_id=$1 AND id=$2", orgID, userID).Scan(&hash); err != nil {
		return err
	}
	if !auth.VerifyPassword(hash, current) {
		return errors.New("current password is incorrect")
	}
	newHash, err := auth.HashPassword(next)
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "UPDATE users SET password_hash=$1,updated_at=now() WHERE organization_id=$2 AND id=$3", newHash, orgID, userID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE sessions SET revoked_at=now() WHERE organization_id=$1 AND user_id=$2", orgID, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) Audit(ctx context.Context, orgID, userID, eventType, resourceType string, resourceID any, metadata any, requestID string) error {
	raw, _ := json.Marshal(metadata)
	_, err := s.Pool.Exec(ctx, "INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,metadata,request_id) VALUES($1,$2,$3,$4,$5,$6,$7)", orgID, nullableUUID(userID), eventType, resourceType, resourceID, raw, requestID)
	return err
}
func nullableUUID(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (s *Store) Dashboard(ctx context.Context, orgID string) (Dashboard, error) {
	var d Dashboard
	err := s.Pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM people WHERE organization_id=$1),
 (SELECT count(*) FROM identity_connectors WHERE organization_id=$1 AND enabled),
 (SELECT count(*) FROM identity_accounts WHERE organization_id=$1),
 (SELECT count(*) FROM identity_accounts WHERE organization_id=$1 AND active_status='ACTIVE'),
 (SELECT count(*) FROM identity_accounts ia WHERE ia.organization_id=$1 AND NOT EXISTS(SELECT 1 FROM identity_links il WHERE il.organization_id=$1 AND il.identity_account_id=ia.id)),
 (SELECT count(*) FROM correlation_candidates WHERE organization_id=$1 AND status='PENDING'),
 (SELECT count(DISTINCT p.id) FROM people p JOIN identity_links l ON l.person_id=p.id AND l.organization_id=$1 JOIN identity_accounts a ON a.id=l.identity_account_id AND a.organization_id=$1 WHERE p.organization_id=$1 AND p.lifecycle_status='TERMINATED' AND a.active_status='ACTIVE'),
 (SELECT count(*) FROM identity_accounts WHERE organization_id=$1 AND privileged),
 (SELECT count(*) FROM lifecycle_cases WHERE organization_id=$1 AND status IN ('PLANNED','AWAITING_APPROVAL','APPROVED','RUNNING','VERIFYING')),
 (SELECT count(*) FROM lifecycle_cases WHERE organization_id=$1 AND status='FAILED'),
 (SELECT count(*) FROM lifecycle_cases WHERE organization_id=$1 AND verification_status='VERIFIED' AND completed_at>now()-interval '30 days'),
 (SELECT count(*) FROM identity_connectors WHERE organization_id=$1 AND last_sync_status IN ('FAILED','PARTIAL')),
 (SELECT count(*) FROM access_review_campaigns WHERE organization_id=$1 AND status IN ('ACTIVE','OVERDUE') AND due_at<now())`, orgID).Scan(&d.People, &d.ConnectedSystems, &d.KnownIdentities, &d.ActiveIdentities, &d.OrphanAccounts, &d.UnresolvedIdentities, &d.TerminatedWithActive, &d.PrivilegedAccounts, &d.OffboardingsInProgress, &d.OffboardingsFailed, &d.RecentlyVerified, &d.ConnectorsDegraded, &d.AccessReviewsOverdue)
	return d, err
}
func (s *Store) ListPeople(ctx context.Context, orgID, query, status string, limit, offset int) ([]domain.Person, error) {
	sql := `SELECT id,organization_id,external_person_id,display_name,coalesce(primary_email,''),coalesce(employee_number,''),coalesce(department,''),lifecycle_status,created_at,updated_at FROM people WHERE organization_id=$1 AND ($2='' OR lifecycle_status=$2) AND ($3='' OR display_name ILIKE '%'||$3||'%' OR primary_email ILIKE '%'||$3||'%' OR external_person_id ILIKE '%'||$3||'%') ORDER BY display_name LIMIT $4 OFFSET $5`
	rows, err := s.Pool.Query(ctx, sql, orgID, status, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Person{}
	for rows.Next() {
		var p domain.Person
		if err = rows.Scan(&p.ID, &p.OrganizationID, &p.ExternalPersonID, &p.DisplayName, &p.PrimaryEmail, &p.EmployeeNumber, &p.Department, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Store) GetPerson(ctx context.Context, orgID, id string) (domain.Person, []domain.IdentityAccount, error) {
	var p domain.Person
	err := s.Pool.QueryRow(ctx, `SELECT id,organization_id,external_person_id,display_name,coalesce(primary_email,''),coalesce(employee_number,''),coalesce(department,''),lifecycle_status,created_at,updated_at FROM people WHERE organization_id=$1 AND id=$2`, orgID, id).Scan(&p.ID, &p.OrganizationID, &p.ExternalPersonID, &p.DisplayName, &p.PrimaryEmail, &p.EmployeeNumber, &p.Department, &p.Status, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return p, nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT a.id,a.organization_id,a.connector_id,a.external_account_id,a.username,coalesce(a.display_name,''),coalesce(a.primary_email,''),coalesce(a.employee_number,''),a.active_status,a.account_type,a.privileged,a.first_seen_at,a.last_seen_at FROM identity_accounts a JOIN identity_links l ON l.identity_account_id=a.id AND l.organization_id=$1 WHERE a.organization_id=$1 AND l.person_id=$2 ORDER BY a.username`, orgID, id)
	if err != nil {
		return p, nil, err
	}
	defer rows.Close()
	accounts := []domain.IdentityAccount{}
	for rows.Next() {
		var a domain.IdentityAccount
		if err = rows.Scan(&a.ID, &a.OrganizationID, &a.ConnectorID, &a.ExternalAccountID, &a.Username, &a.DisplayName, &a.PrimaryEmail, &a.EmployeeNumber, &a.ActiveStatus, &a.AccountType, &a.Privileged, &a.FirstSeenAt, &a.LastSeenAt); err != nil {
			return p, nil, err
		}
		accounts = append(accounts, a)
	}
	return p, accounts, rows.Err()
}
func (s *Store) ListConnectors(ctx context.Context, orgID string) ([]map[string]any, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,name,type,coalesce(base_url,''),environment,enabled,read_enabled,write_enabled,capabilities,last_sync_status,last_sync_at FROM identity_connectors WHERE organization_id=$1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, typ, baseURL, env, status string
		var enabled, readEnabled, writeEnabled bool
		var caps []byte
		var last *time.Time
		if err = rows.Scan(&id, &name, &typ, &baseURL, &env, &enabled, &readEnabled, &writeEnabled, &caps, &status, &last); err != nil {
			return nil, err
		}
		var capabilities any
		_ = json.Unmarshal(caps, &capabilities)
		out = append(out, map[string]any{"id": id, "name": name, "type": typ, "baseURL": baseURL, "environment": env, "enabled": enabled, "readEnabled": readEnabled, "writeEnabled": writeEnabled, "capabilities": capabilities, "lastSyncStatus": status, "lastSyncAt": last})
	}
	return out, rows.Err()
}
