package assurance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/entra"
	githubconnector "github.com/thiagomontozo/identitymesh/backend/internal/connectors/github"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/googleworkspace"
	ldapconnector "github.com/thiagomontozo/identitymesh/backend/internal/connectors/ldap"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/okta"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/provider"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/scim"
	"github.com/thiagomontozo/identitymesh/backend/internal/correlation"
	"github.com/thiagomontozo/identitymesh/backend/internal/csvsource"
	"github.com/thiagomontozo/identitymesh/backend/internal/database"
	"github.com/thiagomontozo/identitymesh/backend/internal/domain"
	"github.com/thiagomontozo/identitymesh/backend/internal/notifier"
	"github.com/thiagomontozo/identitymesh/backend/internal/secure"
)

type Clock interface{ Now() time.Time }
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now().UTC() }

type Service struct {
	DB        *database.Store
	Secrets   secure.SecretStore
	Clock     Clock
	AllowHTTP bool
	Timeout   time.Duration
	Notifier  notifier.Notifier
}

func (s *Service) connectorToken(ctx context.Context, orgID, connectorID string) (string, error) {
	var ciphertext string
	err := s.DB.Pool.QueryRow(ctx, `SELECT ciphertext FROM connector_credentials WHERE organization_id=$1 AND connector_id=$2`, orgID, connectorID).Scan(&ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if s.Secrets == nil {
		return "", errors.New("connector credential store is unavailable")
	}
	plaintext, err := s.Secrets.Decrypt(ciphertext)
	if err != nil {
		return "", errors.New("connector credential could not be decrypted")
	}
	return string(plaintext), nil
}

type SyncResult struct {
	RunID              string `json:"runId"`
	AccountsDiscovered int    `json:"accountsDiscovered"`
	GroupsDiscovered   int    `json:"groupsDiscovered"`
	FindingsCreated    int    `json:"findingsCreated"`
	Status             string `json:"status"`
}

func (s *Service) SyncConnector(ctx context.Context, orgID, connectorID, requestID string) (SyncResult, error) {
	var connectorType string
	if err := s.DB.Pool.QueryRow(ctx, `SELECT type FROM identity_connectors WHERE organization_id=$1 AND id=$2`, orgID, connectorID).Scan(&connectorType); err != nil {
		return SyncResult{}, err
	}
	switch connectorType {
	case "SCIM_2_0":
		return s.SyncSCIM(ctx, orgID, connectorID, requestID)
	case "LDAP_DIRECTORY":
		cfg, err := s.ldapConfiguration(ctx, orgID, connectorID)
		if err != nil {
			return SyncResult{}, err
		}
		return s.SyncLDAP(ctx, orgID, connectorID, requestID, cfg)
	case "ENTRA_ID", "OKTA", "GOOGLE_WORKSPACE", "GITHUB":
		return s.SyncNative(ctx, orgID, connectorID, requestID)
	default:
		return SyncResult{}, errors.New("connector type does not support remote synchronization")
	}
}

func (s *Service) TestConnection(ctx context.Context, orgID, connectorID string) error {
	var connectorType string
	if err := s.DB.Pool.QueryRow(ctx, `SELECT type FROM identity_connectors WHERE organization_id=$1 AND id=$2`, orgID, connectorID).Scan(&connectorType); err != nil {
		return err
	}
	if connectorType == "SCIM_2_0" {
		return s.TestSCIMConnection(ctx, orgID, connectorID)
	}
	if connectorType == "LDAP_DIRECTORY" {
		cfg, err := s.ldapConfiguration(ctx, orgID, connectorID)
		if err != nil {
			return err
		}
		client, err := ldapconnector.New(cfg)
		if err != nil {
			return err
		}
		return client.TestConnection(ctx)
	}
	if connectorType == "ENTRA_ID" || connectorType == "OKTA" || connectorType == "GOOGLE_WORKSPACE" || connectorType == "GITHUB" {
		client, err := s.nativeClient(ctx, orgID, connectorID)
		if err != nil {
			return err
		}
		return client.TestConnection(ctx)
	}
	return errors.New("connector type has no remote connection to test")
}

func (s *Service) ldapConfiguration(ctx context.Context, orgID, connectorID string) (ldapconnector.Config, error) {
	var baseURL string
	var raw []byte
	if err := s.DB.Pool.QueryRow(ctx, `SELECT coalesce(base_url,''),configuration FROM identity_connectors WHERE organization_id=$1 AND id=$2 AND type='LDAP_DIRECTORY'`, orgID, connectorID).Scan(&baseURL, &raw); err != nil {
		return ldapconnector.Config{}, err
	}
	var values struct {
		BindDN, SearchBase, UserFilter, GroupFilter, ServerName, DisableStrategy, MembershipAttribute string
		PageSize                                                                                      uint32
	}
	if err := json.Unmarshal(raw, &values); err != nil {
		return ldapconnector.Config{}, errors.New("LDAP connector configuration is malformed")
	}
	password, err := s.connectorToken(ctx, orgID, connectorID)
	if err != nil {
		return ldapconnector.Config{}, err
	}
	return ldapconnector.Config{URL: baseURL, BindDN: values.BindDN, Password: password, SearchBase: values.SearchBase, UserFilter: values.UserFilter, GroupFilter: values.GroupFilter, PageSize: values.PageSize, Timeout: s.Timeout, ServerName: values.ServerName, DisableStrategy: values.DisableStrategy, MembershipAttribute: values.MembershipAttribute}, nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func ldapValue(attributes map[string][]string, name string) string {
	for key, values := range attributes {
		if strings.EqualFold(key, name) {
			return first(values)
		}
	}
	return ""
}

func ldapValues(attributes map[string][]string, name string) []string {
	for key, values := range attributes {
		if strings.EqualFold(key, name) {
			return values
		}
	}
	return nil
}

// SyncLDAP performs discovery independently of whether explicitly configured
// write capabilities are enabled.
func (s *Service) SyncLDAP(ctx context.Context, orgID, connectorID, requestID string, cfg ldapconnector.Config) (SyncResult, error) {
	var name string
	var enabled, readEnabled bool
	if err := s.DB.Pool.QueryRow(ctx, `SELECT name,enabled,read_enabled FROM identity_connectors WHERE organization_id=$1 AND id=$2 AND type='LDAP_DIRECTORY'`, orgID, connectorID).Scan(&name, &enabled, &readEnabled); err != nil {
		return SyncResult{}, err
	}
	if !enabled || !readEnabled {
		return SyncResult{}, errors.New("connector discovery is disabled")
	}
	runID := uuid.NewString()
	if _, err := s.DB.Pool.Exec(ctx, `INSERT INTO connector_syncs(id,organization_id,connector_id,trigger_type,status,request_id) VALUES($1,$2,$3,'MANUAL','RUNNING',$4)`, runID, orgID, connectorID, requestID); err != nil {
		return SyncResult{}, err
	}
	if _, err := s.DB.Pool.Exec(ctx, `INSERT INTO reconciliation_runs(id,organization_id,connector_id,trigger_type,status) VALUES($1,$2,$3,'MANUAL','RUNNING')`, runID, orgID, connectorID); err != nil {
		return SyncResult{}, err
	}
	client, err := ldapconnector.New(cfg)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "LDAP_CONFIGURATION_ERROR", err)
	}
	users, err := client.SearchUsers(ctx)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "LDAP_DISCOVERY_FAILED", err)
	}
	groups, err := client.SearchGroups(ctx)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "LDAP_GROUP_DISCOVERY_FAILED", err)
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	defer tx.Rollback(ctx)
	seenAccounts := make([]string, 0, len(users))
	for _, entry := range users {
		state := "ACTIVE"
		if strings.EqualFold(ldapValue(entry.Attributes, "description"), "DISABLED") || ldapValue(entry.Attributes, "pwdAccountLockedTime") != "" {
			state = "DISABLED"
		}
		accountType := "HUMAN"
		uid := ldapValue(entry.Attributes, "uid")
		if strings.HasPrefix(uid, "service.") {
			accountType = "SERVICE"
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity_accounts(organization_id,connector_id,external_account_id,username,display_name,primary_email,employee_number,active_status,account_type,raw_attributes_summary) VALUES($1,$2,$3,$4,$5,nullif($6,''),nullif($7,''),$8,$9,jsonb_build_object('dn',$3::text)) ON CONFLICT(organization_id,connector_id,external_account_id) DO UPDATE SET username=EXCLUDED.username,display_name=EXCLUDED.display_name,primary_email=EXCLUDED.primary_email,employee_number=EXCLUDED.employee_number,active_status=EXCLUDED.active_status,account_type=EXCLUDED.account_type,last_seen_at=now(),missing_since=NULL,updated_at=now()`, orgID, connectorID, entry.DN, uid, ldapValue(entry.Attributes, "cn"), ldapValue(entry.Attributes, "mail"), ldapValue(entry.Attributes, "employeeNumber"), state, accountType)
		if err != nil {
			return SyncResult{}, err
		}
		seenAccounts = append(seenAccounts, entry.DN)
	}
	if _, err = tx.Exec(ctx, `UPDATE identity_accounts SET active_status='MISSING',missing_since=coalesce(missing_since,now()),updated_at=now() WHERE organization_id=$1 AND connector_id=$2 AND NOT(external_account_id=ANY($3::text[]))`, orgID, connectorID, seenAccounts); err != nil {
		return SyncResult{}, err
	}
	for _, group := range groups {
		name := ldapValue(group.Attributes, "cn")
		var entitlementID string
		if err = tx.QueryRow(ctx, `INSERT INTO entitlements(organization_id,connector_id,external_id,name,type) VALUES($1,$2,$3,$4,'GROUP') ON CONFLICT(organization_id,connector_id,external_id) DO UPDATE SET name=EXCLUDED.name,last_seen_at=now() RETURNING id`, orgID, connectorID, group.DN, name).Scan(&entitlementID); err != nil {
			return SyncResult{}, err
		}
		members := append([]string{}, ldapValues(group.Attributes, "member")...)
		members = append(members, ldapValues(group.Attributes, "uniqueMember")...)
		for _, memberDN := range members {
			if _, err = tx.Exec(ctx, `INSERT INTO access_grants(organization_id,identity_account_id,entitlement_id,source) SELECT $1,id,$2,'LDAP_GROUP' FROM identity_accounts WHERE organization_id=$1 AND connector_id=$3 AND external_account_id=$4 ON CONFLICT(organization_id,identity_account_id,entitlement_id) DO UPDATE SET active=true,last_seen_at=now()`, orgID, entitlementID, connectorID, memberDN); err != nil {
				return SyncResult{}, err
			}
		}
	}
	findings, err := s.correlate(ctx, tx, orgID, connectorID)
	if err != nil {
		return SyncResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE connector_syncs SET status='SUCCEEDED',completed_at=now(),accounts_discovered=$1,groups_discovered=$2,summary=jsonb_build_object('connector',$3::text,'readOnly',true) WHERE organization_id=$4 AND id=$5`, len(users), len(groups), name, orgID, runID); err != nil {
		return SyncResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE identity_connectors SET last_sync_at=now(),last_sync_status='SUCCEEDED',updated_at=now() WHERE organization_id=$1 AND id=$2`, orgID, connectorID); err != nil {
		return SyncResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE reconciliation_runs SET status='SUCCEEDED',completed_at=now(),accounts_discovered=$1,groups_discovered=$2,findings_created=$3,summary=jsonb_build_object('readOnly',true) WHERE organization_id=$4 AND id=$5`, len(users), len(groups), findings, orgID, runID); err != nil {
		return SyncResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SyncResult{}, err
	}
	return SyncResult{RunID: runID, AccountsDiscovered: len(users), GroupsDiscovered: len(groups), FindingsCreated: findings, Status: "SUCCEEDED"}, nil
}

func (s *Service) ImportPeople(ctx context.Context, orgID, sourceID string, rows []csvsource.Row) (int, error) {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	count := 0
	for _, row := range rows {
		tag, err := tx.Exec(ctx, `INSERT INTO people(organization_id,authoritative_source_id,external_person_id,display_name,primary_email,employee_number,department,lifecycle_status) VALUES($1,$2,$3,$4,nullif($5,''),$3,nullif($6,''),$7) ON CONFLICT(organization_id,authoritative_source_id,external_person_id) DO UPDATE SET display_name=EXCLUDED.display_name,primary_email=EXCLUDED.primary_email,department=EXCLUDED.department,lifecycle_status=EXCLUDED.lifecycle_status,updated_at=now()`, orgID, sourceID, row.EmployeeID, row.DisplayName, row.Email, row.Department, row.Status)
		if err != nil {
			return 0, err
		}
		count += int(tag.RowsAffected())
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Service) SyncSCIM(ctx context.Context, orgID, connectorID, requestID string) (SyncResult, error) {
	var name, baseURL string
	var enabled, readEnabled bool
	err := s.DB.Pool.QueryRow(ctx, `SELECT name,base_url,enabled,read_enabled FROM identity_connectors WHERE organization_id=$1 AND id=$2 AND type='SCIM_2_0'`, orgID, connectorID).Scan(&name, &baseURL, &enabled, &readEnabled)
	if err != nil {
		return SyncResult{}, err
	}
	if !enabled || !readEnabled {
		return SyncResult{}, errors.New("connector discovery is disabled")
	}
	runID := uuid.NewString()
	_, err = s.DB.Pool.Exec(ctx, `INSERT INTO connector_syncs(id,organization_id,connector_id,trigger_type,status,request_id) VALUES($1,$2,$3,'MANUAL','RUNNING',$4)`, runID, orgID, connectorID, requestID)
	if err != nil {
		return SyncResult{}, err
	}
	if _, err = s.DB.Pool.Exec(ctx, `INSERT INTO reconciliation_runs(id,organization_id,connector_id,trigger_type,status) VALUES($1,$2,$3,'MANUAL','RUNNING')`, runID, orgID, connectorID); err != nil {
		return SyncResult{}, err
	}
	token, err := s.connectorToken(ctx, orgID, connectorID)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "CREDENTIAL_ERROR", err)
	}
	client, err := scim.New(baseURL, token, s.AllowHTTP, s.Timeout)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "CONFIGURATION_ERROR", err)
	}
	users, err := client.ListUsers(ctx, 100)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "SCIM_DISCOVERY_FAILED", err)
	}
	groups, err := client.ListGroups(ctx, 100)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "SCIM_GROUP_DISCOVERY_FAILED", err)
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	defer tx.Rollback(ctx)
	seen := make([]string, 0, len(users))
	for _, u := range users {
		email := ""
		for _, e := range u.Emails {
			if e.Primary || email == "" {
				email = strings.ToLower(strings.TrimSpace(e.Value))
			}
		}
		status := "DISABLED"
		if u.Active {
			status = "ACTIVE"
		}
		var id string
		err = tx.QueryRow(ctx, `INSERT INTO identity_accounts(organization_id,connector_id,external_account_id,username,display_name,primary_email,active_status,account_type,provider_updated_at,raw_attributes_summary) VALUES($1,$2,$3,$4,$5,nullif($6,''),$7,'UNKNOWN',nullif($8::timestamptz,'0001-01-01T00:00:00Z'),jsonb_build_object('externalId',$9::text)) ON CONFLICT(organization_id,connector_id,external_account_id) DO UPDATE SET username=EXCLUDED.username,display_name=EXCLUDED.display_name,primary_email=EXCLUDED.primary_email,active_status=EXCLUDED.active_status,provider_updated_at=EXCLUDED.provider_updated_at,last_seen_at=now(),missing_since=NULL,updated_at=now() RETURNING id`, orgID, connectorID, u.ID, u.UserName, u.DisplayName, email, status, u.Meta.LastModified.UTC().Format(time.RFC3339), u.ExternalID).Scan(&id)
		if err != nil {
			return SyncResult{}, err
		}
		seen = append(seen, id)
	}
	for _, g := range groups {
		var entitlementID string
		err = tx.QueryRow(ctx, `INSERT INTO entitlements(organization_id,connector_id,external_id,name,type) VALUES($1,$2,$3,$4,'GROUP') ON CONFLICT(organization_id,connector_id,external_id) DO UPDATE SET name=EXCLUDED.name,last_seen_at=now() RETURNING id`, orgID, connectorID, g.ID, g.DisplayName).Scan(&entitlementID)
		if err != nil {
			return SyncResult{}, err
		}
		for _, m := range g.Members {
			_, err = tx.Exec(ctx, `INSERT INTO access_grants(organization_id,identity_account_id,entitlement_id,source) SELECT $1,a.id,$2,'SCIM_GROUP' FROM identity_accounts a WHERE a.organization_id=$1 AND a.connector_id=$3 AND a.external_account_id=$4 ON CONFLICT(organization_id,identity_account_id,entitlement_id) DO UPDATE SET active=true,last_seen_at=now()`, orgID, entitlementID, connectorID, m.Value)
			if err != nil {
				return SyncResult{}, err
			}
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE identity_accounts SET active_status='MISSING',missing_since=coalesce(missing_since,now()),updated_at=now() WHERE organization_id=$1 AND connector_id=$2 AND NOT(id=ANY($3::uuid[]))`, orgID, connectorID, seen); err != nil {
		return SyncResult{}, err
	}
	findings, err := s.correlate(ctx, tx, orgID, connectorID)
	if err != nil {
		return SyncResult{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE connector_syncs SET status='SUCCEEDED',completed_at=now(),accounts_discovered=$1,groups_discovered=$2,summary=jsonb_build_object('connector',$3::text) WHERE organization_id=$4 AND id=$5`, len(users), len(groups), name, orgID, runID)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE identity_connectors SET last_sync_at=now(),last_sync_status='SUCCEEDED',updated_at=now() WHERE organization_id=$1 AND id=$2`, orgID, connectorID)
	}
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE reconciliation_runs SET status='SUCCEEDED',completed_at=now(),accounts_discovered=$1,groups_discovered=$2,findings_created=$3,summary=jsonb_build_object('normalized',true,'stalePreservedOnFailure',true) WHERE organization_id=$4 AND id=$5`, len(users), len(groups), findings, orgID, runID)
	}
	if err != nil {
		return SyncResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SyncResult{}, err
	}
	return SyncResult{RunID: runID, AccountsDiscovered: len(users), GroupsDiscovered: len(groups), FindingsCreated: findings, Status: "SUCCEEDED"}, nil
}

func (s *Service) nativeClient(ctx context.Context, orgID, connectorID string) (provider.Client, error) {
	var connectorType, baseURL string
	var raw []byte
	if err := s.DB.Pool.QueryRow(ctx, `SELECT type,coalesce(base_url,''),configuration FROM identity_connectors WHERE organization_id=$1 AND id=$2 AND type IN ('ENTRA_ID','OKTA','GOOGLE_WORKSPACE','GITHUB')`, orgID, connectorID).Scan(&connectorType, &baseURL, &raw); err != nil {
		return nil, err
	}
	credential, err := s.connectorToken(ctx, orgID, connectorID)
	if err != nil {
		return nil, err
	}
	var configuration struct {
		Customer     string `json:"customer"`
		Organization string `json:"organization"`
	}
	if err = json.Unmarshal(raw, &configuration); err != nil {
		return nil, errors.New("native connector configuration is malformed")
	}
	switch connectorType {
	case "ENTRA_ID":
		return entra.New(baseURL, credential, s.AllowHTTP, s.Timeout)
	case "OKTA":
		return okta.New(baseURL, credential, s.AllowHTTP, s.Timeout)
	case "GOOGLE_WORKSPACE":
		return googleworkspace.New(baseURL, credential, configuration.Customer, s.AllowHTTP, s.Timeout)
	case "GITHUB":
		return githubconnector.New(baseURL, credential, configuration.Organization, s.AllowHTTP, s.Timeout)
	default:
		return nil, errors.New("unsupported native connector type")
	}
}

func (s *Service) SyncNative(ctx context.Context, orgID, connectorID, requestID string) (SyncResult, error) {
	var name, connectorType string
	var enabled, readEnabled bool
	if err := s.DB.Pool.QueryRow(ctx, `SELECT name,type,enabled,read_enabled FROM identity_connectors WHERE organization_id=$1 AND id=$2 AND type IN ('ENTRA_ID','OKTA','GOOGLE_WORKSPACE','GITHUB')`, orgID, connectorID).Scan(&name, &connectorType, &enabled, &readEnabled); err != nil {
		return SyncResult{}, err
	}
	if !enabled || !readEnabled {
		return SyncResult{}, errors.New("connector discovery is disabled")
	}
	runID := uuid.NewString()
	if _, err := s.DB.Pool.Exec(ctx, `INSERT INTO connector_syncs(id,organization_id,connector_id,trigger_type,status,request_id) VALUES($1,$2,$3,'MANUAL','RUNNING',$4)`, runID, orgID, connectorID, requestID); err != nil {
		return SyncResult{}, err
	}
	if _, err := s.DB.Pool.Exec(ctx, `INSERT INTO reconciliation_runs(id,organization_id,connector_id,trigger_type,status) VALUES($1,$2,$3,'MANUAL','RUNNING')`, runID, orgID, connectorID); err != nil {
		return SyncResult{}, err
	}
	client, err := s.nativeClient(ctx, orgID, connectorID)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "NATIVE_CONFIGURATION_ERROR", err)
	}
	users, err := client.ListUsers(ctx)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "NATIVE_DISCOVERY_FAILED", err)
	}
	groups, err := client.ListGroups(ctx)
	if err != nil {
		return s.failSync(ctx, orgID, connectorID, runID, "NATIVE_GROUP_DISCOVERY_FAILED", err)
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	defer tx.Rollback(ctx)
	seen := make([]string, 0, len(users))
	for _, user := range users {
		state := "DISABLED"
		if user.Active {
			state = "ACTIVE"
		}
		accountType := "HUMAN"
		if user.Username == "" {
			accountType = "UNKNOWN"
		}
		var accountID string
		err = tx.QueryRow(ctx, `INSERT INTO identity_accounts(organization_id,connector_id,external_account_id,username,display_name,primary_email,employee_number,active_status,account_type,privileged,provider_updated_at,raw_attributes_summary) VALUES($1,$2,$3,$4,$5,nullif($6,''),nullif($7,''),$8,$9,$10,nullif($11::timestamptz,'0001-01-01T00:00:00Z'),jsonb_build_object('nativeProvider',$12::text,'externalId',$13::text)) ON CONFLICT(organization_id,connector_id,external_account_id) DO UPDATE SET username=EXCLUDED.username,display_name=EXCLUDED.display_name,primary_email=EXCLUDED.primary_email,employee_number=EXCLUDED.employee_number,active_status=EXCLUDED.active_status,account_type=EXCLUDED.account_type,privileged=EXCLUDED.privileged,provider_updated_at=EXCLUDED.provider_updated_at,last_seen_at=now(),missing_since=NULL,updated_at=now() RETURNING id`, orgID, connectorID, user.ID, user.Username, user.DisplayName, user.PrimaryEmail, user.EmployeeNumber, state, accountType, user.Privileged, user.UpdatedAt.UTC().Format(time.RFC3339), connectorType, user.ExternalID).Scan(&accountID)
		if err != nil {
			return SyncResult{}, err
		}
		seen = append(seen, accountID)
	}
	for _, group := range groups {
		var entitlementID string
		if err = tx.QueryRow(ctx, `INSERT INTO entitlements(organization_id,connector_id,external_id,name,type) VALUES($1,$2,$3,$4,'GROUP') ON CONFLICT(organization_id,connector_id,external_id) DO UPDATE SET name=EXCLUDED.name,last_seen_at=now() RETURNING id`, orgID, connectorID, group.ID, group.Name).Scan(&entitlementID); err != nil {
			return SyncResult{}, err
		}
		for _, memberID := range group.Members {
			if _, err = tx.Exec(ctx, `INSERT INTO access_grants(organization_id,identity_account_id,entitlement_id,source) SELECT $1,id,$2,$3 FROM identity_accounts WHERE organization_id=$1 AND connector_id=$4 AND external_account_id=$5 ON CONFLICT(organization_id,identity_account_id,entitlement_id) DO UPDATE SET active=true,last_seen_at=now()`, orgID, entitlementID, connectorType+"_GROUP", connectorID, memberID); err != nil {
				return SyncResult{}, err
			}
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE identity_accounts SET active_status='MISSING',missing_since=coalesce(missing_since,now()),updated_at=now() WHERE organization_id=$1 AND connector_id=$2 AND NOT(id=ANY($3::uuid[]))`, orgID, connectorID, seen); err != nil {
		return SyncResult{}, err
	}
	findings, err := s.correlate(ctx, tx, orgID, connectorID)
	if err != nil {
		return SyncResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE connector_syncs SET status='SUCCEEDED',completed_at=now(),accounts_discovered=$1,groups_discovered=$2,summary=jsonb_build_object('connector',$3::text,'nativeProvider',$4::text) WHERE organization_id=$5 AND id=$6`, len(users), len(groups), name, connectorType, orgID, runID); err != nil {
		return SyncResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE identity_connectors SET last_sync_at=now(),last_sync_status='SUCCEEDED',updated_at=now() WHERE organization_id=$1 AND id=$2`, orgID, connectorID); err != nil {
		return SyncResult{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE reconciliation_runs SET status='SUCCEEDED',completed_at=now(),accounts_discovered=$1,groups_discovered=$2,findings_created=$3,summary=jsonb_build_object('nativeProvider',$4::text,'stalePreservedOnFailure',true) WHERE organization_id=$5 AND id=$6`, len(users), len(groups), findings, connectorType, orgID, runID); err != nil {
		return SyncResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SyncResult{}, err
	}
	return SyncResult{RunID: runID, AccountsDiscovered: len(users), GroupsDiscovered: len(groups), FindingsCreated: findings, Status: "SUCCEEDED"}, nil
}

func (s *Service) TestSCIMConnection(ctx context.Context, orgID, connectorID string) error {
	var baseURL string
	if err := s.DB.Pool.QueryRow(ctx, `SELECT base_url FROM identity_connectors WHERE organization_id=$1 AND id=$2 AND type='SCIM_2_0' AND enabled`, orgID, connectorID).Scan(&baseURL); err != nil {
		return err
	}
	token, err := s.connectorToken(ctx, orgID, connectorID)
	if err != nil {
		return err
	}
	client, err := scim.New(baseURL, token, s.AllowHTTP, s.Timeout)
	if err != nil {
		return err
	}
	return client.TestConnection(ctx)
}
func (s *Service) failSync(ctx context.Context, orgID, connectorID, runID, code string, cause error) (SyncResult, error) {
	_, _ = s.DB.Pool.Exec(ctx, `UPDATE connector_syncs SET status='FAILED',completed_at=now(),error_code=$1,summary=jsonb_build_object('message',$2::text) WHERE organization_id=$3 AND id=$4`, code, cause.Error(), orgID, runID)
	_, _ = s.DB.Pool.Exec(ctx, `UPDATE identity_connectors SET last_sync_status='FAILED',updated_at=now() WHERE organization_id=$1 AND id=$2`, orgID, connectorID)
	_, _ = s.DB.Pool.Exec(ctx, `UPDATE reconciliation_runs SET status='FAILED',completed_at=now(),summary=jsonb_build_object('errorCode',$1::text,'staleDataPreserved',true) WHERE organization_id=$2 AND id=$3`, code, orgID, runID)
	if s.Notifier != nil {
		_ = s.Notifier.Notify(ctx, notifier.Event{OrganizationID: orgID, Type: "CONNECTOR_SYNC_FAILED", Payload: map[string]any{"connectorId": connectorID, "runId": runID, "errorCode": code}, OccurredAt: s.Clock.Now()})
	}
	return SyncResult{RunID: runID, Status: "FAILED"}, cause
}
func (s *Service) correlate(ctx context.Context, tx pgx.Tx, orgID, connectorID string) (int, error) {
	accounts, err := tx.Query(ctx, `SELECT id,external_account_id,username,coalesce(display_name,''),coalesce(primary_email,''),coalesce(employee_number,raw_attributes_summary->>'employeeNumber',''),coalesce(raw_attributes_summary->>'externalId','') FROM identity_accounts WHERE organization_id=$1 AND connector_id=$2`, orgID, connectorID)
	if err != nil {
		return 0, err
	}
	type acc struct{ id, external, username, name, email, employee, providerExternal string }
	var all []acc
	for accounts.Next() {
		var a acc
		if err = accounts.Scan(&a.id, &a.external, &a.username, &a.name, &a.email, &a.employee, &a.providerExternal); err != nil {
			accounts.Close()
			return 0, err
		}
		all = append(all, a)
	}
	accounts.Close()
	people, err := tx.Query(ctx, `SELECT id,external_person_id,display_name,coalesce(primary_email,''),coalesce(employee_number,''),coalesce(department,''),lifecycle_status,created_at,updated_at FROM people WHERE organization_id=$1`, orgID)
	if err != nil {
		return 0, err
	}
	var persons []domain.Person
	for people.Next() {
		var p domain.Person
		if err = people.Scan(&p.ID, &p.ExternalPersonID, &p.DisplayName, &p.PrimaryEmail, &p.EmployeeNumber, &p.Department, &p.Status, &p.CreatedAt, &p.UpdatedAt); err != nil {
			people.Close()
			return 0, err
		}
		p.OrganizationID = orgID
		persons = append(persons, p)
	}
	people.Close()
	emailCounts := make(map[string]int, len(persons))
	for _, p := range persons {
		if email := strings.ToLower(strings.TrimSpace(p.PrimaryEmail)); email != "" {
			emailCounts[email]++
		}
	}
	findings := 0
	for _, a := range all {
		linked := false
		candidate := false
		for _, p := range persons {
			if a.providerExternal != "" && strings.EqualFold(strings.TrimSpace(a.providerExternal), strings.TrimSpace(p.ExternalPersonID)) {
				_, err = tx.Exec(ctx, `INSERT INTO identity_links(organization_id,person_id,identity_account_id,link_type,confidence,reason) VALUES($1,$2,$3,'AUTOMATIC','HIGH','exact authoritative external identifier') ON CONFLICT(organization_id,identity_account_id) DO NOTHING`, orgID, p.ID, a.id)
				if err != nil {
					return 0, err
				}
				linked = true
				break
			}
			email := strings.ToLower(strings.TrimSpace(a.email))
			r := correlation.Evaluate(p, domain.IdentityAccount{DisplayName: a.name, PrimaryEmail: a.email, EmployeeNumber: a.employee}, map[string]bool{"identitymesh.test": true, "example.test": true}, email != "" && emailCounts[email] == 1)
			if r.Automatic {
				_, err = tx.Exec(ctx, `INSERT INTO identity_links(organization_id,person_id,identity_account_id,link_type,confidence,reason) VALUES($1,$2,$3,'AUTOMATIC',$4,$5) ON CONFLICT(organization_id,identity_account_id) DO NOTHING`, orgID, p.ID, a.id, r.Confidence, strings.Join(r.Reasons, "; "))
				if err != nil {
					return 0, err
				}
				linked = true
				break
			}
			if r.Reasons[0] == "name-only similarity is never auto-linked" {
				raw, _ := json.Marshal(r.Reasons)
				_, err = tx.Exec(ctx, `INSERT INTO correlation_candidates(organization_id,person_id,identity_account_id,confidence,reasons) VALUES($1,$2,$3,$4,$5) ON CONFLICT(organization_id,person_id,identity_account_id) DO NOTHING`, orgID, p.ID, a.id, r.Confidence, raw)
				if err != nil {
					return 0, err
				}
				candidate = true
			}
		}
		if !linked {
			reason := "Observed account has no linked person"
			if candidate {
				reason = "Observed account has ambiguous name-only correlation candidate"
			}
			tag, err := tx.Exec(ctx, `INSERT INTO identity_findings(organization_id,identity_account_id,connector_id,type,severity,reason) SELECT $1,$2,$3,'ORPHAN_ACCOUNT','ATTENTION',$4 WHERE NOT EXISTS(SELECT 1 FROM identity_findings WHERE organization_id=$1 AND identity_account_id=$2 AND type='ORPHAN_ACCOUNT' AND status='OPEN')`, orgID, a.id, connectorID, reason)
			if err != nil {
				return 0, err
			}
			findings += int(tag.RowsAffected())
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO identity_findings(organization_id,person_id,connector_id,type,severity,reason) SELECT $1,l.person_id,a.connector_id,'DUPLICATE_ACTIVE_ACCOUNT','ATTENTION','Person has multiple active accounts in the same connector' FROM identity_links l JOIN identity_accounts a ON a.id=l.identity_account_id AND a.organization_id=$1 WHERE l.organization_id=$1 AND a.active_status='ACTIVE' GROUP BY l.person_id,a.connector_id HAVING count(*)>1 ON CONFLICT DO NOTHING`, orgID)
	return findings, err
}

func (s *Service) CreateCase(ctx context.Context, orgID, personID, userID string) (string, error) {
	id := uuid.NewString()
	tag, err := s.DB.Pool.Exec(ctx, `INSERT INTO lifecycle_cases(id,organization_id,person_id,requested_by,status) SELECT $1,$2,p.id,$3,'DRAFT' FROM people p WHERE p.organization_id=$2 AND p.id=$4`, id, orgID, userID, personID)
	if err == nil && tag.RowsAffected() != 1 {
		err = pgx.ErrNoRows
	}
	return id, err
}
func (s *Service) PlanCase(ctx context.Context, orgID, caseID, userID string) ([]map[string]any, error) {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM lifecycle_cases WHERE organization_id=$1 AND id=$2 FOR UPDATE`, orgID, caseID).Scan(&status)
	if err != nil {
		return nil, err
	}
	if status != "DRAFT" {
		return nil, errors.New("FORBIDDEN_STATE")
	}
	rows, err := tx.Query(ctx, `SELECT a.id,a.connector_id,a.username,a.active_status,c.name,c.type,c.write_enabled,c.capabilities FROM lifecycle_cases lc JOIN identity_links l ON l.person_id=lc.person_id AND l.organization_id=$1 JOIN identity_accounts a ON a.id=l.identity_account_id AND a.organization_id=$1 JOIN identity_connectors c ON c.id=a.connector_id AND c.organization_id=$1 WHERE lc.organization_id=$1 AND lc.id=$2`, orgID, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type plannedAction struct {
		accountID, connectorID, name, username, state, action string
		write                                                 bool
	}
	planned := []plannedAction{}
	for rows.Next() {
		var accountID, connectorID, username, state, name, typ string
		var write bool
		var caps []byte
		if err = rows.Scan(&accountID, &connectorID, &username, &state, &name, &typ, &write, &caps); err != nil {
			return nil, err
		}
		action := "MANUAL_REVIEW"
		if state == "DISABLED" {
			action = "VERIFY_DISABLED"
		} else if containsConnectorType([]string{"SCIM_2_0", "ENTRA_ID", "OKTA", "GOOGLE_WORKSPACE", "LDAP_DIRECTORY"}, typ) && write && strings.Contains(string(caps), "DISABLE_ACCOUNT") {
			action = "DISABLE_ACCOUNT"
		} else if typ == "GITHUB" && write && strings.Contains(string(caps), "REMOVE_MEMBERSHIP") {
			action = "REMOVE_MEMBERSHIP"
		}
		planned = append(planned, plannedAction{accountID: accountID, connectorID: connectorID, name: name, username: username, state: state, action: action, write: write})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	preview := make([]map[string]any, 0, len(planned))
	for _, item := range planned {
		key := caseID + ":" + item.accountID + ":" + item.action
		_, err = tx.Exec(ctx, `INSERT INTO lifecycle_actions(organization_id,case_id,connector_id,identity_account_id,action_type,status,desired_state,idempotency_key) VALUES($1,$2,$3,$4,$5,'PLANNED',jsonb_build_object('active',false),$6) ON CONFLICT(organization_id,idempotency_key) DO NOTHING`, orgID, caseID, item.connectorID, item.accountID, item.action, key)
		if err != nil {
			return nil, err
		}
		preview = append(preview, map[string]any{"connector": item.name, "account": item.username, "observedState": item.state, "action": item.action, "writeEnabled": item.write})
	}
	if len(preview) == 0 {
		return nil, errors.New("no known identities for person")
	}
	_, err = tx.Exec(ctx, `UPDATE lifecycle_cases SET status='AWAITING_APPROVAL',summary=jsonb_build_object('plannedActions',$1::int) WHERE organization_id=$2 AND id=$3`, len(preview), orgID, caseID)
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO lifecycle_events(organization_id,case_id,type,summary) VALUES($1,$2,'PLAN_GENERATED','Offboarding plan generated and awaits explicit approval')`, orgID, caseID)
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return preview, nil
}

func containsConnectorType(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func (s *Service) ApproveCase(ctx context.Context, orgID, caseID, userID string) error {
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE lifecycle_cases SET status='APPROVED',approved_at=now() WHERE organization_id=$1 AND id=$2 AND status='AWAITING_APPROVAL'`, orgID, caseID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("FORBIDDEN_STATE")
	}
	_, err = tx.Exec(ctx, `UPDATE lifecycle_actions SET status='APPROVED',approved_by=$3 WHERE organization_id=$1 AND case_id=$2 AND status='PLANNED'`, orgID, caseID, userID)
	if err == nil {
		_, err = tx.Exec(ctx, `INSERT INTO lifecycle_events(organization_id,case_id,type,summary,metadata) VALUES($1,$2,'APPROVED','Offboarding plan explicitly approved',jsonb_build_object('approvedBy',$3::text))`, orgID, caseID, userID)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) ExecuteAndVerify(ctx context.Context, orgID, caseID, userID string) (domain.VerificationStatus, error) {
	tag, err := s.DB.Pool.Exec(ctx, `UPDATE lifecycle_cases SET status='RUNNING',started_at=now() WHERE organization_id=$1 AND id=$2 AND status='APPROVED'`, orgID, caseID)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", errors.New("FORBIDDEN_STATE")
	}
	rows, err := s.DB.Pool.Query(ctx, `SELECT a.id,a.action_type,a.status,a.connector_id,a.identity_account_id,ia.external_account_id,c.base_url,c.type FROM lifecycle_actions a LEFT JOIN identity_accounts ia ON ia.id=a.identity_account_id AND ia.organization_id=$1 LEFT JOIN identity_connectors c ON c.id=a.connector_id AND c.organization_id=$1 WHERE a.organization_id=$1 AND a.case_id=$2 ORDER BY a.created_at NULLS LAST,a.id`, orgID, caseID)
	if err != nil {
		return "", err
	}
	type action struct{ id, typ, status, connectorID, accountID, externalID, baseURL, connectorType string }
	var actions []action
	for rows.Next() {
		var a action
		if err = rows.Scan(&a.id, &a.typ, &a.status, &a.connectorID, &a.accountID, &a.externalID, &a.baseURL, &a.connectorType); err != nil {
			rows.Close()
			return "", err
		}
		actions = append(actions, a)
	}
	rows.Close()
	failedSystems := map[string]bool{}
	for _, a := range actions {
		if a.status == "SUCCEEDED" {
			continue
		}
		if _, err = s.DB.Pool.Exec(ctx, `UPDATE lifecycle_actions SET status='RUNNING',started_at=coalesce(started_at,now()),attempt_count=attempt_count+1 WHERE organization_id=$1 AND id=$2 AND status IN ('APPROVED','FAILED')`, orgID, a.id); err != nil {
			return "", err
		}
		outcome := "INCONCLUSIVE"
		summary := "Manual system requires human review"
		if a.typ == "DISABLE_ACCOUNT" || a.typ == "REMOVE_MEMBERSHIP" {
			disabled, e := s.executeRemoteAction(ctx, orgID, a.connectorID, a.connectorType, a.baseURL, a.externalID, a.typ)
			if e == nil && disabled {
				outcome = "SUCCEEDED"
				summary = "Provider was re-read and access was observed disabled or removed"
				if _, err = s.DB.Pool.Exec(ctx, `UPDATE identity_accounts SET active_status='DISABLED',last_seen_at=now(),updated_at=now() WHERE organization_id=$1 AND id=$2`, orgID, a.accountID); err != nil {
					return "", err
				}
			} else if e == nil {
				outcome = "FAILED"
				summary = "Provider accepted the change but reconciliation still observed active access"
			}
			if e != nil {
				outcome = "FAILED"
				summary = "Provider action or post-write read failed"
				failedSystems[a.connectorID] = true
			}
		} else if a.typ == "VERIFY_DISABLED" {
			var state string
			e := s.DB.Pool.QueryRow(ctx, `SELECT active_status FROM identity_accounts WHERE organization_id=$1 AND id=$2`, orgID, a.accountID).Scan(&state)
			if e == nil && state == "DISABLED" {
				outcome = "SUCCEEDED"
				summary = "Read-only identity was observed disabled"
			} else {
				outcome = "INCONCLUSIVE"
				summary = "Read-only identity could not be confirmed disabled"
			}
		}
		if _, err = s.DB.Pool.Exec(ctx, `UPDATE lifecycle_actions SET status=$1,completed_at=now(),summary=jsonb_build_object('message',$2::text),error_code=CASE WHEN $1='FAILED' THEN 'POST_WRITE_VERIFICATION_FAILED' ELSE NULL END WHERE organization_id=$3 AND id=$4`, outcome, summary, orgID, a.id); err != nil {
			return "", err
		}
		state := map[string]any{"outcome": outcome, "summary": summary}
		raw, _ := json.Marshal(state)
		sum := sha256.Sum256(raw)
		if _, err = s.DB.Pool.Exec(ctx, `INSERT INTO identity_evidence(organization_id,connector_id,identity_account_id,lifecycle_case_id,action_id,type,summary,observed_state,source_timestamp,integrity_hash) VALUES($1,$2,$3,$4,$5,'POST_ACTION_OBSERVATION',$6,$7,now(),$8)`, orgID, a.connectorID, a.accountID, caseID, a.id, summary, raw, hex.EncodeToString(sum[:])); err != nil {
			return "", err
		}
	}
	if _, err = s.DB.Pool.Exec(ctx, `UPDATE lifecycle_cases SET status='VERIFYING' WHERE organization_id=$1 AND id=$2`, orgID, caseID); err != nil {
		return "", err
	}
	var personID string
	if err = s.DB.Pool.QueryRow(ctx, `SELECT person_id FROM lifecycle_cases WHERE organization_id=$1 AND id=$2`, orgID, caseID).Scan(&personID); err != nil {
		return "", err
	}
	var managed, disabled, active, unresolved, manual int
	err = s.DB.Pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE a.active_status='DISABLED'),count(*) FILTER(WHERE a.active_status='ACTIVE') FROM identity_links l JOIN identity_accounts a ON a.id=l.identity_account_id AND a.organization_id=$1 WHERE l.organization_id=$1 AND l.person_id=$2`, orgID, personID).Scan(&managed, &disabled, &active)
	if err != nil {
		return "", err
	}
	if err = s.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM correlation_candidates WHERE organization_id=$1 AND person_id=$2 AND status='PENDING'`, orgID, personID).Scan(&unresolved); err != nil {
		return "", err
	}
	if err = s.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM lifecycle_actions WHERE organization_id=$1 AND case_id=$2 AND action_type='MANUAL_REVIEW'`, orgID, caseID).Scan(&manual); err != nil {
		return "", err
	}
	systemsFailed := len(failedSystems)
	result := domain.EvaluateVerification(domain.VerificationInput{Managed: managed, Disabled: disabled, Active: active, Unresolved: unresolved, Manual: manual, SystemsFailed: systemsFailed, RequiredSystemsResponded: systemsFailed == 0})
	finalCase := "COMPLETED"
	if result == domain.Failed {
		finalCase = "FAILED"
	} else if result != domain.Verified {
		finalCase = "PARTIAL"
	}
	_, err = s.DB.Pool.Exec(ctx, `INSERT INTO verification_snapshots(organization_id,case_id,observed_at,connected_systems,systems_succeeded,systems_failed,managed_identities,disabled_identities,active_identities,unresolved_identities,status,summary) SELECT $1,$2,now(),count(DISTINCT connector_id),count(DISTINCT connector_id)-$3,$3,$4,$5,$6,$7,$8,jsonb_build_object('manualSystems',$9::int) FROM lifecycle_actions WHERE organization_id=$1 AND case_id=$2`, orgID, caseID, systemsFailed, managed, disabled, active, unresolved, result, manual)
	if err == nil {
		_, err = s.DB.Pool.Exec(ctx, `UPDATE lifecycle_cases SET status=$3,verification_status=$4,completed_at=now(),summary=jsonb_build_object('managedIdentities',$5::int,'disabledIdentities',$6::int,'activeIdentities',$7::int,'unresolvedIdentities',$8::int,'systemsFailed',$9::int) WHERE organization_id=$1 AND id=$2`, orgID, caseID, finalCase, result, managed, disabled, active, unresolved, systemsFailed)
	}
	if err == nil {
		_, err = s.DB.Pool.Exec(ctx, `INSERT INTO lifecycle_events(organization_id,case_id,type,summary,metadata) VALUES($1,$2,'VERIFICATION_COMPLETED','Verification completed from observed provider state',jsonb_build_object('status',$3::text))`, orgID, caseID, result)
	}
	if err == nil && s.Notifier != nil && result != domain.Verified {
		_ = s.Notifier.Notify(ctx, notifier.Event{OrganizationID: orgID, Type: "OFFBOARDING_" + string(result), Payload: map[string]any{"caseId": caseID, "verificationStatus": result}, OccurredAt: s.Clock.Now()})
	}
	return result, err
}

func (s *Service) executeRemoteAction(ctx context.Context, orgID, connectorID, connectorType, baseURL, externalID, actionType string) (bool, error) {
	switch connectorType {
	case "SCIM_2_0":
		token, err := s.connectorToken(ctx, orgID, connectorID)
		if err != nil {
			return false, err
		}
		client, err := scim.New(baseURL, token, s.AllowHTTP, s.Timeout)
		if err != nil {
			return false, err
		}
		if err = client.DisableUser(ctx, externalID); err != nil {
			return false, err
		}
		observed, err := client.GetUser(ctx, externalID)
		return err == nil && !observed.Active, err
	case "LDAP_DIRECTORY":
		if actionType != "DISABLE_ACCOUNT" {
			return false, errors.New("LDAP membership action requires an entitlement-scoped plan")
		}
		cfg, err := s.ldapConfiguration(ctx, orgID, connectorID)
		if err != nil {
			return false, err
		}
		client, err := ldapconnector.New(cfg)
		if err != nil {
			return false, err
		}
		if err = client.DisableUser(ctx, externalID); err != nil {
			return false, err
		}
		observed, err := client.GetUser(ctx, externalID)
		return err == nil && ldapconnector.IsDisabled(observed), err
	case "ENTRA_ID", "OKTA", "GOOGLE_WORKSPACE", "GITHUB":
		client, err := s.nativeClient(ctx, orgID, connectorID)
		if err != nil {
			return false, err
		}
		if err = client.DisableUser(ctx, externalID); err != nil {
			return false, err
		}
		observed, err := client.GetUser(ctx, externalID)
		return err == nil && !observed.Active, err
	default:
		return false, errors.New("connector does not support controlled remote actions")
	}
}

func (s *Service) GetCase(ctx context.Context, orgID, caseID string) (map[string]any, error) {
	var id, personID, status, verification string
	var summary []byte
	var created time.Time
	err := s.DB.Pool.QueryRow(ctx, `SELECT id,person_id,status,coalesce(verification_status,''),summary,created_at FROM lifecycle_cases WHERE organization_id=$1 AND id=$2`, orgID, caseID).Scan(&id, &personID, &status, &verification, &summary, &created)
	if err != nil {
		return nil, err
	}
	var parsed any
	_ = json.Unmarshal(summary, &parsed)
	rows, err := s.DB.Pool.Query(ctx, `SELECT a.id,a.action_type,a.status,coalesce(c.name,'Manual'),coalesce(i.username,''),a.summary FROM lifecycle_actions a LEFT JOIN identity_connectors c ON c.id=a.connector_id AND c.organization_id=$1 LEFT JOIN identity_accounts i ON i.id=a.identity_account_id AND i.organization_id=$1 WHERE a.organization_id=$1 AND a.case_id=$2 ORDER BY a.id`, orgID, caseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	acts := []map[string]any{}
	for rows.Next() {
		var aid, typ, astat, connector, username string
		var raw []byte
		if err = rows.Scan(&aid, &typ, &astat, &connector, &username, &raw); err != nil {
			return nil, err
		}
		var sm any
		_ = json.Unmarshal(raw, &sm)
		acts = append(acts, map[string]any{"id": aid, "type": typ, "status": astat, "connector": connector, "username": username, "summary": sm})
	}
	return map[string]any{"id": id, "personId": personID, "status": status, "verificationStatus": verification, "summary": parsed, "createdAt": created, "actions": acts}, rows.Err()
}
func (s *Service) DecideReview(ctx context.Context, orgID, itemID, userID, decision, comment string) error {
	switch decision {
	case "KEEP", "REVOKE", "NEEDS_INFORMATION", "NOT_APPLICABLE":
	default:
		return errors.New("invalid review decision")
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var campaignID, assignedReviewer string
	err = tx.QueryRow(ctx, `SELECT i.campaign_id,c.reviewer_user_id FROM access_review_items i JOIN access_review_campaigns c ON c.id=i.campaign_id AND c.organization_id=$1 WHERE i.organization_id=$1 AND i.id=$2 FOR UPDATE OF i`, orgID, itemID).Scan(&campaignID, &assignedReviewer)
	if err != nil {
		return err
	}
	if assignedReviewer != userID {
		return errors.New("review decision requires the assigned reviewer")
	}
	_, err = tx.Exec(ctx, `INSERT INTO access_review_decisions(organization_id,item_id,reviewer_user_id,decision,comment) VALUES($1,$2,$3,$4,$5)`, orgID, itemID, userID, decision, comment)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE access_review_items SET status='DECIDED' WHERE organization_id=$1 AND id=$2`, orgID, itemID)
	}
	if err != nil {
		return err
	}
	if decision == "REVOKE" {
		_, err = tx.Exec(ctx, `INSERT INTO outbox_events(organization_id,type,payload) VALUES($1,'ACCESS_REVIEW_REVOCATION_PROPOSED',jsonb_build_object('itemId',$2::text,'campaignId',$3::text,'requiresApproval',true))`, orgID, itemID, campaignID)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,metadata,request_id) VALUES($1,$2,'access_review.decision','access_review_item',$3,jsonb_build_object('decision',$4::text),'access-review-decision')`, orgID, userID, itemID, decision)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE access_review_campaigns c SET status='COMPLETED',completed_at=now() WHERE c.organization_id=$1 AND c.id=$2 AND NOT EXISTS(SELECT 1 FROM access_review_items i WHERE i.organization_id=$1 AND i.campaign_id=c.id AND i.status<>'DECIDED')`, orgID, campaignID)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Service) String() string { return fmt.Sprintf("assurance service timeout=%s", s.Timeout) }
