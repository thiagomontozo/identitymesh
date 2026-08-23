package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	authn "github.com/thiagomontozo/identitymesh/backend/internal/auth"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/scim"
	"github.com/thiagomontozo/identitymesh/backend/internal/csvsource"
	"github.com/thiagomontozo/identitymesh/backend/internal/reports"
)

func queryMaps(ctx context.Context, db interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, sql string, keys []string, args ...any) ([]map[string]any, error) {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		values, e := rows.Values()
		if e != nil {
			return nil, e
		}
		item := map[string]any{}
		for i, key := range keys {
			item[key] = normalizeDBValue(values[i])
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Server) personRelated(ctx context.Context, orgID, personID string) (map[string]any, error) {
	access, err := queryMaps(ctx, s.DB.Pool, `SELECT g.id,e.name,e.type,e.privileged,g.active,g.source,g.last_seen_at,a.username,c.name FROM identity_links l JOIN identity_accounts a ON a.id=l.identity_account_id AND a.organization_id=$1 JOIN access_grants g ON g.identity_account_id=a.id AND g.organization_id=$1 JOIN entitlements e ON e.id=g.entitlement_id AND e.organization_id=$1 JOIN identity_connectors c ON c.id=a.connector_id AND c.organization_id=$1 WHERE l.organization_id=$1 AND l.person_id=$2 ORDER BY e.name`, []string{"id", "entitlementName", "entitlementType", "privileged", "active", "source", "lastSeenAt", "username", "connectorName"}, orgID, personID)
	if err != nil {
		return nil, err
	}
	findings, err := queryMaps(ctx, s.DB.Pool, `SELECT DISTINCT f.id,f.type,f.severity,f.status,f.reason,f.last_observed_at FROM identity_findings f LEFT JOIN identity_links l ON l.organization_id=$1 AND l.identity_account_id=f.identity_account_id WHERE f.organization_id=$1 AND (f.person_id=$2 OR l.person_id=$2) ORDER BY f.last_observed_at DESC`, []string{"id", "type", "severity", "status", "reason", "lastObservedAt"}, orgID, personID)
	if err != nil {
		return nil, err
	}
	lifecycle, err := queryMaps(ctx, s.DB.Pool, `SELECT id,type,status,coalesce(verification_status,''),created_at,completed_at FROM lifecycle_cases WHERE organization_id=$1 AND person_id=$2 ORDER BY created_at DESC`, []string{"id", "type", "status", "verificationStatus", "createdAt", "completedAt"}, orgID, personID)
	if err != nil {
		return nil, err
	}
	evidence, err := queryMaps(ctx, s.DB.Pool, `SELECT DISTINCT e.id,e.type,e.summary,e.observed_state,e.created_at,e.integrity_hash FROM identity_evidence e LEFT JOIN lifecycle_cases lc ON lc.organization_id=$1 AND lc.id=e.lifecycle_case_id LEFT JOIN identity_links l ON l.organization_id=$1 AND l.identity_account_id=e.identity_account_id WHERE e.organization_id=$1 AND (e.person_id=$2 OR lc.person_id=$2 OR l.person_id=$2) ORDER BY e.created_at DESC LIMIT 100`, []string{"id", "type", "summary", "observedState", "createdAt", "integrityHash"}, orgID, personID)
	if err != nil {
		return nil, err
	}
	timeline, err := queryMaps(ctx, s.DB.Pool, `SELECT le.type,le.summary,le.created_at FROM lifecycle_events le JOIN lifecycle_cases lc ON lc.id=le.case_id AND lc.organization_id=$1 WHERE le.organization_id=$1 AND lc.person_id=$2 ORDER BY le.created_at DESC LIMIT 100`, []string{"type", "summary", "createdAt"}, orgID, personID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"access": access, "findings": findings, "lifecycle": lifecycle, "evidence": evidence, "timeline": timeline}, nil
}

func stringConfig(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}

func validateLDAPConfiguration(values map[string]any) error {
	if values == nil {
		return errors.New("LDAP search configuration is required")
	}
	for _, key := range []string{"bindDN", "searchBase", "userFilter", "groupFilter"} {
		if stringConfig(values, key) == "" {
			return fmt.Errorf("LDAP %s is required", key)
		}
	}
	for _, key := range []string{"userFilter", "groupFilter"} {
		filter := stringConfig(values, key)
		if !strings.HasPrefix(filter, "(") || !strings.HasSuffix(filter, ")") || strings.ContainsAny(filter, "\x00\r\n") {
			return fmt.Errorf("LDAP %s is invalid", key)
		}
	}
	if page, ok := values["pageSize"].(float64); ok && (page < 1 || page > 5000) {
		return errors.New("LDAP pageSize must be between 1 and 5000")
	}
	return nil
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT id,created_at,last_seen_at,expires_at,(id=$3) AS current FROM sessions WHERE organization_id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now() ORDER BY last_seen_at DESC`, session.OrganizationID, session.UserID, session.ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "createdAt", "lastSeenAt", "expiresAt", "current"})
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/auth/sessions/")
	session := getSession(r)
	tag, err := s.DB.Pool.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE organization_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL`, session.OrganizationID, session.UserID, id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "SESSION_NOT_FOUND", "The active session was not found.", requestID(r))
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "auth.session_revoked", "session", id, map[string]any{"current": id == session.ID}, requestID(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) csvApply(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.MaxCSVBytes)
	if err := r.ParseMultipartForm(s.MaxCSVBytes); err != nil {
		writeError(w, 413, "CSV_TOO_LARGE", "The CSV exceeds the configured size limit.", requestID(r))
		return
	}
	if r.FormValue("confirmed") != "true" {
		writeError(w, 409, "CSV_CONFIRMATION_REQUIRED", "Preview and explicit confirmation are required before applying an import.", requestID(r))
		return
	}
	sourceID := r.FormValue("sourceConnectorId")
	if _, err := uuid.Parse(sourceID); err != nil {
		writeError(w, 400, "INVALID_SOURCE_CONNECTOR", "A valid authoritative source connector is required.", requestID(r))
		return
	}
	session := getSession(r)
	var valid bool
	if err := s.DB.Pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM identity_connectors WHERE organization_id=$1 AND id=$2 AND type='CSV_AUTHORITATIVE_SOURCE' AND enabled)`, session.OrganizationID, sourceID).Scan(&valid); err != nil || !valid {
		writeError(w, 404, "SOURCE_CONNECTOR_NOT_FOUND", "The authoritative source connector was not found.", requestID(r))
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "CSV_REQUIRED", "A CSV file is required.", requestID(r))
		return
	}
	defer file.Close()
	mapping := csvsource.Mapping{EmployeeID: "employee_id", DisplayName: "display_name", Email: "email", Department: "department", ManagerID: "manager_id", Status: "status"}
	preview, err := csvsource.ParsePreview(file, mapping, s.MaxCSVBytes, 10000)
	if err != nil || len(preview.Errors) > 0 || preview.Truncated {
		writeError(w, 400, "CSV_VALIDATION_FAILED", "The CSV must pass preview validation without truncation before it can be applied.", requestID(r))
		return
	}
	count, err := s.Assurance.ImportPeople(r.Context(), session.OrganizationID, sourceID, preview.Rows)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "person.imported", "connector", sourceID, map[string]any{"rows": count}, requestID(r))
	writeJSON(w, 200, map[string]any{"applied": count, "sourceConnectorId": sourceID})
}

func (s *Server) identities(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	q := r.URL.Query()
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT a.id,a.external_account_id,a.username,coalesce(a.display_name,''),coalesce(a.primary_email,''),a.active_status,a.account_type,a.privileged,a.first_seen_at,a.last_seen_at,c.id,c.name,c.type,p.id,p.display_name
		FROM identity_accounts a JOIN identity_connectors c ON c.id=a.connector_id AND c.organization_id=$1
		LEFT JOIN identity_links l ON l.organization_id=$1 AND l.identity_account_id=a.id LEFT JOIN people p ON p.organization_id=$1 AND p.id=l.person_id
		WHERE a.organization_id=$1 AND ($2='' OR a.connector_id::text=$2) AND ($3='' OR a.active_status=$3) AND ($4='' OR ($4='linked' AND l.id IS NOT NULL) OR ($4='unlinked' AND l.id IS NULL)) AND ($5='' OR a.username ILIKE '%'||$5||'%' OR a.external_account_id ILIKE '%'||$5||'%' OR a.primary_email ILIKE '%'||$5||'%')
		ORDER BY a.last_seen_at DESC LIMIT $6 OFFSET $7`, getSession(r).OrganizationID, q.Get("connector"), q.Get("state"), q.Get("link"), q.Get("q"), limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "externalAccountId", "username", "displayName", "primaryEmail", "activeStatus", "accountType", "privileged", "firstSeenAt", "lastSeenAt", "connectorId", "connectorName", "connectorType", "personId", "personName"})
}

func (s *Server) correlationCandidates(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "PENDING"
	}
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT cc.id,cc.confidence,cc.reasons,cc.status,cc.created_at,cc.reviewed_at,p.id,p.display_name,a.id,a.username,a.primary_email,c.name
		FROM correlation_candidates cc JOIN people p ON p.id=cc.person_id AND p.organization_id=$1 JOIN identity_accounts a ON a.id=cc.identity_account_id AND a.organization_id=$1 JOIN identity_connectors c ON c.id=a.connector_id AND c.organization_id=$1
		WHERE cc.organization_id=$1 AND ($2='' OR cc.status=$2) ORDER BY cc.created_at DESC LIMIT $3 OFFSET $4`, getSession(r).OrganizationID, status, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "confidence", "reasons", "status", "createdAt", "reviewedAt", "personId", "personName", "identityAccountId", "username", "primaryEmail", "connectorName"})
}

func candidateID(path, action string) string {
	return strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/correlation-candidates/"), "/"+action)
}

func (s *Server) acceptCandidate(w http.ResponseWriter, r *http.Request) {
	s.acceptOrRejectCandidate(w, r, candidateID(r.URL.Path, "accept"), true)
}
func (s *Server) rejectCandidate(w http.ResponseWriter, r *http.Request) {
	s.acceptOrRejectCandidate(w, r, candidateID(r.URL.Path, "reject"), false)
}
func (s *Server) acceptOrRejectCandidate(w http.ResponseWriter, r *http.Request, id string, accept bool) {
	if _, err := uuid.Parse(id); err != nil {
		writeError(w, 400, "INVALID_ID", "A valid candidate UUID is required.", requestID(r))
		return
	}
	session := getSession(r)
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var personID, accountID, confidence, status string
	err = tx.QueryRow(r.Context(), `SELECT person_id,identity_account_id,confidence,status FROM correlation_candidates WHERE organization_id=$1 AND id=$2 FOR UPDATE`, session.OrganizationID, id).Scan(&personID, &accountID, &confidence, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "CANDIDATE_NOT_FOUND", "The correlation candidate was not found.", requestID(r))
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if status != "PENDING" {
		writeError(w, 409, "CANDIDATE_ALREADY_REVIEWED", "The correlation candidate has already been reviewed.", requestID(r))
		return
	}
	decision, event := "REJECTED", "correlation.rejected"
	if accept {
		decision, event = "ACCEPTED", "correlation.accepted"
		_, err = tx.Exec(r.Context(), `INSERT INTO identity_links(organization_id,person_id,identity_account_id,link_type,confidence,reason,created_by) VALUES($1,$2,$3,'MANUAL',$4,'Accepted correlation candidate after human review',$5)`, session.OrganizationID, personID, accountID, confidence, session.UserID)
		if err != nil {
			writeError(w, 409, "IDENTITY_ALREADY_LINKED", "The identity is already linked or could not be linked safely.", requestID(r))
			return
		}
		_, err = tx.Exec(r.Context(), `UPDATE identity_findings SET status='RESOLVED',resolved_at=now(),last_observed_at=now() WHERE organization_id=$1 AND identity_account_id=$2 AND type IN ('ORPHAN_ACCOUNT','UNRESOLVED_IDENTITY') AND status='OPEN'`, session.OrganizationID, accountID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE correlation_candidates SET status=$1,reviewed_at=now(),reviewed_by=$2 WHERE organization_id=$3 AND id=$4`, decision, session.UserID, session.OrganizationID, id)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,metadata,request_id) VALUES($1,$2,$3,'correlation_candidate',$4,jsonb_build_object('personId',$5::text,'identityAccountId',$6::text),$7)`, session.OrganizationID, session.UserID, event, id, personID, accountID, requestID(r))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"id": id, "status": decision})
}

func (s *Server) applications(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT a.id,a.name,coalesce(a.description,''),coalesce(a.owner_name,''),coalesce(a.owner_email,''),a.criticality,a.enabled,a.created_at,c.id,c.name,
		(SELECT count(*) FROM identity_accounts ia WHERE ia.organization_id=$1 AND ia.connector_id=a.connector_id),
		(SELECT count(*) FROM identity_accounts ia WHERE ia.organization_id=$1 AND ia.connector_id=a.connector_id AND ia.active_status='ACTIVE')
		FROM applications a LEFT JOIN identity_connectors c ON c.id=a.connector_id AND c.organization_id=$1 WHERE a.organization_id=$1 ORDER BY a.name LIMIT $2 OFFSET $3`, getSession(r).OrganizationID, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "name", "description", "ownerName", "ownerEmail", "criticality", "enabled", "createdAt", "connectorId", "connectorName", "accounts", "activeAccounts"})
}

func (s *Server) createApplication(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Description, OwnerName, OwnerEmail, Criticality, ConnectorID string }
	if !decodeJSON(w, r, &in, 32<<10) {
		return
	}
	in.Name, in.Criticality = strings.TrimSpace(in.Name), strings.ToUpper(in.Criticality)
	if in.Name == "" || !contains([]string{"LOW", "MEDIUM", "HIGH"}, in.Criticality) {
		writeError(w, 400, "INVALID_APPLICATION", "Name and LOW, MEDIUM or HIGH criticality are required.", requestID(r))
		return
	}
	if in.OwnerEmail != "" {
		if _, err := mail.ParseAddress(in.OwnerEmail); err != nil {
			writeError(w, 400, "INVALID_EMAIL", "Owner email is invalid.", requestID(r))
			return
		}
	}
	session := getSession(r)
	id := uuid.NewString()
	tag, err := s.DB.Pool.Exec(r.Context(), `INSERT INTO applications(id,organization_id,name,description,owner_name,owner_email,criticality,connector_id) SELECT $1,$2,$3,nullif($4,''),nullif($5,''),nullif($6,''),$7,id FROM identity_connectors WHERE organization_id=$2 AND id=$8`, id, session.OrganizationID, in.Name, in.Description, in.OwnerName, in.OwnerEmail, in.Criticality, in.ConnectorID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 400, "INVALID_CONNECTOR", "The application connector does not exist in this organization.", requestID(r))
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "application.created", "application", id, map[string]any{"name": in.Name}, requestID(r))
	writeJSON(w, 201, map[string]string{"id": id})
}

func (s *Server) entitlements(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	q := r.URL.Query()
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT e.id,e.external_id,e.name,e.type,coalesce(e.description,''),e.privileged,e.first_seen_at,e.last_seen_at,c.id,c.name,(SELECT count(*) FROM access_grants g WHERE g.organization_id=$1 AND g.entitlement_id=e.id AND g.active)
		FROM entitlements e JOIN identity_connectors c ON c.id=e.connector_id AND c.organization_id=$1 WHERE e.organization_id=$1 AND ($2='' OR e.connector_id::text=$2) AND ($3='' OR e.name ILIKE '%'||$3||'%') ORDER BY e.name LIMIT $4 OFFSET $5`, getSession(r).OrganizationID, q.Get("connector"), q.Get("q"), limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "externalId", "name", "type", "description", "privileged", "firstSeenAt", "lastSeenAt", "connectorId", "connectorName", "activeGrants"})
}

func (s *Server) accessGrants(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT g.id,g.source,g.first_seen_at,g.last_seen_at,g.active,a.id,a.username,a.active_status,e.id,e.name,e.type,e.privileged,p.id,p.display_name
		FROM access_grants g JOIN identity_accounts a ON a.id=g.identity_account_id AND a.organization_id=$1 JOIN entitlements e ON e.id=g.entitlement_id AND e.organization_id=$1 LEFT JOIN identity_links l ON l.identity_account_id=a.id AND l.organization_id=$1 LEFT JOIN people p ON p.id=l.person_id AND p.organization_id=$1 WHERE g.organization_id=$1 ORDER BY g.last_seen_at DESC LIMIT $2 OFFSET $3`, getSession(r).OrganizationID, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "source", "firstSeenAt", "lastSeenAt", "active", "identityAccountId", "username", "accountState", "entitlementId", "entitlementName", "entitlementType", "privileged", "personId", "personName"})
}

func (s *Server) reconciliationRuns(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	q := r.URL.Query()
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT rr.id,rr.trigger_type,rr.status,rr.started_at,rr.completed_at,rr.accounts_discovered,rr.accounts_changed,rr.groups_discovered,rr.memberships_changed,rr.findings_created,rr.summary,c.id,c.name
		FROM reconciliation_runs rr JOIN identity_connectors c ON c.id=rr.connector_id AND c.organization_id=$1 WHERE rr.organization_id=$1 AND ($2='' OR rr.connector_id::text=$2) AND ($3='' OR rr.status=$3) ORDER BY rr.started_at DESC LIMIT $4 OFFSET $5`, getSession(r).OrganizationID, q.Get("connector"), q.Get("status"), limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "triggerType", "status", "startedAt", "completedAt", "accountsDiscovered", "accountsChanged", "groupsDiscovered", "membershipsChanged", "findingsCreated", "summary", "connectorId", "connectorName"})
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	q := r.URL.Query()
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT f.id,f.type,f.severity,f.status,f.reason,f.first_observed_at,f.last_observed_at,f.resolved_at,p.id,p.display_name,a.id,a.username,c.id,c.name
		FROM identity_findings f LEFT JOIN people p ON p.id=f.person_id AND p.organization_id=$1 LEFT JOIN identity_accounts a ON a.id=f.identity_account_id AND a.organization_id=$1 LEFT JOIN identity_connectors c ON c.id=f.connector_id AND c.organization_id=$1
		WHERE f.organization_id=$1 AND ($2='' OR f.status=$2) AND ($3='' OR f.severity=$3) ORDER BY f.last_observed_at DESC LIMIT $4 OFFSET $5`, getSession(r).OrganizationID, q.Get("status"), q.Get("severity"), limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "type", "severity", "status", "reason", "firstObservedAt", "lastObservedAt", "resolvedAt", "personId", "personName", "identityAccountId", "username", "connectorId", "connectorName"})
}

func (s *Server) updateFinding(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/findings/")
	var in struct{ Status string }
	if !decodeJSON(w, r, &in, 4<<10) {
		return
	}
	in.Status = strings.ToUpper(in.Status)
	if !contains([]string{"OPEN", "ACKNOWLEDGED", "RESOLVED", "ACCEPTED", "INCONCLUSIVE"}, in.Status) {
		writeError(w, 400, "INVALID_FINDING_STATUS", "The finding status is invalid.", requestID(r))
		return
	}
	session := getSession(r)
	tag, err := s.DB.Pool.Exec(r.Context(), `UPDATE identity_findings SET status=$1,resolved_at=CASE WHEN $1='RESOLVED' THEN now() ELSE resolved_at END WHERE organization_id=$2 AND id=$3`, in.Status, session.OrganizationID, id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 404, "FINDING_NOT_FOUND", "The finding was not found.", requestID(r))
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "finding.updated", "identity_finding", id, map[string]any{"status": in.Status}, requestID(r))
	writeJSON(w, 200, map[string]string{"id": id, "status": in.Status})
}

func (s *Server) lifecycleCases(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	q := r.URL.Query()
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT lc.id,lc.type,lc.status,coalesce(lc.verification_status,''),lc.effective_at,lc.created_at,lc.approved_at,lc.started_at,lc.completed_at,lc.summary,p.id,p.display_name,p.lifecycle_status
		FROM lifecycle_cases lc JOIN people p ON p.id=lc.person_id AND p.organization_id=$1 WHERE lc.organization_id=$1 AND ($2='' OR lc.status=$2) AND ($3='' OR lc.verification_status=$3) ORDER BY lc.created_at DESC LIMIT $4 OFFSET $5`, getSession(r).OrganizationID, q.Get("status"), q.Get("verification"), limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "type", "status", "verificationStatus", "effectiveAt", "createdAt", "approvedAt", "startedAt", "completedAt", "summary", "personId", "personName", "personLifecycleStatus"})
}

func (s *Server) cancelCase(w http.ResponseWriter, r *http.Request) {
	id := caseIDFromAction(r.URL.Path, "cancel")
	session := getSession(r)
	tag, err := s.DB.Pool.Exec(r.Context(), `UPDATE lifecycle_cases SET status='CANCELLED',completed_at=now() WHERE organization_id=$1 AND id=$2 AND status IN ('DRAFT','PLANNED','AWAITING_APPROVAL','APPROVED')`, session.OrganizationID, id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, 409, "FORBIDDEN_STATE", "Only a case that has not started can be cancelled.", requestID(r))
		return
	}
	_, _ = s.DB.Pool.Exec(r.Context(), `UPDATE lifecycle_actions SET status='SKIPPED',completed_at=now(),summary='{"message":"Case cancelled before execution"}' WHERE organization_id=$1 AND case_id=$2 AND status IN ('PLANNED','APPROVED','QUEUED')`, session.OrganizationID, id)
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "offboarding.cancelled", "lifecycle_case", id, map[string]any{}, requestID(r))
	writeJSON(w, 200, map[string]string{"id": id, "status": "CANCELLED"})
}

func (s *Server) accessReviews(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	status := r.URL.Query().Get("status")
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT c.id,c.name,coalesce(c.description,''),c.scope_type,c.scope_configuration,c.status,c.starts_at,c.due_at,c.completed_at,c.created_at,u.display_name,
		(SELECT count(*) FROM access_review_items i WHERE i.organization_id=$1 AND i.campaign_id=c.id),(SELECT count(*) FROM access_review_items i WHERE i.organization_id=$1 AND i.campaign_id=c.id AND i.status='DECIDED')
		FROM access_review_campaigns c JOIN users u ON u.id=c.reviewer_user_id AND u.organization_id=$1 WHERE c.organization_id=$1 AND ($2='' OR c.status=$2) ORDER BY c.created_at DESC LIMIT $3 OFFSET $4`, getSession(r).OrganizationID, status, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "name", "description", "scopeType", "scopeConfiguration", "status", "startsAt", "dueAt", "completedAt", "createdAt", "reviewerName", "items", "decidedItems"})
}

func (s *Server) createAccessReview(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Description, ScopeType, ReviewerUserID, DueAt string }
	if !decodeJSON(w, r, &in, 32<<10) {
		return
	}
	if strings.TrimSpace(in.Name) == "" || in.ScopeType != "ALL_ACTIVE_GRANTS" {
		writeError(w, 400, "INVALID_REVIEW", "A name and ALL_ACTIVE_GRANTS scope are required.", requestID(r))
		return
	}
	due, err := time.Parse(time.RFC3339, in.DueAt)
	if err != nil || !due.After(time.Now().UTC()) {
		writeError(w, 400, "INVALID_DUE_AT", "A future RFC3339 due date is required.", requestID(r))
		return
	}
	session := getSession(r)
	id := uuid.NewString()
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	var reviewerExists bool
	if err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE organization_id=$1 AND id=$2 AND NOT disabled)`, session.OrganizationID, in.ReviewerUserID).Scan(&reviewerExists); err != nil || !reviewerExists {
		writeError(w, 400, "INVALID_REVIEWER", "The reviewer does not exist in this organization.", requestID(r))
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO access_review_campaigns(id,organization_id,name,description,scope_type,reviewer_user_id,status,starts_at,due_at,created_by) VALUES($1,$2,$3,nullif($4,''),$5,$6,'ACTIVE',now(),$7,$8)`, id, session.OrganizationID, in.Name, in.Description, in.ScopeType, in.ReviewerUserID, due, session.UserID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO access_review_items(organization_id,campaign_id,person_id,identity_account_id,entitlement_id) SELECT $1,$2,l.person_id,g.identity_account_id,g.entitlement_id FROM access_grants g LEFT JOIN identity_links l ON l.organization_id=$1 AND l.identity_account_id=g.identity_account_id WHERE g.organization_id=$1 AND g.active`, session.OrganizationID, id)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,metadata,request_id) VALUES($1,$2,'access_review.created','access_review_campaign',$3,jsonb_build_object('scope',$4::text),$5)`, session.OrganizationID, session.UserID, id, in.ScopeType, requestID(r))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 201, map[string]string{"id": id, "status": "ACTIVE"})
}

func (s *Server) accessReviewDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/access-reviews/")
	session := getSession(r)
	var campaign map[string]any
	var name, description, scope, status, reviewer string
	var due time.Time
	err := s.DB.Pool.QueryRow(r.Context(), `SELECT c.name,coalesce(c.description,''),c.scope_type,c.status,c.due_at,u.display_name FROM access_review_campaigns c JOIN users u ON u.id=c.reviewer_user_id AND u.organization_id=$1 WHERE c.organization_id=$1 AND c.id=$2`, session.OrganizationID, id).Scan(&name, &description, &scope, &status, &due, &reviewer)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "REVIEW_NOT_FOUND", "The access review was not found.", requestID(r))
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	campaign = map[string]any{"id": id, "name": name, "description": description, "scopeType": scope, "status": status, "dueAt": due, "reviewerName": reviewer}
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT i.id,i.status,i.observed_at,p.display_name,a.username,e.name,e.privileged,d.decision,d.comment,d.created_at FROM access_review_items i LEFT JOIN people p ON p.id=i.person_id AND p.organization_id=$1 LEFT JOIN identity_accounts a ON a.id=i.identity_account_id AND a.organization_id=$1 LEFT JOIN entitlements e ON e.id=i.entitlement_id AND e.organization_id=$1 LEFT JOIN access_review_decisions d ON d.item_id=i.id AND d.organization_id=$1 WHERE i.organization_id=$1 AND i.campaign_id=$2 ORDER BY e.name,p.display_name`, session.OrganizationID, id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		values, e := rows.Values()
		if e != nil {
			s.internal(w, r, e)
			return
		}
		keys := []string{"id", "status", "observedAt", "personName", "username", "entitlementName", "privileged", "decision", "comment", "decidedAt"}
		item := map[string]any{}
		for i, k := range keys {
			item[k] = values[i]
		}
		items = append(items, item)
	}
	campaign["items"] = items
	writeJSON(w, 200, campaign)
}

func connectorPathID(path, suffix string) string {
	value := strings.TrimPrefix(path, "/api/v1/connectors/")
	if suffix != "" {
		value = strings.TrimSuffix(value, "/"+suffix)
	}
	return value
}

func (s *Server) connectorDetail(w http.ResponseWriter, r *http.Request) {
	id := connectorPathID(r.URL.Path, "")
	session := getSession(r)
	var name, typ, baseURL, environment, syncInterval, lastStatus string
	var enabled, readEnabled, writeEnabled, credentialConfigured bool
	var caps, configuration []byte
	var lastSync *time.Time
	err := s.DB.Pool.QueryRow(r.Context(), `SELECT c.name,c.type,coalesce(c.base_url,''),c.environment,c.enabled,c.read_enabled,c.write_enabled,c.capabilities,c.configuration,c.sync_interval,c.last_sync_status,c.last_sync_at,EXISTS(SELECT 1 FROM connector_credentials cc WHERE cc.organization_id=$1 AND cc.connector_id=c.id) FROM identity_connectors c WHERE c.organization_id=$1 AND c.id=$2`, session.OrganizationID, id).Scan(&name, &typ, &baseURL, &environment, &enabled, &readEnabled, &writeEnabled, &caps, &configuration, &syncInterval, &lastStatus, &lastSync, &credentialConfigured)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "CONNECTOR_NOT_FOUND", "The connector was not found.", requestID(r))
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	var capabilities, config any
	_ = json.Unmarshal(caps, &capabilities)
	_ = json.Unmarshal(configuration, &config)
	writeJSON(w, 200, map[string]any{"id": id, "name": name, "type": typ, "baseURL": baseURL, "environment": environment, "enabled": enabled, "readEnabled": readEnabled, "writeEnabled": writeEnabled, "capabilities": capabilities, "configuration": config, "syncInterval": syncInterval, "lastSyncStatus": lastStatus, "lastSyncAt": lastSync, "credential": "Configured", "credentialConfigured": credentialConfigured})
}

func (s *Server) connectorSyncs(w http.ResponseWriter, r *http.Request) {
	id := connectorPathID(r.URL.Path, "syncs")
	limit, offset := pagination(r)
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT id,trigger_type,status,request_id,started_at,completed_at,accounts_discovered,groups_discovered,error_code,summary FROM connector_syncs WHERE organization_id=$1 AND connector_id=$2 ORDER BY started_at DESC LIMIT $3 OFFSET $4`, getSession(r).OrganizationID, id, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "triggerType", "status", "requestId", "startedAt", "completedAt", "accountsDiscovered", "groupsDiscovered", "errorCode", "summary"})
}

func (s *Server) updateConnector(w http.ResponseWriter, r *http.Request) {
	id := connectorPathID(r.URL.Path, "")
	var in struct {
		Name, BaseURL, Environment, Credential, SyncInterval string
		Enabled, ReadEnabled, WriteEnabled                   *bool
		Capabilities                                         []string
		Configuration                                        map[string]any
	}
	if !decodeJSON(w, r, &in, 64<<10) {
		return
	}
	session := getSession(r)
	var typ string
	var existingCapabilities []byte
	if err := s.DB.Pool.QueryRow(r.Context(), `SELECT type,capabilities FROM identity_connectors WHERE organization_id=$1 AND id=$2`, session.OrganizationID, id).Scan(&typ, &existingCapabilities); errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "CONNECTOR_NOT_FOUND", "The connector was not found.", requestID(r))
		return
	} else if err != nil {
		s.internal(w, r, err)
		return
	}
	if in.BaseURL != "" && typ == "SCIM_2_0" {
		if _, err := scim.New(in.BaseURL, "", s.Assurance.AllowHTTP, s.Assurance.Timeout); err != nil {
			writeError(w, 400, "INVALID_CONNECTOR_URL", err.Error(), requestID(r))
			return
		}
	}
	if in.BaseURL != "" && typ == "LDAP_DIRECTORY" {
		u, err := url.Parse(in.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			writeError(w, 400, "INVALID_CONNECTOR_URL", "LDAP base URL must use ldap or ldaps without embedded credentials, query or fragment.", requestID(r))
			return
		}
	}
	if typ == "LDAP_DIRECTORY" && in.Configuration != nil {
		if err := validateLDAPConfiguration(in.Configuration); err != nil {
			writeError(w, 400, "INVALID_LDAP_CONFIGURATION", err.Error(), requestID(r))
			return
		}
	}
	if in.WriteEnabled != nil && *in.WriteEnabled && typ != "SCIM_2_0" {
		writeError(w, 400, "WRITE_NOT_SUPPORTED", "LDAP and CSV connectors cannot be write-enabled.", requestID(r))
		return
	}
	if in.SyncInterval != "" && !contains([]string{"MANUAL", "HOURLY", "DAILY"}, in.SyncInterval) {
		writeError(w, 400, "INVALID_SYNC_INTERVAL", "Sync interval must be MANUAL, HOURLY or DAILY.", requestID(r))
		return
	}
	effectiveCapabilities := []string{}
	_ = json.Unmarshal(existingCapabilities, &effectiveCapabilities)
	var caps any = nil
	if in.Capabilities != nil {
		allowed := []string{"DISCOVER_USERS", "DISCOVER_GROUPS", "DISCOVER_MEMBERSHIPS", "DISCOVER_ENTITLEMENTS", "DISABLE_ACCOUNT", "ENABLE_ACCOUNT", "REMOVE_MEMBERSHIP", "ADD_MEMBERSHIP"}
		seen := map[string]bool{}
		for _, capability := range in.Capabilities {
			if !contains(allowed, capability) || seen[capability] {
				writeError(w, 400, "INVALID_CONNECTOR_CAPABILITY", "Connector capabilities must be known and unique.", requestID(r))
				return
			}
			seen[capability] = true
		}
		raw, _ := json.Marshal(in.Capabilities)
		caps = raw
		effectiveCapabilities = in.Capabilities
	}
	if in.WriteEnabled != nil && *in.WriteEnabled && !contains(effectiveCapabilities, "DISABLE_ACCOUNT") {
		writeError(w, 400, "WRITE_CAPABILITY_REQUIRED", "Write enablement requires DISABLE_ACCOUNT capability.", requestID(r))
		return
	}
	var cfg any = nil
	if in.Configuration != nil {
		raw, _ := json.Marshal(in.Configuration)
		cfg = raw
	}
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `UPDATE identity_connectors SET name=coalesce(nullif($1,''),name),base_url=coalesce(nullif($2,''),base_url),environment=coalesce(nullif($3,''),environment),enabled=coalesce($4,enabled),read_enabled=coalesce($5,read_enabled),write_enabled=coalesce($6,write_enabled),capabilities=coalesce($7,capabilities),configuration=coalesce($8,configuration),sync_interval=coalesce(nullif($9,''),sync_interval),updated_at=now() WHERE organization_id=$10 AND id=$11`, in.Name, in.BaseURL, in.Environment, in.Enabled, in.ReadEnabled, in.WriteEnabled, caps, cfg, in.SyncInterval, session.OrganizationID, id)
	if err == nil && in.Credential != "" {
		cipher, e := s.Secrets.Encrypt([]byte(in.Credential))
		err = e
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO connector_credentials(organization_id,connector_id,ciphertext) VALUES($1,$2,$3) ON CONFLICT(connector_id) DO UPDATE SET ciphertext=EXCLUDED.ciphertext,key_version=connector_credentials.key_version+1,updated_at=now()`, session.OrganizationID, id, cipher)
		}
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "connector.updated", "connector", id, map[string]any{"credentialChanged": in.Credential != ""}, requestID(r))
	writeJSON(w, 200, map[string]string{"id": id, "status": "UPDATED"})
}

func (s *Server) reports(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT rp.id,rp.type,rp.status,rp.content_hash,rp.generated_at,rp.lifecycle_case_id,p.display_name,lc.verification_status FROM identity_assurance_reports rp LEFT JOIN lifecycle_cases lc ON lc.id=rp.lifecycle_case_id AND lc.organization_id=$1 LEFT JOIN people p ON p.id=lc.person_id AND p.organization_id=$1 WHERE rp.organization_id=$1 ORDER BY rp.generated_at DESC LIMIT $2 OFFSET $3`, getSession(r).OrganizationID, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "type", "status", "contentHash", "generatedAt", "lifecycleCaseId", "personName", "verificationStatus"})
}

var errReportNotReady = errors.New("verification snapshot required")

func (s *Server) buildOffboardingPDF(ctx context.Context, orgID, id string) ([]byte, string, error) {
	var report reports.OffboardingReport
	report.CaseID = id
	err := s.DB.Pool.QueryRow(ctx, `SELECT p.display_name,p.lifecycle_status,coalesce(lc.verification_status,''),vs.observed_at,vs.connected_systems,vs.systems_failed,vs.managed_identities,vs.disabled_identities,vs.active_identities,vs.unresolved_identities FROM lifecycle_cases lc JOIN people p ON p.id=lc.person_id AND p.organization_id=$1 JOIN LATERAL(SELECT * FROM verification_snapshots v WHERE v.organization_id=$1 AND v.case_id=lc.id ORDER BY v.created_at DESC LIMIT 1)vs ON true WHERE lc.organization_id=$1 AND lc.id=$2`, orgID, id).Scan(&report.PersonName, &report.LifecycleStatus, &report.VerificationStatus, &report.GeneratedAt, &report.ConnectedSystems, &report.UnavailableConnectors, &report.ManagedIdentities, &report.DisabledIdentities, &report.ActiveIdentities, &report.UnresolvedIdentities)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", errReportNotReady
	}
	if err != nil {
		return nil, "", err
	}
	rows, err := s.DB.Pool.Query(ctx, `SELECT coalesce(c.name,'Manual')||' / '||coalesce(a.username,'Unresolved')||': '||la.action_type||' -> '||la.status FROM lifecycle_actions la LEFT JOIN identity_connectors c ON c.id=la.connector_id AND c.organization_id=$1 LEFT JOIN identity_accounts a ON a.id=la.identity_account_id AND a.organization_id=$1 WHERE la.organization_id=$1 AND la.case_id=$2 ORDER BY la.created_at`, orgID, id)
	if err != nil {
		return nil, "", err
	}
	for rows.Next() {
		var line string
		if rows.Scan(&line) == nil {
			report.Actions = append(report.Actions, line)
		}
	}
	rows.Close()
	rows, err = s.DB.Pool.Query(ctx, `SELECT type||': '||summary FROM identity_evidence WHERE organization_id=$1 AND lifecycle_case_id=$2 ORDER BY created_at`, orgID, id)
	if err != nil {
		return nil, "", err
	}
	for rows.Next() {
		var line string
		if rows.Scan(&line) == nil {
			report.Evidence = append(report.Evidence, line)
		}
	}
	rows.Close()
	pdf := reports.OffboardingPDF(report)
	sum := sha256.Sum256(pdf)
	hash := hex.EncodeToString(sum[:])
	return pdf, hash, nil
}

func (s *Server) generateOffboardingReport(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/reports/offboarding/")
	session := getSession(r)
	_, hash, err := s.buildOffboardingPDF(r.Context(), session.OrganizationID, id)
	if errors.Is(err, errReportNotReady) {
		writeError(w, 409, "REPORT_NOT_READY", "A verification snapshot is required before generating this report.", requestID(r))
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	tx, err := s.DB.Pool.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO identity_assurance_reports(organization_id,lifecycle_case_id,type,generated_by,content_hash) VALUES($1,$2,'OFFBOARDING_VERIFICATION',$3,$4) ON CONFLICT DO NOTHING`, session.OrganizationID, id, session.UserID, hash)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,metadata,request_id) VALUES($1,$2,'report.generated','lifecycle_case',$3,jsonb_build_object('type','OFFBOARDING_VERIFICATION','sha256',$4::text),$5)`, session.OrganizationID, session.UserID, id, hash, requestID(r))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 201, map[string]any{"downloadURL": "/api/v1/reports/offboarding/" + id + ".pdf", "contentHash": hash})
}

func (s *Server) offboardingPDF(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/reports/offboarding/"), ".pdf")
	session := getSession(r)
	pdf, hash, err := s.buildOffboardingPDF(r.Context(), session.OrganizationID, id)
	if errors.Is(err, errReportNotReady) {
		writeError(w, 409, "REPORT_NOT_READY", "A verification snapshot is required before generating this report.", requestID(r))
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="identitymesh-offboarding-%s.pdf"`, id))
	w.Header().Set("X-Content-SHA256", hash)
	w.WriteHeader(200)
	_, _ = w.Write(pdf)
}

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT u.id,u.email,u.display_name,u.mfa_enabled,u.disabled,u.created_at,u.updated_at,coalesce(array_agg(r.name ORDER BY r.name) FILTER(WHERE r.name IS NOT NULL),'{}') FROM users u LEFT JOIN user_roles ur ON ur.organization_id=$1 AND ur.user_id=u.id LEFT JOIN roles r ON r.id=ur.role_id WHERE u.organization_id=$1 GROUP BY u.id ORDER BY u.display_name LIMIT $2 OFFSET $3`, getSession(r).OrganizationID, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "email", "displayName", "mfaEnabled", "disabled", "createdAt", "updatedAt", "roles"})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email, DisplayName, Password string
		Roles                        []string
	}
	if !decodeJSON(w, r, &in, 32<<10) {
		return
	}
	if _, err := mail.ParseAddress(in.Email); err != nil || strings.TrimSpace(in.DisplayName) == "" || len(in.Password) < 12 {
		writeError(w, 400, "INVALID_USER", "A valid email, display name and password of at least 12 characters are required.", requestID(r))
		return
	}
	allowed := []string{"OWNER", "IDENTITY_ADMIN", "SECURITY_ADMIN", "ACCESS_REVIEWER", "OPERATOR", "AUDITOR", "VIEWER"}
	if len(in.Roles) == 0 {
		in.Roles = []string{"VIEWER"}
	}
	for _, role := range in.Roles {
		if !contains(allowed, role) {
			writeError(w, 400, "INVALID_ROLE", "One or more roles are invalid.", requestID(r))
			return
		}
	}
	hash, err := authn.HashPassword(in.Password)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	session := getSession(r)
	id := uuid.NewString()
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO users(id,organization_id,email,display_name,password_hash) VALUES($1,$2,lower($3),$4,$5)`, id, session.OrganizationID, in.Email, in.DisplayName, hash)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO user_roles(organization_id,user_id,role_id) SELECT $1,$2,id FROM roles WHERE name=ANY($3)`, session.OrganizationID, id, in.Roles)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,metadata,request_id) VALUES($1,$2,'user.created','user',$3,jsonb_build_object('roles',$4::text[]),$5)`, session.OrganizationID, session.UserID, id, in.Roles, requestID(r))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		if strings.Contains(err.Error(), "users_email_global_unique_idx") {
			writeError(w, 409, "EMAIL_ALREADY_EXISTS", "The email is already registered.", requestID(r))
			return
		}
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 201, map[string]string{"id": id})
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	org := getSession(r).OrganizationID
	_, err := s.DB.Pool.Exec(r.Context(), `INSERT INTO organization_settings(organization_id) VALUES($1) ON CONFLICT DO NOTHING`, org)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	var name string
	var audit, evidence, reconciliation, report int
	var domains []byte
	err = s.DB.Pool.QueryRow(r.Context(), `SELECT o.name,s.audit_retention_days,s.evidence_retention_days,s.reconciliation_retention_days,s.report_retention_days,s.trusted_email_domains FROM organizations o JOIN organization_settings s ON s.organization_id=o.id WHERE o.id=$1`, org).Scan(&name, &audit, &evidence, &reconciliation, &report, &domains)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	var trusted any
	_ = json.Unmarshal(domains, &trusted)
	writeJSON(w, 200, map[string]any{"organizationId": org, "organizationName": name, "auditRetentionDays": audit, "evidenceRetentionDays": evidence, "reconciliationRetentionDays": reconciliation, "reportRetentionDays": report, "trustedEmailDomains": trusted})
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OrganizationName                                                                            string
		AuditRetentionDays, EvidenceRetentionDays, ReconciliationRetentionDays, ReportRetentionDays int
		TrustedEmailDomains                                                                         []string
	}
	if !decodeJSON(w, r, &in, 32<<10) {
		return
	}
	if strings.TrimSpace(in.OrganizationName) == "" || in.AuditRetentionDays < 30 || in.AuditRetentionDays > 3650 || in.EvidenceRetentionDays < 30 || in.EvidenceRetentionDays > 3650 || in.ReconciliationRetentionDays < 7 || in.ReconciliationRetentionDays > 3650 || in.ReportRetentionDays < 30 || in.ReportRetentionDays > 3650 {
		writeError(w, 400, "INVALID_SETTINGS", "Organization name and retention periods are outside accepted bounds.", requestID(r))
		return
	}
	for i, domain := range in.TrustedEmailDomains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" || strings.ContainsAny(domain, "/@: ") {
			writeError(w, 400, "INVALID_TRUSTED_DOMAIN", "Trusted email domains must be host names.", requestID(r))
			return
		}
		in.TrustedEmailDomains[i] = domain
	}
	raw, _ := json.Marshal(in.TrustedEmailDomains)
	session := getSession(r)
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `UPDATE organizations SET name=$1,updated_at=now() WHERE id=$2`, in.OrganizationName, session.OrganizationID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO organization_settings(organization_id,audit_retention_days,evidence_retention_days,reconciliation_retention_days,report_retention_days,trusted_email_domains) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(organization_id) DO UPDATE SET audit_retention_days=EXCLUDED.audit_retention_days,evidence_retention_days=EXCLUDED.evidence_retention_days,reconciliation_retention_days=EXCLUDED.reconciliation_retention_days,report_retention_days=EXCLUDED.report_retention_days,trusted_email_domains=EXCLUDED.trusted_email_domains,updated_at=now()`, session.OrganizationID, in.AuditRetentionDays, in.EvidenceRetentionDays, in.ReconciliationRetentionDays, in.ReportRetentionDays, raw)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,metadata,request_id) VALUES($1,$2,'settings.updated','organization',$1,jsonb_build_object('trustedDomainCount',$3::int),$4)`, session.OrganizationID, session.UserID, len(in.TrustedEmailDomains), requestID(r))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "UPDATED"})
}
