package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/thiagomontozo/identitymesh/backend/internal/assurance"
	authn "github.com/thiagomontozo/identitymesh/backend/internal/auth"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/scim"
	"github.com/thiagomontozo/identitymesh/backend/internal/csvsource"
	"github.com/thiagomontozo/identitymesh/backend/internal/database"
	"github.com/thiagomontozo/identitymesh/backend/internal/domain"
	"github.com/thiagomontozo/identitymesh/backend/internal/ratelimit"
	"github.com/thiagomontozo/identitymesh/backend/internal/rbac"
	"github.com/thiagomontozo/identitymesh/backend/internal/secure"
	"github.com/thiagomontozo/identitymesh/backend/internal/workers"
)

type contextKey string

const (
	sessionKey   contextKey = "session"
	requestIDKey contextKey = "request-id"
)

type Server struct {
	DB                   *database.Store
	Assurance            *assurance.Service
	Secrets              secure.SecretStore
	Log                  *slog.Logger
	AllowedOrigin        string
	SecureCookies        bool
	RequirePrivilegedMFA bool
	MaxCSVBytes          int64
	SyncPool             *workers.Pool
	ActionPool           *workers.Pool
	DistributedQueue     *workers.DistributedQueue
	JobMode              string
	RateLimiter          ratelimit.Limiter
	trustedProxies       []*net.IPNet
}

func New(db *database.Store, svc *assurance.Service, secrets secure.SecretStore, log *slog.Logger, origin string, secureCookies, requirePrivilegedMFA bool, maxCSV int64, syncPool, actionPool *workers.Pool, distributedQueue *workers.DistributedQueue, jobMode string, distributedLimiter ratelimit.Limiter, trustedProxyCIDRs []string) *Server {
	server := &Server{DB: db, Assurance: svc, Secrets: secrets, Log: log, AllowedOrigin: origin, SecureCookies: secureCookies, RequirePrivilegedMFA: requirePrivilegedMFA, MaxCSVBytes: maxCSV, SyncPool: syncPool, ActionPool: actionPool, DistributedQueue: distributedQueue, JobMode: jobMode, RateLimiter: distributedLimiter}
	for _, value := range trustedProxyCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(value))
		if err == nil {
			server.trustedProxies = append(server.trustedProxies, network)
		}
	}
	return server
}

func runBounded(ctx context.Context, pool *workers.Pool, job func(context.Context) error) error {
	if pool == nil {
		return job(ctx)
	}
	done := make(chan error, 1)
	if err := pool.Submit(func(workerCtx context.Context) error {
		err := job(workerCtx)
		done <- err
		return err
	}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func privilegedRoles(roles []string) bool {
	for _, role := range roles {
		switch role {
		case "OWNER", "IDENTITY_ADMIN", "SECURITY_ADMIN", "OPERATOR":
			return true
		}
	}
	return false
}

func connectorCapabilityAllowed(connectorType, capability string) bool {
	allowed := map[string]map[string]bool{
		"CSV_AUTHORITATIVE_SOURCE": {},
		"SCIM_2_0":                 {"DISCOVER_USERS": true, "DISCOVER_GROUPS": true, "DISCOVER_MEMBERSHIPS": true, "DISCOVER_ENTITLEMENTS": true, "DISABLE_ACCOUNT": true, "ENABLE_ACCOUNT": true, "REMOVE_MEMBERSHIP": true, "ADD_MEMBERSHIP": true},
		"LDAP_DIRECTORY":           {"DISCOVER_USERS": true, "DISCOVER_GROUPS": true, "DISCOVER_MEMBERSHIPS": true, "DISCOVER_ENTITLEMENTS": true, "DISABLE_ACCOUNT": true, "REMOVE_MEMBERSHIP": true},
		"ENTRA_ID":                 {"DISCOVER_USERS": true, "DISCOVER_GROUPS": true, "DISCOVER_MEMBERSHIPS": true, "DISCOVER_ENTITLEMENTS": true, "DISABLE_ACCOUNT": true},
		"OKTA":                     {"DISCOVER_USERS": true, "DISCOVER_GROUPS": true, "DISCOVER_MEMBERSHIPS": true, "DISCOVER_ENTITLEMENTS": true, "DISABLE_ACCOUNT": true},
		"GOOGLE_WORKSPACE":         {"DISCOVER_USERS": true, "DISCOVER_GROUPS": true, "DISCOVER_MEMBERSHIPS": true, "DISCOVER_ENTITLEMENTS": true, "DISABLE_ACCOUNT": true},
		"GITHUB":                   {"DISCOVER_USERS": true, "DISCOVER_GROUPS": true, "DISCOVER_MEMBERSHIPS": true, "DISCOVER_ENTITLEMENTS": true, "REMOVE_MEMBERSHIP": true},
	}
	return allowed[connectorType][capability]
}

func secretProviderName(store secure.SecretStore) string {
	if _, ok := store.(*secure.VaultTransitStore); ok {
		return "VAULT_TRANSIT"
	}
	return "LOCAL_AES_GCM"
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /ready", s.ready)
	mux.HandleFunc("POST /api/v1/auth/login", s.rate(10, time.Minute, s.login))
	mux.Handle("/api/v1/", s.authenticated(s.csrf(http.HandlerFunc(s.api))))
	return s.middleware(mux)
}
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if _, err := uuid.Parse(id); err != nil {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if origin := r.Header.Get("Origin"); origin != "" && origin == s.AllowedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-Request-ID")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.DB.Pool.Ping(ctx); err != nil {
		writeError(w, 503, "NOT_READY", "PostgreSQL is unavailable.", requestID(r))
		return
	}
	var migrated bool
	_ = s.DB.Pool.QueryRow(ctx, "SELECT count(*)=3 FROM schema_migrations WHERE version IN ('001_initial','002_product_completion','003_production_platform')").Scan(&migrated)
	if !migrated {
		writeError(w, 503, "MIGRATIONS_PENDING", "Database migrations are not current.", requestID(r))
		return
	}
	if checker, ok := s.Secrets.(secure.HealthChecker); ok {
		if err := checker.Health(ctx); err != nil {
			writeError(w, 503, "SECRET_STORE_NOT_READY", "The external secret store is unavailable.", requestID(r))
			return
		}
	}
	writeJSON(w, 200, map[string]any{"status": "ready", "database": true, "migrations": true, "secretStore": true})
}
func (s *Server) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("identitymesh_session")
		if err != nil {
			writeError(w, 401, "UNAUTHENTICATED", "Authentication is required.", requestID(r))
			return
		}
		session, err := s.DB.SessionByToken(r.Context(), cookie.Value)
		if err != nil {
			writeError(w, 401, "SESSION_INVALID", "The session is expired or revoked.", requestID(r))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, session)))
	})
}
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		session := getSession(r)
		token := r.Header.Get("X-CSRF-Token")
		h := sha256.Sum256([]byte(token))
		if token == "" || subtle.ConstantTimeCompare(h[:], session.CSRFHash) != 1 {
			writeError(w, 403, "CSRF_VALIDATION_FAILED", "The request could not be validated.", requestID(r))
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != s.AllowedOrigin {
			writeError(w, 403, "ORIGIN_NOT_ALLOWED", "The request origin is not allowed.", requestID(r))
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) rate(limit int, window time.Duration, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.RateLimiter == nil {
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMITER_UNAVAILABLE", "Request protection is temporarily unavailable.", requestID(r))
			return
		}
		key := s.clientIP(r) + ":" + r.URL.Path
		if session, ok := r.Context().Value(sessionKey).(database.Session); ok && session.OrganizationID != "" {
			key += ":" + session.OrganizationID + ":" + session.UserID
		}
		allowed, retry, err := s.RateLimiter.Allow(r.Context(), key, limit, window)
		if err != nil {
			s.Log.Error("distributed rate limiter unavailable", "requestId", requestID(r), "error", err.Error())
			writeError(w, http.StatusServiceUnavailable, "RATE_LIMITER_UNAVAILABLE", "Request protection is temporarily unavailable.", requestID(r))
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Round(time.Second)/time.Second))))
			writeError(w, 429, "RATE_LIMITED", "Too many requests. Try again later.", requestID(r))
			return
		}
		next(w, r)
	}
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if !s.isTrustedProxy(peer) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for index := len(parts) - 1; index >= 0; index-- {
		forwarded := net.ParseIP(strings.TrimSpace(parts[index]))
		if forwarded == nil {
			continue
		}
		if !s.isTrustedProxy(forwarded) {
			return forwarded.String()
		}
	}
	return host
}

func (s *Server) isTrustedProxy(ip net.IP) bool {
	for _, network := range s.trustedProxies {
		if ip != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password, TOTP string }
	if !decodeJSON(w, r, &in, 32<<10) {
		return
	}
	session, err := s.DB.Authenticate(r.Context(), in.Email, in.Password)
	if err != nil {
		writeError(w, 401, "INVALID_CREDENTIALS", "Email or password is incorrect.", requestID(r))
		return
	}
	var mfaEnabled bool
	var mfaCipher *string
	if err = s.DB.Pool.QueryRow(r.Context(), `SELECT mfa_enabled,mfa_secret_ciphertext FROM users WHERE organization_id=$1 AND id=$2`, session.OrganizationID, session.UserID).Scan(&mfaEnabled, &mfaCipher); err != nil {
		s.internal(w, r, err)
		return
	}
	if s.RequirePrivilegedMFA && privilegedRoles(session.Roles) && !mfaEnabled {
		writeError(w, http.StatusForbidden, "MFA_ENROLLMENT_REQUIRED", "MFA enrollment is required for this privileged role.", requestID(r))
		return
	}
	if mfaEnabled {
		if mfaCipher == nil {
			writeError(w, http.StatusUnauthorized, "MFA_CONFIGURATION_INVALID", "MFA configuration is incomplete.", requestID(r))
			return
		}
		secret, decryptErr := s.Secrets.Decrypt(*mfaCipher)
		if decryptErr != nil || !authn.VerifyTOTP(string(secret), in.TOTP, time.Now().UTC()) {
			writeError(w, http.StatusUnauthorized, "MFA_REQUIRED", "A valid multi-factor authentication code is required.", requestID(r))
			return
		}
	}
	token := randomToken(32)
	csrf := randomToken(32)
	th := sha256.Sum256([]byte(token))
	ch := sha256.Sum256([]byte(csrf))
	session, err = s.DB.CreateSession(r.Context(), session, th[:], ch[:], time.Now().UTC().Add(8*time.Hour))
	if err != nil {
		writeError(w, 500, "SESSION_CREATE_FAILED", "The session could not be created.", requestID(r))
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "identitymesh_session", Value: token, Path: "/", HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 60 * 60})
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "auth.login", "session", session.ID, map[string]any{"email": session.Email}, requestID(r))
	writeJSON(w, 200, map[string]any{"user": map[string]any{"id": session.UserID, "email": session.Email, "displayName": session.DisplayName, "roles": session.Roles}, "csrfToken": csrf, "expiresAt": session.ExpiresAt})
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case r.Method == "GET" && path == "/auth/me":
		session := getSession(r)
		writeJSON(w, 200, map[string]any{"id": session.UserID, "email": session.Email, "displayName": session.DisplayName, "roles": session.Roles})
	case r.Method == "POST" && path == "/auth/logout":
		s.logout(w, r)
	case r.Method == "POST" && path == "/auth/password":
		s.changePassword(w, r)
	case r.Method == "POST" && path == "/auth/mfa/enroll":
		s.mfaEnroll(w, r)
	case r.Method == "POST" && path == "/auth/mfa/confirm":
		s.mfaConfirm(w, r)
	case r.Method == "GET" && path == "/auth/sessions":
		s.sessions(w, r)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/auth/sessions/"):
		s.revokeSession(w, r)
	case r.Method == "GET" && path == "/dashboard":
		s.require("person.read", s.dashboard)(w, r)
	case r.Method == "GET" && path == "/people":
		s.require("person.read", s.people)(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/people/"):
		s.require("person.read", s.person)(w, r)
	case r.Method == "GET" && path == "/connectors":
		s.require("connector.read", s.connectors)(w, r)
	case r.Method == "POST" && path == "/connectors":
		s.require("connector.manage", s.createConnector)(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/connectors/") && strings.HasSuffix(path, "/syncs"):
		s.require("connector.read", s.connectorSyncs)(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/connectors/"):
		s.require("connector.read", s.connectorDetail)(w, r)
	case r.Method == "PATCH" && strings.HasPrefix(path, "/connectors/"):
		s.require("connector.manage", s.updateConnector)(w, r)
	case r.Method == "POST" && strings.HasPrefix(path, "/connectors/") && strings.HasSuffix(path, "/test"):
		s.require("connector.manage", s.rate(10, time.Minute, s.testConnector))(w, r)
	case r.Method == "POST" && strings.HasPrefix(path, "/connectors/") && strings.HasSuffix(path, "/sync"):
		s.require("connector.sync", s.rate(10, time.Minute, s.syncConnector))(w, r)
	case r.Method == "POST" && path == "/csv-import/preview":
		s.require("person.manage", s.rate(10, time.Minute, s.csvPreview))(w, r)
	case r.Method == "POST" && path == "/csv-import/apply":
		s.require("person.manage", s.rate(6, time.Minute, s.csvApply))(w, r)
	case r.Method == "GET" && path == "/identities":
		s.require("identity.read", s.identities)(w, r)
	case r.Method == "GET" && path == "/correlation-candidates":
		s.require("identity.read", s.correlationCandidates)(w, r)
	case r.Method == "POST" && strings.HasPrefix(path, "/correlation-candidates/") && strings.HasSuffix(path, "/accept"):
		s.require("identity.link", s.acceptCandidate)(w, r)
	case r.Method == "POST" && strings.HasPrefix(path, "/correlation-candidates/") && strings.HasSuffix(path, "/reject"):
		s.require("identity.link", s.rejectCandidate)(w, r)
	case r.Method == "GET" && path == "/applications":
		s.require("identity.read", s.applications)(w, r)
	case r.Method == "POST" && path == "/applications":
		s.require("connector.manage", s.createApplication)(w, r)
	case r.Method == "GET" && path == "/entitlements":
		s.require("identity.read", s.entitlements)(w, r)
	case r.Method == "GET" && path == "/access-grants":
		s.require("identity.read", s.accessGrants)(w, r)
	case r.Method == "GET" && path == "/reconciliation":
		s.require("connector.read", s.reconciliationRuns)(w, r)
	case r.Method == "GET" && path == "/findings":
		s.require("identity.read", s.findings)(w, r)
	case r.Method == "PATCH" && strings.HasPrefix(path, "/findings/"):
		s.require("identity.link", s.updateFinding)(w, r)
	case r.Method == "POST" && path == "/lifecycle-cases":
		s.require("lifecycle.plan", s.createCase)(w, r)
	case r.Method == "GET" && path == "/lifecycle-cases":
		s.require("lifecycle.read", s.lifecycleCases)(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/lifecycle-cases/") && strings.HasSuffix(path, "/events"):
		s.require("lifecycle.read", s.caseEvents)(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/lifecycle-cases/"):
		s.require("lifecycle.read", s.getCase)(w, r)
	case r.Method == "POST" && strings.HasSuffix(path, "/plan"):
		s.require("lifecycle.plan", s.planCase)(w, r)
	case r.Method == "POST" && strings.HasSuffix(path, "/approve"):
		s.require("lifecycle.approve", s.approveCase)(w, r)
	case r.Method == "POST" && strings.HasSuffix(path, "/execute"):
		s.require("lifecycle.execute", s.rate(8, time.Minute, s.executeCase))(w, r)
	case r.Method == "POST" && strings.HasSuffix(path, "/cancel"):
		s.require("lifecycle.plan", s.cancelCase)(w, r)
	case r.Method == "GET" && path == "/access-reviews":
		s.require("access_review.read", s.accessReviews)(w, r)
	case r.Method == "POST" && path == "/access-reviews":
		s.require("access_review.manage", s.createAccessReview)(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/access-reviews/"):
		s.require("access_review.read", s.accessReviewDetail)(w, r)
	case r.Method == "POST" && strings.HasPrefix(path, "/access-review-items/") && strings.HasSuffix(path, "/decision"):
		s.require("access_review.decide", s.reviewDecision)(w, r)
	case r.Method == "GET" && path == "/audit":
		s.require("audit.read", s.audit)(w, r)
	case r.Method == "GET" && path == "/evidence":
		s.require("evidence.read", s.evidence)(w, r)
	case r.Method == "GET" && path == "/reports":
		s.require("evidence.read", s.reports)(w, r)
	case r.Method == "POST" && strings.HasPrefix(path, "/reports/offboarding/"):
		s.require("evidence.read", s.generateOffboardingReport)(w, r)
	case r.Method == "GET" && strings.HasPrefix(path, "/reports/offboarding/") && strings.HasSuffix(path, ".pdf"):
		s.require("evidence.read", s.offboardingPDF)(w, r)
	case r.Method == "GET" && path == "/users":
		s.require("user.manage", s.users)(w, r)
	case r.Method == "POST" && path == "/users":
		s.require("user.manage", s.createUser)(w, r)
	case r.Method == "GET" && path == "/settings":
		s.require("settings.manage", s.settings)(w, r)
	case r.Method == "PATCH" && path == "/settings":
		s.require("settings.manage", s.updateSettings)(w, r)
	default:
		writeError(w, 404, "NOT_FOUND", "The requested resource was not found.", requestID(r))
	}
}
func (s *Server) require(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rbac.Allowed(getSession(r).Roles, permission) {
			writeError(w, 403, "FORBIDDEN", "You do not have permission to perform this operation.", requestID(r))
			return
		}
		next(w, r)
	}
}
func (s *Server) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	secret, err := authn.NewTOTPSecret()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	ciphertext, err := s.Secrets.Encrypt([]byte(secret))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if _, err = s.DB.Pool.Exec(r.Context(), `UPDATE users SET mfa_secret_ciphertext=$1,mfa_enabled=false,updated_at=now() WHERE organization_id=$2 AND id=$3`, ciphertext, session.OrganizationID, session.UserID); err != nil {
		s.internal(w, r, err)
		return
	}
	issuer := "IdentityMesh"
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, session.Email, secret, issuer)
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauthURI": uri})
}
func (s *Server) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if !decodeJSON(w, r, &in, 4<<10) {
		return
	}
	session := getSession(r)
	var ciphertext *string
	if err := s.DB.Pool.QueryRow(r.Context(), `SELECT mfa_secret_ciphertext FROM users WHERE organization_id=$1 AND id=$2`, session.OrganizationID, session.UserID).Scan(&ciphertext); err != nil || ciphertext == nil {
		writeError(w, http.StatusBadRequest, "MFA_NOT_ENROLLED", "Start MFA enrollment first.", requestID(r))
		return
	}
	secret, err := s.Secrets.Decrypt(*ciphertext)
	if err != nil || !authn.VerifyTOTP(string(secret), in.Code, time.Now().UTC()) {
		writeError(w, http.StatusBadRequest, "MFA_CODE_INVALID", "The MFA code is invalid.", requestID(r))
		return
	}
	if _, err = s.DB.Pool.Exec(r.Context(), `UPDATE users SET mfa_enabled=true,updated_at=now() WHERE organization_id=$1 AND id=$2`, session.OrganizationID, session.UserID); err != nil {
		s.internal(w, r, err)
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "auth.mfa_enabled", "user", session.UserID, map[string]any{}, requestID(r))
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	_ = s.DB.RevokeSession(r.Context(), session.OrganizationID, session.ID)
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "auth.logout", "session", session.ID, map[string]any{}, requestID(r))
	http.SetCookie(w, &http.Cookie{Name: "identitymesh_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(204)
}
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ CurrentPassword, NewPassword string }
	if !decodeJSON(w, r, &in, 16<<10) {
		return
	}
	session := getSession(r)
	if err := s.DB.ChangePassword(r.Context(), session.OrganizationID, session.UserID, in.CurrentPassword, in.NewPassword); err != nil {
		writeError(w, 400, "PASSWORD_CHANGE_FAILED", err.Error(), requestID(r))
		return
	}
	w.WriteHeader(204)
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	d, err := s.DB.Dashboard(r.Context(), getSession(r).OrganizationID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, d)
}
func (s *Server) people(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	items, err := s.DB.ListPeople(r.Context(), getSession(r).OrganizationID, r.URL.Query().Get("q"), r.URL.Query().Get("status"), limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "limit": limit, "offset": offset})
}
func (s *Server) person(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/people/")
	if _, err := uuid.Parse(id); err != nil {
		writeError(w, 400, "INVALID_ID", "A valid UUID is required.", requestID(r))
		return
	}
	p, accounts, err := s.DB.GetPerson(r.Context(), getSession(r).OrganizationID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "PERSON_NOT_FOUND", "The person was not found.", requestID(r))
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	related, err := s.personRelated(r.Context(), getSession(r).OrganizationID, id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	related["person"] = p
	related["identities"] = accounts
	writeJSON(w, 200, related)
}
func (s *Server) connectors(w http.ResponseWriter, r *http.Request) {
	items, err := s.DB.ListConnectors(r.Context(), getSession(r).OrganizationID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) createConnector(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Type, BaseURL, Environment, Credential string
		Capabilities                                 []string
		WriteEnabled                                 bool
		Configuration                                map[string]any
	}
	if !decodeJSON(w, r, &in, 64<<10) {
		return
	}
	if in.Name == "" || !contains([]string{"CSV_AUTHORITATIVE_SOURCE", "SCIM_2_0", "LDAP_DIRECTORY", "ENTRA_ID", "OKTA", "GOOGLE_WORKSPACE", "GITHUB"}, in.Type) {
		writeError(w, 400, "INVALID_CONNECTOR", "Connector name and supported type are required.", requestID(r))
		return
	}
	allowedCapabilities := []string{"DISCOVER_USERS", "DISCOVER_GROUPS", "DISCOVER_MEMBERSHIPS", "DISCOVER_ENTITLEMENTS", "DISABLE_ACCOUNT", "ENABLE_ACCOUNT", "REMOVE_MEMBERSHIP", "ADD_MEMBERSHIP"}
	seenCapabilities := map[string]bool{}
	for _, capability := range in.Capabilities {
		if !contains(allowedCapabilities, capability) || !connectorCapabilityAllowed(in.Type, capability) || seenCapabilities[capability] {
			writeError(w, 400, "INVALID_CONNECTOR_CAPABILITY", "Connector capabilities must be known and unique.", requestID(r))
			return
		}
		seenCapabilities[capability] = true
	}
	writeTypes := []string{"SCIM_2_0", "LDAP_DIRECTORY", "ENTRA_ID", "OKTA", "GOOGLE_WORKSPACE", "GITHUB"}
	if in.WriteEnabled && !contains(writeTypes, in.Type) {
		writeError(w, 400, "WRITE_NOT_SUPPORTED", "This connector type cannot be write-enabled.", requestID(r))
		return
	}
	if in.WriteEnabled && !seenCapabilities["DISABLE_ACCOUNT"] && !seenCapabilities["REMOVE_MEMBERSHIP"] {
		writeError(w, 400, "WRITE_CAPABILITY_REQUIRED", "Write enablement requires an explicit supported write capability.", requestID(r))
		return
	}
	if in.Type == "SCIM_2_0" {
		if _, err := scim.New(in.BaseURL, "", s.Assurance.AllowHTTP, s.Assurance.Timeout); err != nil {
			writeError(w, 400, "INVALID_CONNECTOR_URL", err.Error(), requestID(r))
			return
		}
	}
	if in.Type == "LDAP_DIRECTORY" {
		u, err := url.Parse(in.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			writeError(w, 400, "INVALID_CONNECTOR_URL", "LDAP base URL must use ldap or ldaps without embedded credentials, query or fragment.", requestID(r))
			return
		}
		if err := validateLDAPConfiguration(in.Configuration); err != nil {
			writeError(w, 400, "INVALID_LDAP_CONFIGURATION", err.Error(), requestID(r))
			return
		}
		if in.WriteEnabled {
			if err := validateLDAPWriteConfiguration(in.Configuration, in.Capabilities); err != nil {
				writeError(w, 400, "INVALID_LDAP_WRITE_CONFIGURATION", err.Error(), requestID(r))
				return
			}
		}
	}
	if contains([]string{"ENTRA_ID", "OKTA", "GOOGLE_WORKSPACE", "GITHUB"}, in.Type) {
		if err := validateNativeURL(in.BaseURL, s.Assurance.AllowHTTP, s.Assurance.Timeout); err != nil {
			writeError(w, 400, "INVALID_CONNECTOR_URL", err.Error(), requestID(r))
			return
		}
		if err := validateNativeConfiguration(in.Type, in.Configuration); err != nil {
			writeError(w, 400, "INVALID_CONNECTOR_CONFIGURATION", err.Error(), requestID(r))
			return
		}
	}
	org := getSession(r).OrganizationID
	id := uuid.NewString()
	caps, _ := json.Marshal(in.Capabilities)
	configuration, _ := json.Marshal(in.Configuration)
	tx, err := s.DB.Pool.Begin(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), `INSERT INTO identity_connectors(id,organization_id,name,type,base_url,environment,write_enabled,capabilities,configuration) VALUES($1,$2,$3,$4,nullif($5,''),$6,$7,$8,$9)`, id, org, in.Name, in.Type, in.BaseURL, in.Environment, in.WriteEnabled, caps, configuration)
	if err == nil && in.Credential != "" {
		var encrypted string
		encrypted, err = s.Secrets.Encrypt([]byte(in.Credential))
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO connector_credentials(organization_id,connector_id,ciphertext,provider) VALUES($1,$2,$3,$4)`, org, id, encrypted, secretProviderName(s.Secrets))
		}
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	_ = s.DB.Audit(r.Context(), org, getSession(r).UserID, "connector.created", "connector", id, map[string]any{"type": in.Type, "writeEnabled": in.WriteEnabled}, requestID(r))
	writeJSON(w, 201, map[string]string{"id": id})
}
func (s *Server) syncConnector(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/connectors/"), "/sync")
	session := getSession(r)
	if s.JobMode == "DISTRIBUTED" {
		if s.DistributedQueue == nil {
			writeError(w, 503, "JOB_QUEUE_UNAVAILABLE", "The distributed job queue is unavailable.", requestID(r))
			return
		}
		payload := map[string]string{"connectorId": id, "requestId": requestID(r), "actorUserId": session.UserID}
		jobID, created, err := s.DistributedQueue.Enqueue(r.Context(), session.OrganizationID, "CONNECTOR_SYNC", payload, "connector-sync:"+id+":"+requestID(r), 100)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		_, _ = s.DB.Pool.Exec(r.Context(), `UPDATE identity_connectors SET last_sync_status='QUEUED',updated_at=now() WHERE organization_id=$1 AND id=$2`, session.OrganizationID, id)
		_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "connector.sync_queued", "connector", id, map[string]any{"jobId": jobID}, requestID(r))
		writeJSON(w, http.StatusAccepted, map[string]any{"jobId": jobID, "status": "QUEUED", "created": created})
		return
	}
	var result assurance.SyncResult
	err := runBounded(r.Context(), s.SyncPool, func(ctx context.Context) error {
		var syncErr error
		result, syncErr = s.Assurance.SyncConnector(ctx, session.OrganizationID, id, requestID(r))
		return syncErr
	})
	if err != nil {
		writeError(w, 502, "CONNECTOR_SYNC_FAILED", "The identity connector could not be synchronized.", requestID(r))
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "connector.sync_completed", "connector", id, result, requestID(r))
	writeJSON(w, 200, result)
}
func (s *Server) testConnector(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/connectors/"), "/test")
	session := getSession(r)
	if err := s.Assurance.TestConnection(r.Context(), session.OrganizationID, id); err != nil {
		writeError(w, 502, "CONNECTOR_TEST_FAILED", "The expected connector endpoint could not be authenticated and read.", requestID(r))
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "connector.test_succeeded", "connector", id, map[string]any{}, requestID(r))
	writeJSON(w, 200, map[string]any{"status": "SUCCEEDED", "writeAttempted": false})
}
func (s *Server) csvPreview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.MaxCSVBytes)
	if err := r.ParseMultipartForm(s.MaxCSVBytes); err != nil {
		writeError(w, 413, "CSV_TOO_LARGE", "The CSV exceeds the configured size limit.", requestID(r))
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
	if err != nil {
		writeError(w, 400, "CSV_INVALID", err.Error(), requestID(r))
		return
	}
	writeJSON(w, 200, preview)
}
func (s *Server) createCase(w http.ResponseWriter, r *http.Request) {
	var in struct{ PersonID string }
	if !decodeJSON(w, r, &in, 16<<10) {
		return
	}
	if _, err := uuid.Parse(in.PersonID); err != nil {
		writeError(w, 400, "INVALID_PERSON_ID", "A valid person UUID is required.", requestID(r))
		return
	}
	session := getSession(r)
	id, err := s.Assurance.CreateCase(r.Context(), session.OrganizationID, in.PersonID, session.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "PERSON_NOT_FOUND", "The person was not found in the authorized organization.", requestID(r))
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "offboarding.created", "lifecycle_case", id, map[string]any{"personId": in.PersonID}, requestID(r))
	writeJSON(w, 201, map[string]string{"id": id, "status": "DRAFT"})
}
func caseIDFromAction(path, action string) string {
	return strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/lifecycle-cases/"), "/"+action)
}
func (s *Server) planCase(w http.ResponseWriter, r *http.Request) {
	id := caseIDFromAction(r.URL.Path, "plan")
	session := getSession(r)
	preview, err := s.Assurance.PlanCase(r.Context(), session.OrganizationID, id, session.UserID)
	if err != nil {
		s.lifecycleError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"status": "AWAITING_APPROVAL", "actions": preview})
}
func (s *Server) approveCase(w http.ResponseWriter, r *http.Request) {
	id := caseIDFromAction(r.URL.Path, "approve")
	session := getSession(r)
	if err := s.Assurance.ApproveCase(r.Context(), session.OrganizationID, id, session.UserID); err != nil {
		s.lifecycleError(w, r, err)
		return
	}
	_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "offboarding.approved", "lifecycle_case", id, map[string]any{}, requestID(r))
	writeJSON(w, 200, map[string]string{"status": "APPROVED"})
}
func (s *Server) executeCase(w http.ResponseWriter, r *http.Request) {
	id := caseIDFromAction(r.URL.Path, "execute")
	session := getSession(r)
	if s.JobMode == "DISTRIBUTED" {
		if s.DistributedQueue == nil {
			writeError(w, 503, "JOB_QUEUE_UNAVAILABLE", "The distributed job queue is unavailable.", requestID(r))
			return
		}
		payload := map[string]string{"caseId": id, "requestId": requestID(r), "actorUserId": session.UserID}
		jobID, created, err := s.DistributedQueue.Enqueue(r.Context(), session.OrganizationID, "LIFECYCLE_EXECUTE", payload, "lifecycle-execute:"+id, 200)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		_ = s.DB.Audit(r.Context(), session.OrganizationID, session.UserID, "offboarding.queued", "lifecycle_case", id, map[string]any{"jobId": jobID}, requestID(r))
		writeJSON(w, http.StatusAccepted, map[string]any{"jobId": jobID, "status": "QUEUED", "created": created})
		return
	}
	var status domain.VerificationStatus
	err := runBounded(r.Context(), s.ActionPool, func(ctx context.Context) error {
		var executeErr error
		status, executeErr = s.Assurance.ExecuteAndVerify(ctx, session.OrganizationID, id, session.UserID)
		return executeErr
	})
	if err != nil {
		s.lifecycleError(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"verificationStatus": status})
}
func (s *Server) getCase(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/lifecycle-cases/")
	item, err := s.Assurance.GetCase(r.Context(), getSession(r).OrganizationID, id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, 200, item)
}
func (s *Server) caseEvents(w http.ResponseWriter, r *http.Request) {
	id := caseIDFromAction(r.URL.Path, "events")
	session := getSession(r)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "SSE_UNAVAILABLE", "Streaming is unavailable.", requestID(r))
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := time.Time{}
	for {
		rows, err := s.DB.Pool.Query(r.Context(), `SELECT type,summary,created_at FROM lifecycle_events WHERE organization_id=$1 AND case_id=$2 AND created_at>$3 ORDER BY created_at`, session.OrganizationID, id, last)
		if err != nil {
			return
		}
		for rows.Next() {
			var typ, summary string
			var at time.Time
			if rows.Scan(&typ, &summary, &at) == nil {
				data, _ := json.Marshal(map[string]any{"type": typ, "summary": summary, "at": at})
				_, _ = fmt.Fprintf(w, "event: lifecycle\ndata: %s\n\n", data)
				last = at
			}
		}
		rows.Close()
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
func (s *Server) reviewDecision(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/access-review-items/"), "/decision")
	var in struct{ Decision, Comment string }
	if !decodeJSON(w, r, &in, 16<<10) {
		return
	}
	session := getSession(r)
	if err := s.Assurance.DecideReview(r.Context(), session.OrganizationID, id, session.UserID, in.Decision, in.Comment); err != nil {
		writeError(w, 400, "REVIEW_DECISION_FAILED", err.Error(), requestID(r))
		return
	}
	writeJSON(w, 201, map[string]any{"decision": in.Decision, "externalActionExecuted": false, "requiresApproval": in.Decision == "REVOKE"})
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT id,event_type,resource_type,resource_id,metadata,request_id,timestamp FROM audit_events WHERE organization_id=$1 ORDER BY timestamp DESC LIMIT $2 OFFSET $3`, getSession(r).OrganizationID, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "eventType", "resourceType", "resourceId", "metadata", "requestId", "timestamp"})
}
func (s *Server) evidence(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	rows, err := s.DB.Pool.Query(r.Context(), `SELECT id,connector_id,person_id,identity_account_id,lifecycle_case_id,action_id,type,summary,observed_state,source_timestamp,created_at,integrity_hash FROM identity_evidence WHERE organization_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, getSession(r).OrganizationID, limit, offset)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	writeRows(w, rows, []string{"id", "connectorId", "personId", "identityAccountId", "lifecycleCaseId", "actionId", "type", "summary", "observedState", "sourceTimestamp", "createdAt", "integrityHash"})
}
func writeRows(w http.ResponseWriter, rows pgx.Rows, keys []string) {
	items := []map[string]any{}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			writeError(w, 500, "QUERY_FAILED", "The records could not be read.", "")
			return
		}
		item := map[string]any{}
		for i, k := range keys {
			item[k] = normalizeDBValue(values[i])
		}
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func normalizeDBValue(value any) any {
	switch typed := value.(type) {
	case [16]byte:
		return uuid.UUID(typed).String()
	case []byte:
		if json.Valid(typed) {
			var decoded any
			if json.Unmarshal(typed, &decoded) == nil {
				return decoded
			}
		}
		return string(typed)
	default:
		return value
	}
}
func (s *Server) lifecycleError(w http.ResponseWriter, r *http.Request, err error) {
	if strings.Contains(err.Error(), "FORBIDDEN_STATE") {
		writeError(w, 409, "FORBIDDEN_STATE", "The lifecycle case is not in the required state.", requestID(r))
		return
	}
	s.internal(w, r, err)
}
func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Error("request failed", "requestId", requestID(r), "error", err.Error())
	writeError(w, 500, "INTERNAL_ERROR", "The request could not be completed.", requestID(r))
}
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, 400, "INVALID_JSON", "The request body is invalid.", requestID(r))
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, 400, "INVALID_JSON", "Only one JSON value is allowed.", requestID(r))
		return false
	}
	return true
}
func pagination(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
func requestID(r *http.Request) string { v, _ := r.Context().Value(requestIDKey).(string); return v }
func getSession(r *http.Request) database.Session {
	return r.Context().Value(sessionKey).(database.Session)
}
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func contains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message, "requestId": requestID}})
}
