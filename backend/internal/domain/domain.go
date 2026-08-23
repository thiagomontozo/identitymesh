package domain

import "time"

type LifecycleStatus string

const (
	PreHire    LifecycleStatus = "PRE_HIRE"
	Active     LifecycleStatus = "ACTIVE"
	Leave      LifecycleStatus = "LEAVE"
	Suspended  LifecycleStatus = "SUSPENDED"
	Terminated LifecycleStatus = "TERMINATED"
	Unknown    LifecycleStatus = "UNKNOWN"
)

type VerificationStatus string

const (
	Verified          VerificationStatus = "VERIFIED"
	PartiallyVerified VerificationStatus = "PARTIALLY_VERIFIED"
	Failed            VerificationStatus = "FAILED"
	Inconclusive      VerificationStatus = "INCONCLUSIVE"
)

type Person struct {
	ID, OrganizationID, ExternalPersonID, DisplayName, PrimaryEmail, EmployeeNumber, Department string
	Status                                                                                      LifecycleStatus
	CreatedAt, UpdatedAt                                                                        time.Time
}
type IdentityAccount struct {
	ID, OrganizationID, ConnectorID, ExternalAccountID, Username, DisplayName, PrimaryEmail, EmployeeNumber, ActiveStatus, AccountType string
	Privileged                                                                                                                         bool
	FirstSeenAt, LastSeenAt                                                                                                            time.Time
}
type IdentityLink struct {
	ID, OrganizationID, PersonID, IdentityAccountID, LinkType, Confidence, Reason, CreatedBy string
	CreatedAt                                                                                time.Time
}
type CorrelationCandidate struct {
	ID, OrganizationID, PersonID, IdentityAccountID, Confidence string
	Reasons                                                     []string
	Status                                                      string
}

type ConnectorCapabilities struct{ DiscoverUsers, DiscoverGroups, DiscoverMemberships, DiscoverEntitlements, DisableAccount, EnableAccount, RemoveMembership, AddMembership bool }
type Connector struct {
	ID, OrganizationID, Name, Type, BaseURL, Environment, CredentialReference string
	Enabled, ReadEnabled, WriteEnabled                                        bool
	Capabilities                                                              ConnectorCapabilities
	LastSyncStatus                                                            string
	LastSyncAt                                                                *time.Time
}

type LifecycleCase struct {
	ID, OrganizationID, PersonID, RequestedBy, Status string
	EffectiveAt                                       *time.Time
	CreatedAt                                         time.Time
	VerificationStatus                                VerificationStatus
	Summary                                           string
}
type LifecycleAction struct {
	ID, OrganizationID, CaseID, ConnectorID, IdentityAccountID, ActionType, Status, DesiredState, IdempotencyKey string
	AttemptCount                                                                                                 int
	ErrorCode, Summary                                                                                           string
}
type VerificationInput struct {
	Managed, Disabled, Active, Unresolved, Manual, SystemsFailed int
	RequiredSystemsResponded                                     bool
}

func EvaluateVerification(v VerificationInput) VerificationStatus {
	if v.SystemsFailed > 0 || !v.RequiredSystemsResponded {
		return Inconclusive
	}
	if v.Active > 0 {
		return Failed
	}
	if v.Unresolved > 0 || v.Manual > 0 || v.Disabled < v.Managed {
		return PartiallyVerified
	}
	return Verified
}

func CanTransitionCase(from, to string) bool {
	allowed := map[string]map[string]bool{
		"DRAFT":             {"PLANNED": true, "CANCELLED": true},
		"PLANNED":           {"AWAITING_APPROVAL": true, "CANCELLED": true},
		"AWAITING_APPROVAL": {"APPROVED": true, "CANCELLED": true},
		"APPROVED":          {"RUNNING": true, "CANCELLED": true},
		"RUNNING":           {"VERIFYING": true, "FAILED": true, "PARTIAL": true},
		"VERIFYING":         {"COMPLETED": true, "FAILED": true, "PARTIAL": true},
	}
	return allowed[from][to]
}
