package provider

import (
	"context"
	"time"
)

type User struct {
	ID, ExternalID, Username, DisplayName, PrimaryEmail, EmployeeNumber string
	Active, Privileged                                                  bool
	UpdatedAt                                                           time.Time
}

type Group struct {
	ID, Name string
	Members  []string
}

type Client interface {
	TestConnection(context.Context) error
	ListUsers(context.Context) ([]User, error)
	ListGroups(context.Context) ([]Group, error)
	GetUser(context.Context, string) (User, error)
	DisableUser(context.Context, string) error
}

type MembershipRemover interface {
	RemoveMembership(context.Context, string, string) error
}
