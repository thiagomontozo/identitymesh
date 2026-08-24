package okta

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/nativehttp"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/provider"
)

type Client struct{ http *nativehttp.Client }

func New(baseURL, token string, allowHTTP bool, timeout time.Duration) (*Client, error) {
	if token == "" {
		return nil, errors.New("Okta API token is required")
	}
	headers := http.Header{"Authorization": {"SSWS " + token}, "Accept": {"application/json"}}
	c, err := nativehttp.New(baseURL, headers, allowHTTP, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{http: c}, nil
}

type oktaUser struct {
	ID, Status, LastUpdated string
	Profile                 struct{ Login, Email, DisplayName, FirstName, LastName, EmployeeNumber string }
}
type oktaGroup struct {
	ID      string
	Profile struct{ Name, Description string }
}

func active(status string) bool { return status != "SUSPENDED" && status != "DEPROVISIONED" }
func nextLink(header http.Header) string {
	for _, part := range strings.Split(header.Get("Link"), ",") {
		pieces := strings.Split(part, ";")
		if len(pieces) == 2 && strings.TrimSpace(pieces[1]) == `rel="next"` {
			return strings.Trim(strings.TrimSpace(pieces[0]), "<>")
		}
	}
	return ""
}
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.http.Do(ctx, http.MethodGet, "/api/v1/users?limit=1", nil)
	return err
}
func (c *Client) ListUsers(ctx context.Context) ([]provider.User, error) {
	next := "/api/v1/users?limit=200"
	var out []provider.User
	for pages := 0; next != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("Okta pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var users []oktaUser
		if json.Unmarshal(resp.Body, &users) != nil {
			return nil, errors.New("Okta returned malformed users")
		}
		for _, user := range users {
			name := user.Profile.DisplayName
			if name == "" {
				name = strings.TrimSpace(user.Profile.FirstName + " " + user.Profile.LastName)
			}
			updated, _ := time.Parse(time.RFC3339, user.LastUpdated)
			out = append(out, provider.User{ID: user.ID, Username: user.Profile.Login, DisplayName: name, PrimaryEmail: strings.ToLower(user.Profile.Email), EmployeeNumber: user.Profile.EmployeeNumber, Active: active(user.Status), UpdatedAt: updated})
		}
		next = nextLink(resp.Header)
	}
	return out, nil
}
func (c *Client) ListGroups(ctx context.Context) ([]provider.Group, error) {
	next := "/api/v1/groups?limit=200"
	var out []provider.Group
	for pages := 0; next != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("Okta group pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var groups []oktaGroup
		if json.Unmarshal(resp.Body, &groups) != nil {
			return nil, errors.New("Okta returned malformed groups")
		}
		for _, g := range groups {
			members, memberErr := c.groupMembers(ctx, g.ID)
			if memberErr != nil {
				return nil, memberErr
			}
			out = append(out, provider.Group{ID: g.ID, Name: g.Profile.Name, Members: members})
		}
		next = nextLink(resp.Header)
	}
	return out, nil
}
func (c *Client) groupMembers(ctx context.Context, id string) ([]string, error) {
	if !nativehttp.SafeID(id) {
		return nil, errors.New("invalid Okta group id")
	}
	next := "/api/v1/groups/" + url.PathEscape(id) + "/users?limit=200"
	var out []string
	for pages := 0; next != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("Okta membership pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var users []oktaUser
		if json.Unmarshal(resp.Body, &users) != nil {
			return nil, errors.New("Okta returned malformed memberships")
		}
		for _, u := range users {
			out = append(out, u.ID)
		}
		next = nextLink(resp.Header)
	}
	return out, nil
}
func (c *Client) GetUser(ctx context.Context, id string) (provider.User, error) {
	if !nativehttp.SafeID(id) {
		return provider.User{}, errors.New("invalid Okta user id")
	}
	resp, err := c.http.Do(ctx, http.MethodGet, "/api/v1/users/"+url.PathEscape(id), nil)
	if err != nil {
		return provider.User{}, err
	}
	var u oktaUser
	if json.Unmarshal(resp.Body, &u) != nil {
		return provider.User{}, errors.New("Okta returned malformed user")
	}
	return provider.User{ID: u.ID, Username: u.Profile.Login, DisplayName: u.Profile.DisplayName, PrimaryEmail: strings.ToLower(u.Profile.Email), EmployeeNumber: u.Profile.EmployeeNumber, Active: active(u.Status)}, nil
}
func (c *Client) DisableUser(ctx context.Context, id string) error {
	u, err := c.GetUser(ctx, id)
	if err != nil || !u.Active {
		return err
	}
	_, err = c.http.Do(ctx, http.MethodPost, "/api/v1/users/"+url.PathEscape(id)+"/lifecycle/suspend", nil)
	return err
}
