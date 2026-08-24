package googleworkspace

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

type Client struct {
	http     *nativehttp.Client
	customer string
}

func New(baseURL, token, customer string, allowHTTP bool, timeout time.Duration) (*Client, error) {
	if token == "" {
		return nil, errors.New("Google Workspace access token is required")
	}
	if customer == "" {
		customer = "my_customer"
	}
	headers := http.Header{"Authorization": {"Bearer " + token}, "Accept": {"application/json"}}
	c, err := nativehttp.New(baseURL, headers, allowHTTP, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{http: c, customer: customer}, nil
}

type googleUser struct {
	ID, PrimaryEmail, LastLoginTime, CreationTime string
	Name                                          struct{ FullName string }
	Suspended, IsAdmin                            bool
	ExternalIDs                                   []struct{ Value, Type string }
}
type userPage struct {
	Users         []googleUser
	NextPageToken string
}
type googleGroup struct{ ID, Email, Name string }
type groupPage struct {
	Groups        []googleGroup
	NextPageToken string
}
type memberPage struct {
	Members       []struct{ ID, Email string }
	NextPageToken string
}

func employee(u googleUser) string {
	for _, v := range u.ExternalIDs {
		if strings.EqualFold(v.Type, "organization") {
			return v.Value
		}
	}
	return ""
}
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.http.Do(ctx, http.MethodGet, "/admin/directory/v1/users?customer="+url.QueryEscape(c.customer)+"&maxResults=1", nil)
	return err
}
func (c *Client) ListUsers(ctx context.Context) ([]provider.User, error) {
	token := ""
	var out []provider.User
	for pages := 0; ; pages++ {
		if pages >= 100 {
			return nil, errors.New("Google Workspace pagination exceeded safety limit")
		}
		path := "/admin/directory/v1/users?customer=" + url.QueryEscape(c.customer) + "&maxResults=500&orderBy=email"
		if token != "" {
			path += "&pageToken=" + url.QueryEscape(token)
		}
		resp, err := c.http.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var page userPage
		if json.Unmarshal(resp.Body, &page) != nil {
			return nil, errors.New("Google Workspace returned malformed users")
		}
		for _, u := range page.Users {
			out = append(out, provider.User{ID: u.ID, Username: u.PrimaryEmail, DisplayName: u.Name.FullName, PrimaryEmail: strings.ToLower(u.PrimaryEmail), EmployeeNumber: employee(u), Active: !u.Suspended, Privileged: u.IsAdmin})
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	return out, nil
}
func (c *Client) ListGroups(ctx context.Context) ([]provider.Group, error) {
	token := ""
	var out []provider.Group
	for pages := 0; ; pages++ {
		if pages >= 100 {
			return nil, errors.New("Google Workspace group pagination exceeded safety limit")
		}
		path := "/admin/directory/v1/groups?customer=" + url.QueryEscape(c.customer) + "&maxResults=200"
		if token != "" {
			path += "&pageToken=" + url.QueryEscape(token)
		}
		resp, err := c.http.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var page groupPage
		if json.Unmarshal(resp.Body, &page) != nil {
			return nil, errors.New("Google Workspace returned malformed groups")
		}
		for _, g := range page.Groups {
			members, e := c.members(ctx, g.ID)
			if e != nil {
				return nil, e
			}
			out = append(out, provider.Group{ID: g.ID, Name: g.Name, Members: members})
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	return out, nil
}
func (c *Client) members(ctx context.Context, id string) ([]string, error) {
	if !nativehttp.SafeID(id) {
		return nil, errors.New("invalid Google group id")
	}
	token := ""
	var out []string
	for pages := 0; ; pages++ {
		if pages >= 100 {
			return nil, errors.New("Google membership pagination exceeded safety limit")
		}
		path := "/admin/directory/v1/groups/" + url.PathEscape(id) + "/members?maxResults=200"
		if token != "" {
			path += "&pageToken=" + url.QueryEscape(token)
		}
		resp, err := c.http.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var page memberPage
		if json.Unmarshal(resp.Body, &page) != nil {
			return nil, errors.New("Google Workspace returned malformed memberships")
		}
		for _, m := range page.Members {
			out = append(out, m.ID)
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	return out, nil
}
func (c *Client) GetUser(ctx context.Context, id string) (provider.User, error) {
	if !nativehttp.SafeID(id) {
		return provider.User{}, errors.New("invalid Google user id")
	}
	resp, err := c.http.Do(ctx, http.MethodGet, "/admin/directory/v1/users/"+url.PathEscape(id), nil)
	if err != nil {
		return provider.User{}, err
	}
	var u googleUser
	if json.Unmarshal(resp.Body, &u) != nil {
		return provider.User{}, errors.New("Google Workspace returned malformed user")
	}
	return provider.User{ID: u.ID, Username: u.PrimaryEmail, DisplayName: u.Name.FullName, PrimaryEmail: strings.ToLower(u.PrimaryEmail), EmployeeNumber: employee(u), Active: !u.Suspended, Privileged: u.IsAdmin}, nil
}
func (c *Client) DisableUser(ctx context.Context, id string) error {
	u, err := c.GetUser(ctx, id)
	if err != nil || !u.Active {
		return err
	}
	_, err = c.http.Do(ctx, http.MethodPatch, "/admin/directory/v1/users/"+url.PathEscape(id), []byte(`{"suspended":true}`))
	return err
}
