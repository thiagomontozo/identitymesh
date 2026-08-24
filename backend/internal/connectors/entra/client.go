package entra

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
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("Entra access token is required")
	}
	headers := http.Header{"Authorization": {"Bearer " + token}, "Accept": {"application/json"}}
	c, err := nativehttp.New(baseURL, headers, allowHTTP, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{http: c}, nil
}

type graphUser struct {
	ID, UserPrincipalName, DisplayName, Mail, EmployeeID string
	AccountEnabled                                       bool
}
type userPage struct {
	Value    []graphUser `json:"value"`
	NextLink string      `json:"@odata.nextLink"`
}
type graphGroup struct{ ID, DisplayName string }
type groupPage struct {
	Value    []graphGroup `json:"value"`
	NextLink string       `json:"@odata.nextLink"`
}
type memberPage struct {
	Value []struct{ ID string } `json:"value"`
	Next  string                `json:"@odata.nextLink"`
}

func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.http.Do(ctx, http.MethodGet, "/v1.0/users?$select=id&$top=1", nil)
	return err
}
func (c *Client) ListUsers(ctx context.Context) ([]provider.User, error) {
	next := "/v1.0/users?$select=id,userPrincipalName,displayName,mail,accountEnabled,employeeId&$top=999"
	var out []provider.User
	for pages := 0; next != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("Entra pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var page userPage
		if err = json.Unmarshal(resp.Body, &page); err != nil {
			return nil, errors.New("Entra returned malformed users")
		}
		for _, user := range page.Value {
			email := user.Mail
			if email == "" {
				email = user.UserPrincipalName
			}
			out = append(out, provider.User{ID: user.ID, Username: user.UserPrincipalName, DisplayName: user.DisplayName, PrimaryEmail: strings.ToLower(email), EmployeeNumber: user.EmployeeID, Active: user.AccountEnabled})
		}
		next = page.NextLink
	}
	return out, nil
}
func (c *Client) ListGroups(ctx context.Context) ([]provider.Group, error) {
	next := "/v1.0/groups?$select=id,displayName&$top=999"
	var out []provider.Group
	for pages := 0; next != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("Entra group pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var page groupPage
		if err = json.Unmarshal(resp.Body, &page); err != nil {
			return nil, errors.New("Entra returned malformed groups")
		}
		for _, group := range page.Value {
			members, memberErr := c.members(ctx, group.ID)
			if memberErr != nil {
				return nil, memberErr
			}
			out = append(out, provider.Group{ID: group.ID, Name: group.DisplayName, Members: members})
		}
		next = page.NextLink
	}
	return out, nil
}
func (c *Client) members(ctx context.Context, groupID string) ([]string, error) {
	if !nativehttp.SafeID(groupID) {
		return nil, errors.New("invalid Entra group id")
	}
	next := "/v1.0/groups/" + url.PathEscape(groupID) + "/members?$select=id&$top=999"
	var out []string
	for pages := 0; next != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("Entra membership pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		var page memberPage
		if err = json.Unmarshal(resp.Body, &page); err != nil {
			return nil, errors.New("Entra returned malformed memberships")
		}
		for _, member := range page.Value {
			out = append(out, member.ID)
		}
		next = page.Next
	}
	return out, nil
}
func (c *Client) GetUser(ctx context.Context, id string) (provider.User, error) {
	if !nativehttp.SafeID(id) {
		return provider.User{}, errors.New("invalid Entra user id")
	}
	resp, err := c.http.Do(ctx, http.MethodGet, "/v1.0/users/"+url.PathEscape(id)+"?$select=id,userPrincipalName,displayName,mail,accountEnabled,employeeId", nil)
	if err != nil {
		return provider.User{}, err
	}
	var user graphUser
	if err = json.Unmarshal(resp.Body, &user); err != nil {
		return provider.User{}, errors.New("Entra returned malformed user")
	}
	return provider.User{ID: user.ID, Username: user.UserPrincipalName, DisplayName: user.DisplayName, PrimaryEmail: strings.ToLower(user.Mail), EmployeeNumber: user.EmployeeID, Active: user.AccountEnabled}, nil
}
func (c *Client) DisableUser(ctx context.Context, id string) error {
	user, err := c.GetUser(ctx, id)
	if err != nil || !user.Active {
		return err
	}
	_, err = c.http.Do(ctx, http.MethodPatch, "/v1.0/users/"+url.PathEscape(id), []byte(`{"accountEnabled":false}`))
	return err
}
