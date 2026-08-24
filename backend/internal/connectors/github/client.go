package githubconnector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/nativehttp"
	"github.com/thiagomontozo/identitymesh/backend/internal/connectors/provider"
)

type Client struct {
	http         *nativehttp.Client
	organization string
}

func New(baseURL, token, organization string, allowHTTP bool, timeout time.Duration) (*Client, error) {
	if token == "" || organization == "" || !nativehttp.SafeID(organization) {
		return nil, errors.New("GitHub token and organization are required")
	}
	headers := http.Header{"Authorization": {"Bearer " + token}, "Accept": {"application/vnd.github+json"}, "X-GitHub-Api-Version": {"2026-03-10"}}
	c, err := nativehttp.New(baseURL, headers, allowHTTP, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{http: c, organization: organization}, nil
}

type githubUser struct {
	ID                       int64
	Login, Name, Email, Type string
	SiteAdmin                bool
}
type githubTeam struct {
	ID         int64
	Name, Slug string
}

func next(header http.Header) string {
	for _, part := range strings.Split(header.Get("Link"), ",") {
		pieces := strings.Split(part, ";")
		if len(pieces) == 2 && strings.TrimSpace(pieces[1]) == `rel="next"` {
			return strings.Trim(strings.TrimSpace(pieces[0]), "<>")
		}
	}
	return ""
}
func (c *Client) TestConnection(ctx context.Context) error {
	_, err := c.http.Do(ctx, http.MethodGet, "/orgs/"+url.PathEscape(c.organization)+"/members?per_page=1", nil)
	return err
}
func (c *Client) ListUsers(ctx context.Context) ([]provider.User, error) {
	path := "/orgs/" + url.PathEscape(c.organization) + "/members?per_page=100"
	var out []provider.User
	for pages := 0; path != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("GitHub pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var users []githubUser
		if json.Unmarshal(resp.Body, &users) != nil {
			return nil, errors.New("GitHub returned malformed members")
		}
		for _, u := range users {
			out = append(out, provider.User{ID: strconv.FormatInt(u.ID, 10), Username: u.Login, DisplayName: u.Name, PrimaryEmail: strings.ToLower(u.Email), Active: true, Privileged: u.SiteAdmin})
		}
		path = next(resp.Header)
	}
	return out, nil
}
func (c *Client) ListGroups(ctx context.Context) ([]provider.Group, error) {
	path := "/orgs/" + url.PathEscape(c.organization) + "/teams?per_page=100"
	var out []provider.Group
	for pages := 0; path != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("GitHub team pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var teams []githubTeam
		if json.Unmarshal(resp.Body, &teams) != nil {
			return nil, errors.New("GitHub returned malformed teams")
		}
		for _, team := range teams {
			members, e := c.members(ctx, team.Slug)
			if e != nil {
				return nil, e
			}
			out = append(out, provider.Group{ID: strconv.FormatInt(team.ID, 10), Name: team.Name, Members: members})
		}
		path = next(resp.Header)
	}
	return out, nil
}
func (c *Client) members(ctx context.Context, slug string) ([]string, error) {
	if !nativehttp.SafeID(slug) {
		return nil, errors.New("invalid GitHub team slug")
	}
	path := "/orgs/" + url.PathEscape(c.organization) + "/teams/" + url.PathEscape(slug) + "/members?per_page=100"
	var out []string
	for pages := 0; path != ""; pages++ {
		if pages >= 100 {
			return nil, errors.New("GitHub membership pagination exceeded safety limit")
		}
		resp, err := c.http.Do(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		var users []githubUser
		if json.Unmarshal(resp.Body, &users) != nil {
			return nil, errors.New("GitHub returned malformed team members")
		}
		for _, u := range users {
			out = append(out, strconv.FormatInt(u.ID, 10))
		}
		path = next(resp.Header)
	}
	return out, nil
}
func (c *Client) GetUser(ctx context.Context, id string) (provider.User, error) {
	if !nativehttp.SafeID(id) {
		return provider.User{}, errors.New("invalid GitHub user id")
	}
	var login string
	if _, err := strconv.ParseInt(id, 10, 64); err == nil {
		resp, e := c.http.Do(ctx, http.MethodGet, "/user/"+url.PathEscape(id), nil)
		if e != nil {
			return provider.User{}, e
		}
		var u githubUser
		if json.Unmarshal(resp.Body, &u) != nil {
			return provider.User{}, errors.New("GitHub returned malformed user")
		}
		login = u.Login
	} else {
		login = id
	}
	resp, err := c.http.Do(ctx, http.MethodGet, "/orgs/"+url.PathEscape(c.organization)+"/memberships/"+url.PathEscape(login), nil)
	if err != nil {
		return provider.User{}, err
	}
	var membership struct {
		State string
		User  githubUser
	}
	if json.Unmarshal(resp.Body, &membership) != nil {
		return provider.User{}, errors.New("GitHub returned malformed membership")
	}
	u := membership.User
	if u.Login == "" {
		u.Login = login
	}
	return provider.User{ID: fmt.Sprint(u.ID), Username: u.Login, DisplayName: u.Name, PrimaryEmail: strings.ToLower(u.Email), Active: membership.State == "active", Privileged: u.SiteAdmin}, nil
}
func (c *Client) DisableUser(ctx context.Context, id string) error {
	return c.RemoveMembership(ctx, "", id)
}
func (c *Client) RemoveMembership(ctx context.Context, _ string, userID string) error {
	u, err := c.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if !u.Active {
		return nil
	}
	_, err = c.http.Do(ctx, http.MethodDelete, "/orgs/"+url.PathEscape(c.organization)+"/members/"+url.PathEscape(u.Username), nil)
	return err
}
