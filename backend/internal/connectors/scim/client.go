package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type User struct {
	ID          string `json:"id"`
	ExternalID  string `json:"externalId"`
	UserName    string `json:"userName"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
	Emails      []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
	Meta struct {
		LastModified time.Time `json:"lastModified"`
	} `json:"meta"`
}
type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}
type listResponse[T any] struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
	Resources    []T `json:"Resources"`
}
type Client struct {
	origin      *url.URL
	token       string
	http        *http.Client
	maxRetries  int
	maxResponse int64
}

func blockedEndpointHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "metadata.google.internal" || host == "metadata.azure.com" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
	}
	return false
}

func restrictedDialer(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || blockedEndpointHost(host) {
			return nil, errors.New("SCIM destination is not permitted")
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if blockedEndpointHost(ip.String()) {
				continue
			}
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			err = dialErr
		}
		if err == nil {
			err = errors.New("SCIM host resolved only to blocked addresses")
		}
		return nil, err
	}
}

func New(baseURL, token string, allowHTTP bool, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid SCIM base URL")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("SCIM base URL must use HTTPS")
	}
	host := strings.ToLower(u.Hostname())
	if blockedEndpointHost(host) {
		return nil, errors.New("link-local and metadata endpoints are blocked")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: restrictedDialer(5 * time.Second), TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: timeout, MaxIdleConnsPerHost: 4}
	c := &Client{origin: u, token: token, maxRetries: 3, maxResponse: 4 << 20}
	c.http = &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != u.Scheme || !strings.EqualFold(req.URL.Host, u.Host) {
			return errors.New("cross-origin redirect blocked")
		}
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return nil
	}}
	return c, nil
}
func (c *Client) endpoint(path string) string {
	u := *c.origin
	parts := strings.SplitN(path, "?", 2)
	u.Path = strings.TrimRight(c.origin.Path, "/") + parts[0]
	u.RawQuery = ""
	if len(parts) == 2 {
		u.RawQuery = parts[1]
	}
	return u.String()
}
func (c *Client) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	var last error
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), bytes.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Accept", "application/scim+json")
		if body != nil {
			req.Header.Set("Content-Type", "application/scim+json")
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			last = err
		} else {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, c.maxResponse+1))
			resp.Body.Close()
			if readErr != nil {
				return nil, resp.StatusCode, readErr
			}
			if int64(len(data)) > c.maxResponse {
				return nil, resp.StatusCode, errors.New("SCIM response exceeds size limit")
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return data, resp.StatusCode, nil
			}
			last = fmt.Errorf("SCIM provider returned %d", resp.StatusCode)
			if resp.StatusCode != 429 && resp.StatusCode < 500 {
				return nil, resp.StatusCode, last
			}
			if wait := retryAfter(resp.Header.Get("Retry-After")); wait > 0 {
				select {
				case <-ctx.Done():
					return nil, 0, ctx.Err()
				case <-time.After(wait):
				}
			}
		}
		if attempt+1 < c.maxRetries {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 100 * time.Millisecond):
			}
		}
	}
	return nil, 0, last
}
func retryAfter(v string) time.Duration {
	if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 30 {
		return time.Duration(n) * time.Second
	}
	return 0
}
func (c *Client) ListUsers(ctx context.Context, pageSize int) ([]User, error) {
	if pageSize < 1 || pageSize > 200 {
		pageSize = 100
	}
	all := []User{}
	for start, pages := 1, 0; ; pages++ {
		if pages >= 100 {
			return nil, errors.New("SCIM user pagination exceeded safety limit")
		}
		raw, _, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/Users?startIndex=%d&count=%d", start, pageSize), nil)
		if err != nil {
			return nil, err
		}
		var page listResponse[User]
		if err = json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("decode SCIM users: %w", err)
		}
		all = append(all, page.Resources...)
		if len(page.Resources) == 0 || len(all) >= page.TotalResults {
			break
		}
		start += len(page.Resources)
	}
	return all, nil
}
func (c *Client) GetUser(ctx context.Context, id string) (User, error) {
	if !safeID(id) {
		return User{}, errors.New("invalid SCIM user id")
	}
	raw, _, err := c.request(ctx, http.MethodGet, "/Users/"+url.PathEscape(id), nil)
	if err != nil {
		return User{}, err
	}
	var u User
	err = json.Unmarshal(raw, &u)
	return u, err
}
func (c *Client) DisableUser(ctx context.Context, id string) error {
	if !safeID(id) {
		return errors.New("invalid SCIM user id")
	}
	patch := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	_, _, err := c.request(ctx, http.MethodPatch, "/Users/"+url.PathEscape(id), patch)
	return err
}

// TestConnection performs one bounded read against the expected SCIM Users
// endpoint. It never follows arbitrary paths and never attempts a write.
func (c *Client) TestConnection(ctx context.Context) error {
	raw, _, err := c.request(ctx, http.MethodGet, "/Users?startIndex=1&count=1", nil)
	if err != nil {
		return err
	}
	var page listResponse[User]
	if err = json.Unmarshal(raw, &page); err != nil {
		return fmt.Errorf("decode SCIM connection test: %w", err)
	}
	return nil
}
func (c *Client) ListGroups(ctx context.Context, pageSize int) ([]Group, error) {
	if pageSize < 1 || pageSize > 200 {
		pageSize = 100
	}
	all := []Group{}
	for start, pages := 1, 0; ; pages++ {
		if pages >= 100 {
			return nil, errors.New("SCIM group pagination exceeded safety limit")
		}
		raw, _, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/Groups?startIndex=%d&count=%d", start, pageSize), nil)
		if err != nil {
			return nil, err
		}
		var page listResponse[Group]
		if err = json.Unmarshal(raw, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Resources...)
		if len(page.Resources) == 0 || len(all) >= page.TotalResults {
			break
		}
		start += len(page.Resources)
	}
	return all, nil
}
func safeID(v string) bool { return v != "" && !strings.ContainsAny(v, "/?#\\") }
