package ldapconnector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type Config struct {
	URL, BindDN, Password, SearchBase, UserFilter, GroupFilter string
	PageSize                                                   uint32
	Timeout                                                    time.Duration
	ServerName                                                 string
}
type Entry struct {
	DN         string
	Attributes map[string][]string
}
type Client struct{ cfg Config }

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return nil, errors.New("LDAP URL must use ldap or ldaps")
	}
	if cfg.SearchBase == "" || !safeFilter(cfg.UserFilter) || !safeFilter(cfg.GroupFilter) {
		return nil, errors.New("invalid administrative LDAP search configuration")
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 200
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Client{cfg: cfg}, nil
}

// TestConnection validates dialing and bind credentials without performing discovery.
func (c *Client) TestConnection(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
func safeFilter(v string) bool {
	return v != "" && strings.HasPrefix(v, "(") && strings.HasSuffix(v, ")") && !strings.ContainsAny(v, "\x00\r\n")
}
func (c *Client) dial(ctx context.Context) (*ldap.Conn, error) {
	type result struct {
		conn *ldap.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: c.cfg.Timeout})}
		if strings.HasPrefix(c.cfg.URL, "ldaps://") {
			opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.cfg.ServerName}))
		}
		conn, err := ldap.DialURL(c.cfg.URL, opts...)
		ch <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if err := r.conn.Bind(c.cfg.BindDN, c.cfg.Password); err != nil {
			r.conn.Close()
			return nil, err
		}
		return r.conn, nil
	}
}
func (c *Client) SearchUsers(ctx context.Context) ([]Entry, error) {
	return c.search(ctx, c.cfg.UserFilter, []string{"uid", "cn", "mail", "employeeNumber", "description", "pwdAccountLockedTime", "modifyTimestamp", "objectClass"})
}
func (c *Client) SearchGroups(ctx context.Context) ([]Entry, error) {
	return c.search(ctx, c.cfg.GroupFilter, []string{"cn", "description", "member", "uniqueMember", "memberUid", "modifyTimestamp"})
}
func (c *Client) search(ctx context.Context, filter string, attrs []string) ([]Entry, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	request := ldap.NewSearchRequest(c.cfg.SearchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(c.cfg.Timeout.Seconds()), false, filter, attrs, nil)
	result, err := conn.SearchWithPaging(request, c.cfg.PageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}
	out := make([]Entry, 0, len(result.Entries))
	for _, e := range result.Entries {
		m := map[string][]string{}
		for _, a := range e.Attributes {
			m[a.Name] = append([]string(nil), a.Values...)
		}
		out = append(out, Entry{DN: e.DN, Attributes: m})
	}
	return out, nil
}
