package ldapconnector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type Config struct {
	URL, BindDN, Password, SearchBase, UserFilter, GroupFilter string
	PageSize                                                   uint32
	Timeout                                                    time.Duration
	ServerName                                                 string
	DisableStrategy                                            string
	MembershipAttribute                                        string
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
		r.conn.SetTimeout(c.cfg.Timeout)
		return r.conn, nil
	}
}
func (c *Client) SearchUsers(ctx context.Context) ([]Entry, error) {
	return c.search(ctx, c.cfg.UserFilter, []string{"uid", "cn", "mail", "employeeNumber", "description", "pwdAccountLockedTime", "userAccountControl", "modifyTimestamp", "objectClass"})
}

func (c *Client) GetUser(ctx context.Context, userDN string) (Entry, error) {
	if _, err := ldap.ParseDN(userDN); err != nil {
		return Entry{}, errors.New("invalid LDAP user DN")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return Entry{}, err
	}
	defer conn.Close()
	request := ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(c.cfg.Timeout.Seconds()), false, "(objectClass=*)", []string{"uid", "cn", "mail", "employeeNumber", "description", "pwdAccountLockedTime", "userAccountControl", "modifyTimestamp"}, nil)
	result, err := conn.Search(request)
	if err != nil {
		return Entry{}, err
	}
	if len(result.Entries) != 1 {
		return Entry{}, errors.New("LDAP user was not returned")
	}
	values := map[string][]string{}
	for _, attribute := range result.Entries[0].Attributes {
		values[attribute.Name] = append([]string(nil), attribute.Values...)
	}
	return Entry{DN: result.Entries[0].DN, Attributes: values}, nil
}

func IsDisabled(entry Entry) bool {
	for name, values := range entry.Attributes {
		if strings.EqualFold(name, "pwdAccountLockedTime") && len(values) > 0 && values[0] != "" {
			return true
		}
		if strings.EqualFold(name, "description") && len(values) > 0 && strings.EqualFold(values[0], "DISABLED") {
			return true
		}
		if strings.EqualFold(name, "userAccountControl") && len(values) > 0 {
			value, err := strconv.Atoi(values[0])
			if err == nil && value&2 != 0 {
				return true
			}
		}
	}
	return false
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

// DisableUser performs one of two explicit, reversible directory lock
// operations. The strategy is administrative connector configuration; callers
// cannot submit arbitrary attributes or LDAP modifications.
func (c *Client) DisableUser(ctx context.Context, userDN string) error {
	if _, err := ldap.ParseDN(userDN); err != nil {
		return errors.New("invalid LDAP user DN")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	switch c.cfg.DisableStrategy {
	case "PPOLICY_LOCK":
		request := ldap.NewModifyRequest(userDN, nil)
		request.Replace("pwdAccountLockedTime", []string{time.Now().UTC().Format("20060102150405Z")})
		return conn.Modify(request)
	case "ACTIVE_DIRECTORY_UAC":
		search := ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(c.cfg.Timeout.Seconds()), false, "(objectClass=*)", []string{"userAccountControl"}, nil)
		result, searchErr := conn.Search(search)
		if searchErr != nil || len(result.Entries) != 1 {
			if searchErr != nil {
				return searchErr
			}
			return errors.New("LDAP userAccountControl could not be read")
		}
		current, parseErr := strconv.Atoi(result.Entries[0].GetAttributeValue("userAccountControl"))
		if parseErr != nil {
			return errors.New("LDAP userAccountControl is malformed")
		}
		request := ldap.NewModifyRequest(userDN, nil)
		request.Replace("userAccountControl", []string{strconv.Itoa(current | 2)})
		return conn.Modify(request)
	default:
		return errors.New("LDAP connector has no supported disable strategy")
	}
}

func (c *Client) RemoveMembership(ctx context.Context, groupDN, userDN string) error {
	if _, err := ldap.ParseDN(groupDN); err != nil {
		return errors.New("invalid LDAP group DN")
	}
	parsedUser, err := ldap.ParseDN(userDN)
	if err != nil {
		return errors.New("invalid LDAP user DN")
	}
	attribute := c.cfg.MembershipAttribute
	if attribute == "" {
		attribute = "member"
	}
	if attribute != "member" && attribute != "uniqueMember" && attribute != "memberUid" {
		return errors.New("unsupported LDAP membership attribute")
	}
	value := userDN
	if attribute == "memberUid" {
		value = ""
		for _, rdn := range parsedUser.RDNs {
			for _, part := range rdn.Attributes {
				if strings.EqualFold(part.Type, "uid") {
					value = part.Value
				}
			}
		}
		if value == "" {
			return errors.New("LDAP user DN has no uid for memberUid removal")
		}
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	request := ldap.NewModifyRequest(groupDN, nil)
	request.Delete(attribute, []string{value})
	err = conn.Modify(request)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
		return nil
	}
	return err
}
