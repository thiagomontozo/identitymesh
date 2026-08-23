package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	OrganizationID string         `json:"organizationId"`
	Type           string         `json:"type"`
	Payload        map[string]any `json:"payload"`
	OccurredAt     time.Time      `json:"occurredAt"`
}
type Notifier interface {
	Notify(context.Context, Event) error
}

type InApp struct{ DB *pgxpool.Pool }

func (n InApp) Notify(ctx context.Context, event Event) error {
	raw, err := json.Marshal(event.Payload)
	if err != nil {
		return err
	}
	_, err = n.DB.Exec(ctx, `INSERT INTO notifications(organization_id,type,channel,payload,status,delivered_at) VALUES($1,$2,'IN_APP',$3,'DELIVERED',now())`, event.OrganizationID, event.Type, raw)
	return err
}

type Webhook struct {
	endpoint *url.URL
	secret   []byte
	client   *http.Client
}

func NewWebhook(endpoint, secret string, allowHTTP bool, timeout time.Duration) (*Webhook, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid webhook endpoint")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("webhook endpoint must use HTTPS")
	}
	if len(secret) < 16 {
		return nil, errors.New("webhook signing secret must contain at least 16 bytes")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range addresses {
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
		}
		return nil, errors.New("webhook destination has no permitted address")
	}}
	client := &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &Webhook{endpoint: u, secret: []byte(secret), client: client}, nil
}
func (n *Webhook) Notify(ctx context.Context, event Event) error {
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, n.secret)
	_, _ = mac.Write(raw)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint.String(), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-IdentityMesh-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

type Fanout []Notifier

func (notifiers Fanout) Notify(ctx context.Context, event Event) error {
	var failures []error
	for _, n := range notifiers {
		if n != nil {
			if err := n.Notify(ctx, event); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}
