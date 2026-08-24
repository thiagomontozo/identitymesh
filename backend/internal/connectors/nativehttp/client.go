package nativehttp

import (
	"bytes"
	"context"
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

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

type Client struct {
	Origin      *url.URL
	HTTP        *http.Client
	Headers     http.Header
	MaxResponse int64
	MaxRetries  int
}

func blockedHost(host string) bool {
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
		if err != nil || blockedHost(host) {
			return nil, errors.New("provider destination is not permitted")
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		var dialErr error
		for _, ip := range ips {
			if blockedHost(ip.String()) {
				continue
			}
			conn, currentErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if currentErr == nil {
				return conn, nil
			}
			dialErr = currentErr
		}
		if dialErr == nil {
			dialErr = errors.New("provider host resolved only to blocked addresses")
		}
		return nil, dialErr
	}
}

func New(baseURL string, headers http.Header, allowHTTP bool, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid provider base URL")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("provider base URL must use HTTPS")
	}
	if blockedHost(u.Hostname()) {
		return nil, errors.New("link-local and metadata endpoints are blocked")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	u.Path = strings.TrimRight(u.Path, "/")
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: restrictedDialer(5 * time.Second), TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: timeout, MaxIdleConnsPerHost: 8}
	c := &Client{Origin: u, Headers: headers.Clone(), MaxResponse: 8 << 20, MaxRetries: 3}
	c.HTTP = &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != u.Scheme || !strings.EqualFold(req.URL.Host, u.Host) {
			return errors.New("provider cross-origin redirect blocked")
		}
		if len(via) >= 3 {
			return errors.New("too many provider redirects")
		}
		return nil
	}}
	return c, nil
}

func (c *Client) Resolve(pathOrURL string) (string, error) {
	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		u, err := url.Parse(pathOrURL)
		if err != nil || u.Scheme != c.Origin.Scheme || !strings.EqualFold(u.Host, c.Origin.Host) {
			return "", errors.New("provider pagination escaped configured origin")
		}
		return u.String(), nil
	}
	u := *c.Origin
	parts := strings.SplitN(pathOrURL, "?", 2)
	u.Path = strings.TrimRight(c.Origin.Path, "/") + "/" + strings.TrimLeft(parts[0], "/")
	u.RawQuery = ""
	if len(parts) == 2 {
		u.RawQuery = parts[1]
	}
	return u.String(), nil
}

func (c *Client) Do(ctx context.Context, method, pathOrURL string, body []byte) (Response, error) {
	endpoint, err := c.Resolve(pathOrURL)
	if err != nil {
		return Response{}, err
	}
	attempts := 1
	if method == http.MethodGet || method == http.MethodHead {
		attempts = c.MaxRetries
	}
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		req, reqErr := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
		if reqErr != nil {
			return Response{}, reqErr
		}
		for key, values := range c.Headers {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, doErr := c.HTTP.Do(req)
		if doErr != nil {
			last = doErr
		} else {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, c.MaxResponse+1))
			resp.Body.Close()
			if readErr != nil {
				return Response{}, readErr
			}
			if int64(len(data)) > c.MaxResponse {
				return Response{}, errors.New("provider response exceeds size limit")
			}
			result := Response{Status: resp.StatusCode, Header: resp.Header.Clone(), Body: data}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return result, nil
			}
			last = fmt.Errorf("provider returned status %d", resp.StatusCode)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return result, last
			}
			if wait := retryAfter(resp.Header.Get("Retry-After")); wait > 0 {
				select {
				case <-ctx.Done():
					return Response{}, ctx.Err()
				case <-time.After(wait):
				}
			}
		}
		if attempt+1 < attempts {
			select {
			case <-ctx.Done():
				return Response{}, ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 100 * time.Millisecond):
			}
		}
	}
	return Response{}, last
}

func retryAfter(value string) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 && seconds <= 30 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		wait := time.Until(when)
		if wait > 0 && wait <= 30*time.Second {
			return wait
		}
	}
	return 0
}

func SafeID(value string) bool {
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "/?#\\\x00\r\n")
}
