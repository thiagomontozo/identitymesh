package secure

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type SecretStore interface {
	Encrypt([]byte) (string, error)
	Decrypt(string) ([]byte, error)
}

// HealthChecker is implemented by external secret stores that readiness can
// verify without disclosing or decrypting any application secret.
type HealthChecker interface {
	Health(context.Context) error
}
type AESGCMStore struct{ key []byte }

func NewAESGCMStore(key []byte) (*AESGCMStore, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256-GCM requires a 32-byte key")
	}
	return &AESGCMStore{key: append([]byte(nil), key...)}, nil
}
func (s *AESGCMStore) Encrypt(plain []byte) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(out), nil
}
func (s *AESGCMStore) Decrypt(encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("malformed ciphertext")
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("secret authentication failed")
	}
	return plain, nil
}

var vaultPathPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// VaultTransitStore delegates encryption to Vault Transit. IdentityMesh stores
// only the opaque vault:vN ciphertext. Vault can in turn be seal-wrapped by a
// KMS or PKCS#11 HSM without exposing those keys to this process.
type VaultTransitStore struct {
	origin    *url.URL
	token     string
	namespace string
	mount     string
	key       string
	client    *http.Client
}

func NewVaultTransitStore(address, token, namespace, mount, key string, allowHTTP bool, timeout time.Duration) (*VaultTransitStore, error) {
	u, err := url.Parse(address)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid Vault address")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return nil, errors.New("Vault address must use HTTPS")
	}
	if token == "" {
		return nil, errors.New("Vault token is required")
	}
	if mount == "" {
		mount = "transit"
	}
	if key == "" {
		key = "identitymesh"
	}
	if !vaultPathPart.MatchString(mount) || !vaultPathPart.MatchString(key) {
		return nil, errors.New("Vault mount and key must be safe path segments")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	u.Path = strings.TrimRight(u.Path, "/")
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   4,
	}
	s := &VaultTransitStore{origin: u, token: token, namespace: namespace, mount: mount, key: key}
	s.client = &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != u.Scheme || !strings.EqualFold(req.URL.Host, u.Host) {
			return errors.New("Vault cross-origin redirect blocked")
		}
		if len(via) >= 2 {
			return errors.New("too many Vault redirects")
		}
		return nil
	}}
	return s, nil
}

func (s *VaultTransitStore) endpoint(operation string) string {
	u := *s.origin
	u.Path = strings.TrimRight(s.origin.Path, "/") + "/v1/" + s.mount + "/" + operation + "/" + s.key
	return u.String()
}

func (s *VaultTransitStore) call(operation string, input map[string]string) (map[string]any, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), s.client.Timeout)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint(operation), bytes.NewReader(body))
		if reqErr != nil {
			cancel()
			return nil, reqErr
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Vault-Token", s.token)
		if s.namespace != "" {
			req.Header.Set("X-Vault-Namespace", s.namespace)
		}
		resp, doErr := s.client.Do(req)
		if doErr != nil {
			lastErr = doErr
			cancel()
		} else {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			cancel()
			if readErr != nil {
				return nil, readErr
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var decoded map[string]any
				if err = json.Unmarshal(data, &decoded); err != nil {
					return nil, errors.New("Vault returned malformed JSON")
				}
				return decoded, nil
			}
			lastErr = fmt.Errorf("Vault Transit returned status %d", resp.StatusCode)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				break
			}
		}
		if attempt == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	return nil, lastErr
}

func vaultDataString(response map[string]any, name string) (string, error) {
	data, ok := response["data"].(map[string]any)
	if !ok {
		return "", errors.New("Vault response is missing data")
	}
	value, ok := data[name].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("Vault response is missing %s", name)
	}
	return value, nil
}

func (s *VaultTransitStore) Encrypt(plain []byte) (string, error) {
	response, err := s.call("encrypt", map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plain)})
	if err != nil {
		return "", err
	}
	return vaultDataString(response, "ciphertext")
}

func (s *VaultTransitStore) Decrypt(ciphertext string) ([]byte, error) {
	if !strings.HasPrefix(ciphertext, "vault:v") {
		return nil, errors.New("malformed Vault ciphertext")
	}
	response, err := s.call("decrypt", map[string]string{"ciphertext": ciphertext})
	if err != nil {
		return nil, err
	}
	encoded, err := vaultDataString(response, "plaintext")
	if err != nil {
		return nil, err
	}
	plain, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("Vault returned malformed plaintext")
	}
	return plain, nil
}

func (s *VaultTransitStore) Health(ctx context.Context) error {
	u := *s.origin
	u.Path = strings.TrimRight(s.origin.Path, "/") + "/v1/sys/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 429 && resp.StatusCode != 472 && resp.StatusCode != 473 {
		return fmt.Errorf("Vault health returned status %d", resp.StatusCode)
	}
	return nil
}
