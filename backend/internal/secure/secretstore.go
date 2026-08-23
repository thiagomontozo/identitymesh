package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

type SecretStore interface {
	Encrypt([]byte) (string, error)
	Decrypt(string) ([]byte, error)
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
