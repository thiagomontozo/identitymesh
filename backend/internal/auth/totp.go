package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

func NewTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}
func VerifyTOTP(secret, code string, now time.Time) bool {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(code) != 6 {
		return false
	}
	counter := now.Unix() / 30
	for skew := -1; skew <= 1; skew++ {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(counter+int64(skew)))
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(buf)
		sum := mac.Sum(nil)
		offset := sum[len(sum)-1] & 0x0f
		value := (uint32(sum[offset])&0x7f)<<24 | (uint32(sum[offset+1])&0xff)<<16 | (uint32(sum[offset+2])&0xff)<<8 | (uint32(sum[offset+3]) & 0xff)
		if fmt.Sprintf("%06d", value%1000000) == code {
			return true
		}
	}
	return false
}
