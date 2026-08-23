package httpapi

import (
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeDBValue(t *testing.T) {
	want := "ce2f8f63-23b5-41ee-a26c-a5a7544faa15"
	parsed := uuid.MustParse(want)
	if got := normalizeDBValue([16]byte(parsed)); got != want {
		t.Fatalf("UUID was not normalized: %v", got)
	}
	decoded, ok := normalizeDBValue([]byte(`{"status":"VERIFIED"}`)).(map[string]any)
	if !ok || decoded["status"] != "VERIFIED" {
		t.Fatalf("JSONB was not normalized: %#v", decoded)
	}
}
