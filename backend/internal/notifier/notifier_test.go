package notifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookIsSignedAndRejectsUnsafeSchemes(t *testing.T) {
	var signature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-IdentityMesh-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	n, err := NewWebhook(server.URL, "test-signing-secret", true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = n.Notify(context.Background(), Event{OrganizationID: "org", Type: "connector.sync_failed", Payload: map[string]any{"connectorId": "synthetic"}}); err != nil {
		t.Fatal(err)
	}
	if len(signature) < 20 {
		t.Fatal("signed webhook header missing")
	}
	if _, err = NewWebhook("file:///tmp/hook", "test-signing-secret", true, 0); err == nil {
		t.Fatal("unsafe webhook URL accepted")
	}
}
