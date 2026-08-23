package rbac

import "testing"

func TestViewerCannotExecuteLifecycle(t *testing.T) {
	if Allowed([]string{"VIEWER"}, "lifecycle.execute") {
		t.Fatal("viewer must not execute offboarding")
	}
	if !Allowed([]string{"SECURITY_ADMIN"}, "lifecycle.approve") {
		t.Fatal("security admin should approve")
	}
}
