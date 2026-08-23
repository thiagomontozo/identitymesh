package domain

import "testing"

func TestVerificationHonestOutcomes(t *testing.T) {
	tests := []struct {
		name  string
		input VerificationInput
		want  VerificationStatus
	}{{"verified", VerificationInput{Managed: 3, Disabled: 3, RequiredSystemsResponded: true}, Verified}, {"active access fails", VerificationInput{Managed: 3, Disabled: 2, Active: 1, RequiredSystemsResponded: true}, Failed}, {"unreachable provider makes stale active state inconclusive", VerificationInput{Managed: 3, Disabled: 2, Active: 1, SystemsFailed: 1}, Inconclusive}, {"offline is inconclusive", VerificationInput{Managed: 3, Disabled: 3, SystemsFailed: 1}, Inconclusive}, {"unresolved is partial", VerificationInput{Managed: 3, Disabled: 3, Unresolved: 1, RequiredSystemsResponded: true}, PartiallyVerified}, {"manual is partial", VerificationInput{Managed: 3, Disabled: 3, Manual: 1, RequiredSystemsResponded: true}, PartiallyVerified}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EvaluateVerification(tt.input); got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
		})
	}
}
func TestLifecycleStateMachineRequiresApproval(t *testing.T) {
	if CanTransitionCase("DRAFT", "APPROVED") {
		t.Fatal("draft case must not skip planning and approval")
	}
	if !CanTransitionCase("AWAITING_APPROVAL", "APPROVED") {
		t.Fatal("explicit approval transition should be valid")
	}
	if CanTransitionCase("PLANNED", "RUNNING") {
		t.Fatal("planned case must not execute")
	}
}
