package chio

import (
	"encoding/json"
	"testing"
)

func TestChioToolCallRequestPreservesApprovalSetAndOpaqueExtension(t *testing.T) {
	request := ChioToolCallRequest{
		Type:     "tool_call_request",
		ID:       "request-go-1",
		ServerID: "server-go-1",
		Tool:     "execute",
		Params:   json.RawMessage(`{"amount":7}`),
		ApprovalTokens: []CapabilityGovernedApprovalToken{
			{Id: "approval-a"},
			{Id: "approval-b"},
		},
		ThresholdApprovalProposal: &CapabilityThresholdApprovalProposal{
			ProposalId: "proposal-go-1",
		},
		SupplementalAuthorization: &CapabilitySupplementalAuthorization{
			SignedExtension: "b3BhcXVl",
		},
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	var approvals []CapabilityGovernedApprovalToken
	if err := json.Unmarshal(decoded["approval_tokens"], &approvals); err != nil {
		t.Fatalf("unmarshal approvals: %v", err)
	}
	if len(approvals) != 2 || approvals[0].Id != "approval-a" || approvals[1].Id != "approval-b" {
		t.Fatalf("approval set changed: %#v", approvals)
	}
	var supplemental CapabilitySupplementalAuthorization
	if err := json.Unmarshal(decoded["supplemental_authorization"], &supplemental); err != nil {
		t.Fatalf("unmarshal supplemental authorization: %v", err)
	}
	if supplemental.SignedExtension != "b3BhcXVl" {
		t.Fatalf("supplemental authorization changed: %#v", supplemental)
	}
}
