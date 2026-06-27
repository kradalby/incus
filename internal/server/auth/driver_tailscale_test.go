package auth

import (
	"testing"
)

func TestTailscaleGrantAllows(t *testing.T) {
	instDefault := ObjectInstance("default", "c1")
	instWeb := ObjectInstance("web", "c1")
	server := ObjectServer()

	tests := []struct {
		name        string
		grant       TailscaleGrant
		object      Object
		entitlement Entitlement
		want        bool
	}{
		{
			name:        "wildcard project admin allows anything",
			grant:       TailscaleGrant{Projects: []string{"*"}, Role: "admin"},
			object:      instDefault,
			entitlement: EntitlementCanEdit,
			want:        true,
		},
		{
			name:        "viewer role grants view but not edit",
			grant:       TailscaleGrant{Projects: []string{"default"}, Role: "viewer"},
			object:      instDefault,
			entitlement: EntitlementCanEdit,
			want:        false,
		},
		{
			name:        "viewer role grants view",
			grant:       TailscaleGrant{Projects: []string{"default"}, Role: "viewer"},
			object:      instDefault,
			entitlement: EntitlementCanView,
			want:        true,
		},
		{
			name:        "project scope is enforced",
			grant:       TailscaleGrant{Projects: []string{"default"}, Role: "operator"},
			object:      instWeb,
			entitlement: EntitlementCanEdit,
			want:        false,
		},
		{
			name:        "explicit entitlement is honoured",
			grant:       TailscaleGrant{Projects: []string{"default"}, Entitlements: []string{string(EntitlementCanEdit)}},
			object:      instDefault,
			entitlement: EntitlementCanEdit,
			want:        true,
		},
		{
			name:        "no role and no matching entitlement denies",
			grant:       TailscaleGrant{Projects: []string{"default"}},
			object:      instDefault,
			entitlement: EntitlementCanView,
			want:        false,
		},
		{
			name:        "wildcard covers server-level object",
			grant:       TailscaleGrant{Projects: []string{"*"}, Role: "admin"},
			object:      server,
			entitlement: EntitlementCanViewMetrics,
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.grant.allows(tt.object, tt.entitlement)
			if got != tt.want {
				t.Fatalf("allows(%v, %q) = %v, want %v", tt.object, tt.entitlement, got, tt.want)
			}
		})
	}
}
