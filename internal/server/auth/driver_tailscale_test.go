package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/lxc/incus/v7/internal/server/request"
	"github.com/lxc/incus/v7/shared/api"
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

// fakeWhoIs is a tsWhoIser that returns a canned WhoIs response, standing in for
// a live tailscaled so the full request path can be tested without a tailnet.
type fakeWhoIs struct {
	resp *apitype.WhoIsResponse
	err  error
}

func (f fakeWhoIs) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return f.resp, f.err
}

func whoisWithGrant(login string, grant string) *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{},
		UserProfile: &tailcfg.UserProfile{LoginName: login},
		CapMap: tailcfg.PeerCapMap{
			tailcfg.PeerCapability(tailscaleDefaultCapName): []tailcfg.RawMessage{tailcfg.RawMessage(grant)},
		},
	}
}

// tsRequest builds a request carrying a Tailscale-authenticated identity, as the
// daemon would after Authenticate resolves the caller.
func tsRequest(username string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/1.0/instances", nil)
	r.RemoteAddr = "100.64.0.1:33333"
	ctx := context.WithValue(r.Context(), request.CtxUsername, username)
	ctx = context.WithValue(ctx, request.CtxProtocol, api.AuthenticationMethodTailscale)
	return r.WithContext(ctx)
}

// TestTailscaleAuthorizerCheckPermission exercises the full authorizer path:
// request details -> WhoIs -> CapMap grant -> evaluation.
func TestTailscaleAuthorizerCheckPermission(t *testing.T) {
	tests := []struct {
		name        string
		grant       string
		object      Object
		entitlement Entitlement
		wantErr     bool
	}{
		{
			name:        "admin grant allows edit",
			grant:       `{"projects":["*"],"role":"admin"}`,
			object:      ObjectInstance("default", "c1"),
			entitlement: EntitlementCanEdit,
			wantErr:     false,
		},
		{
			name:        "viewer grant denies edit",
			grant:       `{"projects":["default"],"role":"viewer"}`,
			object:      ObjectInstance("default", "c1"),
			entitlement: EntitlementCanEdit,
			wantErr:     true,
		},
		{
			name:        "grant for other project denies",
			grant:       `{"projects":["web"],"role":"admin"}`,
			object:      ObjectInstance("default", "c1"),
			entitlement: EntitlementCanEdit,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &Tailscale{
				client:  fakeWhoIs{resp: whoisWithGrant("alice@example.com", tt.grant)},
				capName: tailcfg.PeerCapability(tailscaleDefaultCapName),
			}

			r := tsRequest("alice@example.com")
			err := ts.CheckPermission(r.Context(), r, tt.object, tt.entitlement)
			if tt.wantErr && err == nil {
				t.Fatal("expected permission denied, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("expected allowed, got: %v", err)
			}
		})
	}
}

// TestTailscaleGetPermissionChecker covers the list-filter path.
func TestTailscaleGetPermissionChecker(t *testing.T) {
	ts := &Tailscale{
		client:  fakeWhoIs{resp: whoisWithGrant("alice@example.com", `{"projects":["default"],"role":"viewer"}`)},
		capName: tailcfg.PeerCapability(tailscaleDefaultCapName),
	}

	r := tsRequest("alice@example.com")
	checker, err := ts.GetPermissionChecker(r.Context(), r, EntitlementCanView, ObjectTypeInstance)
	if err != nil {
		t.Fatal(err)
	}

	if !checker(ObjectInstance("default", "c1")) {
		t.Fatal("expected viewer to be allowed to view default instance")
	}

	if checker(ObjectInstance("web", "c1")) {
		t.Fatal("expected viewer to be denied on another project")
	}
}

func TestTailscaleVerifierIdentity(t *testing.T) {
	ctx := context.Background()

	// User-owned node resolves to its login name.
	v := &TailscaleVerifier{client: fakeWhoIs{resp: &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
	}}}

	id, err := v.Identity(ctx, "100.64.0.1:1")
	if err != nil || id != "alice@example.com" {
		t.Fatalf("got (%q, %v), want (alice@example.com, nil)", id, err)
	}

	// Tagged node resolves to tagged:<tags>.
	v = &TailscaleVerifier{client: fakeWhoIs{resp: &apitype.WhoIsResponse{
		Node: &tailcfg.Node{Tags: []string{"tag:incus"}},
	}}}

	id, err = v.Identity(ctx, "100.64.0.2:1")
	if err != nil || id != "tagged:tag:incus" {
		t.Fatalf("got (%q, %v), want (tagged:tag:incus, nil)", id, err)
	}

	// An unknown peer (WhoIs error) propagates as an error.
	v = &TailscaleVerifier{client: fakeWhoIs{err: errors.New("no peer")}}
	_, err = v.Identity(ctx, "10.0.0.1:1")
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}
}
