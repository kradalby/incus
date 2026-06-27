package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/tailcfg"

	"github.com/lxc/incus/v7/internal/server/certificate"
	"github.com/lxc/incus/v7/shared/api"
)

// tailscaleDefaultCapName is the default Tailscale grant capability name that
// Incus reads permissions from. Override with the "tailscale.cap_name" key.
const tailscaleDefaultCapName = "incus.com/cap/incus"

// TailscaleGrant is the JSON shape of a single Tailscale app-capability grant
// entry for Incus, e.g. {"projects": ["default"], "role": "operator"}.
// Multiple grant rules accumulate into a slice via the Tailscale CapMap.
type TailscaleGrant struct {
	// Projects the grant applies to. "*" means all projects.
	Projects []string `json:"projects"`

	// Role is a shorthand expanded against tailscaleRoles. Optional.
	Role string `json:"role,omitempty"`

	// Entitlements lists explicit entitlement relations granted. Optional.
	Entitlements []string `json:"entitlements,omitempty"`
}

// tailscaleRoles expands a role name into the entitlements it grants. Kept
// deliberately small for the MVP; "admin" is handled specially as allow-all.
var tailscaleRoles = map[string][]Entitlement{
	"operator": {EntitlementCanEdit, EntitlementCanView},
	"viewer":   {EntitlementCanView},
}

// allows reports whether this grant permits the entitlement on the object.
func (g TailscaleGrant) allows(object Object, entitlement Entitlement) bool {
	// Project scope: "*" matches any project (including server-level "").
	if !slices.Contains(g.Projects, "*") && !slices.Contains(g.Projects, object.Project()) {
		return false
	}

	// The admin role grants everything.
	if g.Role == "admin" {
		return true
	}

	// Role expansion.
	if slices.Contains(tailscaleRoles[g.Role], entitlement) {
		return true
	}

	// Explicit entitlements.
	return slices.Contains(g.Entitlements, string(entitlement))
}

// Tailscale is a grant-based authorizer driven by Tailscale app capabilities,
// resolved from the local tailscaled daemon via WhoIs. Certificate-authenticated
// callers are delegated to an embedded TLS authorizer so cert bootstrap keeps
// working.
type Tailscale struct {
	commonAuthorizer
	tls *TLS

	client  *local.Client
	capName tailcfg.PeerCapability
}

func (t *Tailscale) load(ctx context.Context, certificateCache *certificate.Cache, opts Opts) error {
	t.tls = &TLS{}
	err := t.tls.load(ctx, certificateCache, opts)
	if err != nil {
		return err
	}

	t.capName = tailcfg.PeerCapability(tailscaleDefaultCapName)
	if opts.config != nil {
		v, ok := opts.config["tailscale.cap_name"].(string)
		if ok && v != "" {
			t.capName = tailcfg.PeerCapability(v)
		}
	}

	// Zero-value client talks to the local tailscaled socket.
	t.client = &local.Client{}
	return nil
}

// grants resolves the Tailscale grants for the caller at remoteAddr.
func (t *Tailscale) grants(ctx context.Context, remoteAddr string) ([]TailscaleGrant, error) {
	who, err := t.client.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, err
	}

	return tailcfg.UnmarshalCapJSON[TailscaleGrant](who.CapMap, t.capName)
}

// CheckPermission returns an error if the caller lacks the entitlement on the object.
func (t *Tailscale) CheckPermission(ctx context.Context, r *http.Request, object Object, entitlement Entitlement) error {
	details, err := t.requestDetails(r)
	if err != nil {
		return api.StatusErrorf(http.StatusForbidden, "Failed to extract request details: %v", err)
	}

	if details.isInternalOrUnix() {
		return nil
	}

	// Certificate-authenticated callers go through the TLS authorizer.
	if details.authenticationProtocol() == api.AuthenticationMethodTLS {
		return t.tls.CheckPermission(ctx, r, object, entitlement)
	}

	if details.authenticationProtocol() != api.AuthenticationMethodTailscale {
		return api.StatusErrorf(http.StatusForbidden, "Unsupported authentication method %q", details.authenticationProtocol())
	}

	grants, err := t.grants(ctx, r.RemoteAddr)
	if err != nil {
		return api.StatusErrorf(http.StatusForbidden, "Failed to read Tailscale grants: %v", err)
	}

	for _, g := range grants {
		if g.allows(object, entitlement) {
			return nil
		}
	}

	return api.StatusErrorf(http.StatusForbidden, "No Tailscale grant permits %q on %q", entitlement, object)
}

// GetPermissionChecker returns a filter for whether the caller has the entitlement on an object.
func (t *Tailscale) GetPermissionChecker(ctx context.Context, r *http.Request, entitlement Entitlement, objectType ObjectType) (PermissionChecker, error) {
	allowFunc := func(b bool) func(Object) bool {
		return func(Object) bool {
			return b
		}
	}

	details, err := t.requestDetails(r)
	if err != nil {
		return nil, api.StatusErrorf(http.StatusForbidden, "Failed to extract request details: %v", err)
	}

	if details.isInternalOrUnix() {
		return allowFunc(true), nil
	}

	if details.authenticationProtocol() == api.AuthenticationMethodTLS {
		return t.tls.GetPermissionChecker(ctx, r, entitlement, objectType)
	}

	if details.authenticationProtocol() != api.AuthenticationMethodTailscale {
		return allowFunc(false), nil
	}

	grants, err := t.grants(ctx, r.RemoteAddr)
	if err != nil {
		return nil, api.StatusErrorf(http.StatusForbidden, "Failed to read Tailscale grants: %v", err)
	}

	return func(object Object) bool {
		for _, g := range grants {
			if g.allows(object, entitlement) {
				return true
			}
		}

		return false
	}, nil
}

// GetInstanceAccess is a no-op for the Tailscale authorizer (MVP).
func (t *Tailscale) GetInstanceAccess(ctx context.Context, projectName string, instanceName string) (*api.Access, error) {
	return &api.Access{}, nil
}

// GetProjectAccess is a no-op for the Tailscale authorizer (MVP).
func (t *Tailscale) GetProjectAccess(ctx context.Context, projectName string) (*api.Access, error) {
	return &api.Access{}, nil
}

// TailscaleVerifier resolves the Tailscale identity of an inbound connection
// using the local tailscaled daemon.
type TailscaleVerifier struct {
	client *local.Client
}

// NewTailscaleVerifier returns a verifier backed by the local tailscaled socket.
func NewTailscaleVerifier() (*TailscaleVerifier, error) {
	return &TailscaleVerifier{client: &local.Client{}}, nil
}

// Identity returns a stable identity string for the caller at remoteAddr, or an
// error if the address does not belong to a known Tailscale peer. User-owned
// nodes resolve to their login name; tagged nodes resolve to "tagged:<tags>".
func (v *TailscaleVerifier) Identity(ctx context.Context, remoteAddr string) (string, error) {
	who, err := v.client.WhoIs(ctx, remoteAddr)
	if err != nil {
		return "", err
	}

	if who.Node != nil && who.Node.IsTagged() {
		return "tagged:" + strings.Join(who.Node.Tags, ","), nil
	}

	if who.UserProfile == nil || who.UserProfile.LoginName == "" {
		return "", errors.New("Tailscale peer has no login name")
	}

	return who.UserProfile.LoginName, nil
}
