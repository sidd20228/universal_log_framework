package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Scope string

const (
	ScopeEventsWrite   Scope = "events:write"
	ScopeEventsRead    Scope = "events:read"
	ScopeRawRead       Scope = "raw:read"
	ScopeReplayWrite   Scope = "replay:write"
	ScopeConfigRead    Scope = "config:read"
	ScopeConfigWrite   Scope = "config:write"
	ScopeConfigApprove Scope = "config:approve"
	ScopeOpsRead       Scope = "ops:read"
)

var (
	ErrMissingCredentials = errors.New("credentials are required")
	ErrInvalidCredentials = errors.New("credentials are invalid")
	ErrPermissionDenied   = errors.New("permission denied")
)

var allowedScopes = map[Scope]struct{}{
	ScopeEventsWrite: {}, ScopeEventsRead: {}, ScopeRawRead: {}, ScopeReplayWrite: {},
	ScopeConfigRead: {}, ScopeConfigWrite: {}, ScopeConfigApprove: {}, ScopeOpsRead: {},
}

type TokenConfig struct {
	ID       string
	Secret   string
	Actor    string
	Scopes   []Scope
	Tenants  []string
	Disabled bool
}

type Principal struct {
	TokenID string
	Actor   string
	scopes  map[Scope]struct{}
	tenants map[string]struct{}
}

func (principal Principal) Scopes() []Scope {
	values := make([]Scope, 0, len(principal.scopes))
	for scope := range principal.scopes {
		values = append(values, scope)
	}
	sort.Slice(values, func(first, second int) bool { return values[first] < values[second] })
	return values
}

func (principal Principal) Tenants() []string {
	values := make([]string, 0, len(principal.tenants))
	for tenant := range principal.tenants {
		values = append(values, tenant)
	}
	sort.Strings(values)
	return values
}

func (principal Principal) Allows(scope Scope, tenantID string) bool {
	if _, found := principal.scopes[scope]; !found {
		return false
	}
	if tenantID == "" {
		return true
	}
	if _, all := principal.tenants["*"]; all {
		return true
	}
	_, found := principal.tenants[tenantID]
	return found
}

type Requirement struct {
	Scope    Scope
	TenantID string
}

type tokenEntry struct {
	digest    [sha256.Size]byte
	principal Principal
}

type Authorizer struct {
	entries []tokenEntry
}

func New(configs []TokenConfig) (*Authorizer, error) {
	if len(configs) == 0 {
		return nil, errors.New("at least one token is required")
	}
	entries := make([]tokenEntry, 0, len(configs))
	ids := make(map[string]struct{}, len(configs))
	digests := make(map[[sha256.Size]byte]struct{}, len(configs))
	for index, config := range configs {
		if config.Disabled {
			continue
		}
		if !validIdentifier(config.ID) || !validActor(config.Actor) {
			return nil, fmt.Errorf("token %d has an invalid id or actor", index)
		}
		if _, duplicate := ids[config.ID]; duplicate {
			return nil, fmt.Errorf("token id %q is duplicated", config.ID)
		}
		ids[config.ID] = struct{}{}
		if !validSecret(config.Secret) {
			return nil, fmt.Errorf("token %q secret must contain 32 to 512 visible ASCII characters", config.ID)
		}
		digest := sha256.Sum256([]byte(config.Secret))
		if _, duplicate := digests[digest]; duplicate {
			return nil, errors.New("token secrets must be unique")
		}
		digests[digest] = struct{}{}
		if len(config.Scopes) == 0 || len(config.Tenants) == 0 {
			return nil, fmt.Errorf("token %q requires at least one scope and tenant", config.ID)
		}
		scopes := make(map[Scope]struct{}, len(config.Scopes))
		for _, scope := range config.Scopes {
			if _, valid := allowedScopes[scope]; !valid {
				return nil, fmt.Errorf("token %q contains unknown scope %q", config.ID, scope)
			}
			if _, duplicate := scopes[scope]; duplicate {
				return nil, fmt.Errorf("token %q repeats scope %q", config.ID, scope)
			}
			scopes[scope] = struct{}{}
		}
		tenants := make(map[string]struct{}, len(config.Tenants))
		for _, tenant := range config.Tenants {
			if tenant != "*" && !validIdentifier(tenant) {
				return nil, fmt.Errorf("token %q contains invalid tenant %q", config.ID, tenant)
			}
			if _, duplicate := tenants[tenant]; duplicate {
				return nil, fmt.Errorf("token %q repeats tenant %q", config.ID, tenant)
			}
			tenants[tenant] = struct{}{}
		}
		entries = append(entries, tokenEntry{
			digest: digest,
			principal: Principal{
				TokenID: config.ID,
				Actor:   config.Actor,
				scopes:  scopes,
				tenants: tenants,
			},
		})
	}
	if len(entries) == 0 {
		return nil, errors.New("at least one enabled token is required")
	}
	return &Authorizer{entries: entries}, nil
}

func (authorizer *Authorizer) Authenticate(secret string) (Principal, error) {
	if secret == "" {
		return Principal{}, ErrMissingCredentials
	}
	digest := sha256.Sum256([]byte(secret))
	match := -1
	for index := range authorizer.entries {
		if subtle.ConstantTimeCompare(digest[:], authorizer.entries[index].digest[:]) == 1 {
			match = index
		}
	}
	if match < 0 {
		return Principal{}, ErrInvalidCredentials
	}
	return clonePrincipal(authorizer.entries[match].principal), nil
}

func (authorizer *Authorizer) Authorize(secret string, requirement Requirement) (Principal, error) {
	if _, valid := allowedScopes[requirement.Scope]; !valid {
		return Principal{}, fmt.Errorf("%w: unknown required scope", ErrPermissionDenied)
	}
	principal, err := authorizer.Authenticate(secret)
	if err != nil {
		return Principal{}, err
	}
	if !principal.Allows(requirement.Scope, requirement.TenantID) {
		return Principal{}, ErrPermissionDenied
	}
	return principal, nil
}

func clonePrincipal(source Principal) Principal {
	clone := Principal{TokenID: source.TokenID, Actor: source.Actor}
	clone.scopes = make(map[Scope]struct{}, len(source.scopes))
	for value := range source.scopes {
		clone.scopes[value] = struct{}{}
	}
	clone.tenants = make(map[string]struct{}, len(source.tenants))
	for value := range source.tenants {
		clone.tenants[value] = struct{}{}
	}
	return clone
}

func validSecret(secret string) bool {
	if len(secret) < 32 || len(secret) > 512 {
		return false
	}
	for _, character := range secret {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func validActor(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) > 0 && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}
