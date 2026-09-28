package auth

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	writerSecret   = "writer-secret-0000000000000000001"
	analystSecret  = "analyst-secret-000000000000000001"
	forensicSecret = "forensic-secret-0000000000000001"
)

func TestPermissionMatrix(t *testing.T) {
	authorizer := testAuthorizer(t)
	tests := []struct {
		name   string
		secret string
		scope  Scope
		tenant string
		allow  bool
	}{
		{name: "writer admits own tenant", secret: writerSecret, scope: ScopeEventsWrite, tenant: "tenant-a", allow: true},
		{name: "writer cannot query", secret: writerSecret, scope: ScopeEventsRead, tenant: "tenant-a", allow: false},
		{name: "writer cannot cross tenant", secret: writerSecret, scope: ScopeEventsWrite, tenant: "tenant-b", allow: false},
		{name: "analyst reads events", secret: analystSecret, scope: ScopeEventsRead, tenant: "tenant-a", allow: true},
		{name: "events read does not imply raw", secret: analystSecret, scope: ScopeRawRead, tenant: "tenant-a", allow: false},
		{name: "forensic reads raw in any tenant", secret: forensicSecret, scope: ScopeRawRead, tenant: "tenant-b", allow: true},
		{name: "raw read does not imply config", secret: forensicSecret, scope: ScopeConfigRead, tenant: "tenant-a", allow: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := authorizer.Authorize(test.secret, Requirement{Scope: test.scope, TenantID: test.tenant})
			if (err == nil) != test.allow {
				t.Fatalf("allow = %t, error = %v", test.allow, err)
			}
			if err != nil && !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthenticationErrorsDoNotRevealTokenExistence(t *testing.T) {
	authorizer := testAuthorizer(t)
	if _, err := authorizer.Authenticate(""); !errors.Is(err, ErrMissingCredentials) {
		t.Fatalf("missing error = %v", err)
	}
	if _, err := authorizer.Authenticate("unknown-secret-000000000000000000"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("invalid error = %v", err)
	}
	principal, err := authorizer.Authenticate(writerSecret)
	if err != nil || principal.TokenID != "writer" || principal.Actor != "synthetic-sender" {
		t.Fatalf("principal = %#v, error = %v", principal, err)
	}
}

func TestAuthorizerDoesNotRetainPlaintextTokens(t *testing.T) {
	authorizer := testAuthorizer(t)
	formatted := fmt.Sprintf("%#v", authorizer)
	for _, secret := range []string{writerSecret, analystSecret, forensicSecret} {
		if strings.Contains(formatted, secret) {
			t.Fatalf("authorizer representation retained secret %q", secret)
		}
	}
}

func TestPrincipalCopiesCannotChangePermissions(t *testing.T) {
	authorizer := testAuthorizer(t)
	principal, err := authorizer.Authenticate(writerSecret)
	if err != nil {
		t.Fatal(err)
	}
	scopes := principal.Scopes()
	tenants := principal.Tenants()
	scopes[0] = ScopeRawRead
	tenants[0] = "tenant-b"
	again, err := authorizer.Authenticate(writerSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.Scopes(), []Scope{ScopeEventsWrite}) || !reflect.DeepEqual(again.Tenants(), []string{"tenant-a"}) {
		t.Fatalf("permissions were mutated: %#v %#v", again.Scopes(), again.Tenants())
	}
}

func TestInvalidConfigurationsAreRejected(t *testing.T) {
	base := TokenConfig{ID: "id", Actor: "actor", Secret: writerSecret, Scopes: []Scope{ScopeEventsRead}, Tenants: []string{"tenant-a"}}
	tests := map[string][]TokenConfig{
		"no tokens":           nil,
		"short secret":        {{ID: "id", Actor: "actor", Secret: "short", Scopes: base.Scopes, Tenants: base.Tenants}},
		"unknown scope":       {{ID: "id", Actor: "actor", Secret: writerSecret, Scopes: []Scope{"admin:*"}, Tenants: base.Tenants}},
		"no tenant":           {{ID: "id", Actor: "actor", Secret: writerSecret, Scopes: base.Scopes}},
		"duplicate id":        {base, {ID: "id", Actor: "other", Secret: analystSecret, Scopes: base.Scopes, Tenants: base.Tenants}},
		"duplicate secret":    {base, {ID: "other", Actor: "other", Secret: writerSecret, Scopes: base.Scopes, Tenants: base.Tenants}},
		"all disabled":        {{ID: "id", Disabled: true}},
		"control character":   {{ID: "id", Actor: "actor\nforged", Secret: writerSecret, Scopes: base.Scopes, Tenants: base.Tenants}},
		"duplicate privilege": {{ID: "id", Actor: "actor", Secret: writerSecret, Scopes: []Scope{ScopeEventsRead, ScopeEventsRead}, Tenants: base.Tenants}},
	}
	for name, configs := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(configs); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func testAuthorizer(t *testing.T) *Authorizer {
	t.Helper()
	authorizer, err := New([]TokenConfig{
		{ID: "writer", Actor: "synthetic-sender", Secret: writerSecret, Scopes: []Scope{ScopeEventsWrite}, Tenants: []string{"tenant-a"}},
		{ID: "analyst", Actor: "analyst@example.test", Secret: analystSecret, Scopes: []Scope{ScopeEventsRead}, Tenants: []string{"tenant-a"}},
		{ID: "forensic", Actor: "forensic@example.test", Secret: forensicSecret, Scopes: []Scope{ScopeRawRead}, Tenants: []string{"*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}
