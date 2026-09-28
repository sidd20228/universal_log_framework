package auth

import (
	"strings"
	"testing"
)

func FuzzBearerTokenParsing(f *testing.F) {
	for _, seed := range []string{
		"",
		"Bearer " + writerSecret,
		"bearer " + writerSecret,
		"Basic " + writerSecret,
		"Bearer " + writerSecret + " trailing",
		"Bearer\t" + writerSecret,
		"Bearer " + writerSecret + "\r\nX-Injected: value",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		secret, err := bearerSecret([]string{header})
		if err != nil {
			return
		}
		scheme, expected, found := strings.Cut(header, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || secret != expected || !validSecret(secret) || strings.Contains(secret, " ") {
			t.Fatalf("invalid bearer header was accepted: %q", header)
		}
	})
}

func FuzzAuthorizationScopeIsolation(f *testing.F) {
	for _, seed := range []struct {
		secret string
		scope  string
		tenant string
	}{
		{writerSecret, string(ScopeEventsWrite), "tenant-a"},
		{writerSecret, string(ScopeRawRead), "tenant-a"},
		{analystSecret, string(ScopeEventsRead), "tenant-b"},
		{forensicSecret, string(ScopeRawRead), "tenant-z"},
		{"unknown-secret-000000000000000000", "admin:*", "*"},
	} {
		f.Add(seed.secret, seed.scope, seed.tenant)
	}
	authorizer, err := New([]TokenConfig{
		{ID: "writer", Actor: "synthetic-sender", Secret: writerSecret, Scopes: []Scope{ScopeEventsWrite}, Tenants: []string{"tenant-a"}},
		{ID: "analyst", Actor: "analyst@example.test", Secret: analystSecret, Scopes: []Scope{ScopeEventsRead}, Tenants: []string{"tenant-a"}},
		{ID: "forensic", Actor: "forensic@example.test", Secret: forensicSecret, Scopes: []Scope{ScopeRawRead}, Tenants: []string{"*"}},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, secret, scopeValue, tenant string) {
		if len(secret)+len(scopeValue)+len(tenant) > 4<<10 {
			return
		}
		scope := Scope(scopeValue)
		_, err := authorizer.Authorize(secret, Requirement{Scope: scope, TenantID: tenant})
		allowed := expectedAuthorization(secret, scope, tenant)
		if (err == nil) != allowed {
			t.Fatalf("Authorize(%q, %q, %q) error = %v, want allowed=%t", secret, scope, tenant, err, allowed)
		}
	})
}

func TestSecurityBearerHeaderCorpus(t *testing.T) {
	for name, values := range map[string][]string{
		"missing":          nil,
		"multiple":         {"Bearer " + writerSecret, "Bearer " + writerSecret},
		"embedded space":   {"Bearer " + writerSecret + " suffix"},
		"header injection": {"Bearer " + writerSecret + "\r\nX-Scope: raw:read"},
		"wrong scheme":     {"Basic " + writerSecret},
		"tab separator":    {"Bearer\t" + writerSecret},
	} {
		t.Run(name, func(t *testing.T) {
			if secret, err := bearerSecret(values); err == nil {
				t.Fatalf("hostile header returned secret %q", secret)
			}
		})
	}
}

func expectedAuthorization(secret string, scope Scope, tenant string) bool {
	allowsTenantA := tenant == "" || tenant == "tenant-a"
	switch secret {
	case writerSecret:
		return scope == ScopeEventsWrite && allowsTenantA
	case analystSecret:
		return scope == ScopeEventsRead && allowsTenantA
	case forensicSecret:
		return scope == ScopeRawRead
	default:
		return false
	}
}
