package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type contextKey uint8

const (
	principalKey contextKey = iota
	requestIDKey
)

type TenantResolver func(*http.Request) string

func RequireHTTP(authorizer *Authorizer, scope Scope, tenant TenantResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID := newRequestID()
		writer.Header().Set("X-Request-ID", requestID)
		secret, err := bearerSecret(request.Header.Values("Authorization"))
		if err != nil {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="ulpf"`)
			writeError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", "valid bearer credentials are required", requestID)
			return
		}
		tenantID := ""
		if tenant != nil {
			tenantID = tenant(request)
		}
		principal, err := authorizer.Authorize(secret, Requirement{Scope: scope, TenantID: tenantID})
		if err != nil {
			if errors.Is(err, ErrMissingCredentials) || errors.Is(err, ErrInvalidCredentials) {
				writer.Header().Set("WWW-Authenticate", `Bearer realm="ulpf"`)
				writeError(writer, http.StatusUnauthorized, "UNAUTHENTICATED", "valid bearer credentials are required", requestID)
				return
			}
			writeError(writer, http.StatusForbidden, "FORBIDDEN", "token does not grant the required permission", requestID)
			return
		}
		ctx := context.WithValue(request.Context(), principalKey, principal)
		ctx = context.WithValue(ctx, requestIDKey, requestID)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, found := ctx.Value(principalKey).(Principal)
	if !found {
		return Principal{}, false
	}
	return clonePrincipal(principal), true
}

func RequestIDFromContext(ctx context.Context) (string, bool) {
	requestID, found := ctx.Value(requestIDKey).(string)
	return requestID, found
}

func bearerSecret(values []string) (string, error) {
	if len(values) != 1 {
		return "", ErrMissingCredentials
	}
	scheme, secret, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || !validSecret(secret) || strings.Contains(secret, " ") {
		return "", ErrInvalidCredentials
	}
	return secret, nil
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(value[:])
}

func writeError(writer http.ResponseWriter, status int, code, message, requestID string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"code":       code,
		"message":    message,
		"request_id": requestID,
	})
}
