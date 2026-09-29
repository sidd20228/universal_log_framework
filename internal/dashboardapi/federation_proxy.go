package dashboardapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sidd20228/universal_log_framework/internal/auth"
)

const maxFederationTraceBytes = 8 << 20

// NewFederationProxyHandler keeps peer credentials on the server while making
// cross-node receipt and event traces available to the local dashboard.
func NewFederationProxyHandler(authorizer *auth.Authorizer, tenantID string, peers []FederationPeer) (http.Handler, error) {
	if authorizer == nil || !validTenantID(tenantID) {
		return nil, errors.New("federation proxy authorizer and tenant are required")
	}
	byID := make(map[string]FederationPeer, len(peers))
	for _, peer := range peers {
		if peer.ID == "" || peer.Token == "" {
			return nil, errors.New("federation proxy peer is incomplete")
		}
		byID[peer.ID] = peer
	}
	inner := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeError(writer, request, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
			return
		}
		path := strings.TrimPrefix(request.URL.Path, "/api/v1/federation/")
		parts := strings.SplitN(path, "/", 3)
		if len(parts) != 3 || (parts[1] != "events" && parts[1] != "receipts") || parts[2] == "" || strings.Contains(parts[2], "/") {
			writeError(writer, request, http.StatusNotFound, "NOT_FOUND", "federated trace not found")
			return
		}
		peer, found := byID[parts[0]]
		if !found {
			writeError(writer, request, http.StatusNotFound, "NOT_FOUND", "federated trace not found")
			return
		}
		endpoint := strings.TrimRight(peer.Endpoint, "/") + "/api/v1/" + parts[1] + "/" + url.PathEscape(parts[2]) + "?tenant_id=" + url.QueryEscape(tenantID)
		ctx, cancel := context.WithTimeout(request.Context(), peer.Timeout)
		defer cancel()
		upstream, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			writeError(writer, request, http.StatusBadGateway, "PEER_UNAVAILABLE", "federated peer is unavailable")
			return
		}
		upstream.Header.Set("Authorization", "Bearer "+peer.Token)
		upstream.Header.Set("Accept", "application/json")
		response, err := http.DefaultClient.Do(upstream)
		if err != nil {
			writeError(writer, request, http.StatusBadGateway, "PEER_UNAVAILABLE", "federated peer is unavailable")
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, maxFederationTraceBytes+1))
		if err != nil || len(body) > maxFederationTraceBytes || !json.Valid(body) {
			writeError(writer, request, http.StatusBadGateway, "PEER_RESPONSE_INVALID", "federated peer returned an invalid response")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.WriteHeader(response.StatusCode)
		_, _ = writer.Write(body)
	})
	return auth.RequireHTTP(authorizer, auth.ScopeEventsRead, func(*http.Request) string { return tenantID }, inner), nil
}
