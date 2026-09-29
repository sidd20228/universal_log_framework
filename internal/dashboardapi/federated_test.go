package dashboardapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type staticSummaryReader struct{ summary Summary }

func (reader staticSummaryReader) ReadSummary(context.Context, string, time.Time) (Summary, error) {
	return reader.summary, nil
}

func TestFederatedReaderAggregatesPeersAndReportsOrigin(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	peerSummary := Summary{
		GeneratedAt: now, TenantID: "tenant-a", Totals: Totals{Receipts: 2, Revisions: 1, RawBytes: 20},
		AcceptedTotal: 2, CommittedTotal: 1,
		ReceiptStateCounts: map[string]int64{"REVISION_COMMITTED": 1}, StatusCounts: map[string]int64{"PARSED": 1},
		Activity: []ActivityBucket{{Time: now.Truncate(activityBucket), Accepted: 2, Committed: 1}},
		RecentEvents: []RecentEvent{{ReceiptID: "receipt-peer", RevisionID: "revision-peer", TenantID: "tenant-a", ReceivedAt: now,
			ReceiptURL: "/api/v1/receipts/receipt-peer", EventURL: "/api/v1/events/revision-peer"}},
	}
	peer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer peer-secret" || request.URL.Query().Get("tenant_id") != "tenant-a" {
			http.Error(writer, "denied", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(writer).Encode(peerSummary)
	}))
	defer peer.Close()
	local := Summary{GeneratedAt: now, TenantID: "tenant-a", Totals: Totals{Receipts: 1, Revisions: 1, RawBytes: 10},
		AcceptedTotal: 1, CommittedTotal: 1, ReceiptStateCounts: map[string]int64{"REVISION_COMMITTED": 1}, StatusCounts: map[string]int64{"PARSED": 1},
		Activity: []ActivityBucket{{Time: now.Truncate(activityBucket), Accepted: 1, Committed: 1}}}
	reader, err := NewFederatedReader(staticSummaryReader{local}, "prod", "node-a", []FederationPeer{{
		ID: "peer-b", EnvironmentID: "dr", InstanceID: "node-b", Endpoint: peer.URL, Token: "peer-secret", Timeout: time.Second,
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.ReadSummary(context.Background(), "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Totals.Receipts != 3 || result.Totals.Revisions != 2 || result.Activity[0].Accepted != 3 {
		t.Fatalf("aggregated summary = %+v", result)
	}
	if len(result.Nodes) != 2 || !result.Nodes[1].Available || result.RecentEvents[0].EnvironmentID != "dr" {
		t.Fatalf("federation metadata = %+v, events = %+v", result.Nodes, result.RecentEvents)
	}
	if len(result.Origins) != 2 || result.Origins[1].EnvironmentID != "dr" || result.Origins[1].Retained {
		t.Fatalf("origin summaries = %+v", result.Origins)
	}
	if result.RecentEvents[0].EventURL != "/api/v1/federation/peer-b/events/revision-peer" ||
		result.RecentEvents[0].ReceiptURL != "/api/v1/federation/peer-b/receipts/receipt-peer" {
		t.Fatalf("peer trace URLs = %+v", result.RecentEvents[0])
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "peer-secret") || strings.Contains(string(encoded), peer.URL) {
		t.Fatalf("federation credentials or endpoint leaked in response: %s", encoded)
	}
}

func TestFederatedReaderExposesPartialFailure(t *testing.T) {
	now := time.Now().UTC()
	local := Summary{GeneratedAt: now, TenantID: "tenant-a", ReceiptStateCounts: map[string]int64{}, StatusCounts: map[string]int64{}}
	reader, err := NewFederatedReader(staticSummaryReader{local}, "prod", "node-a", []FederationPeer{{
		ID: "down", EnvironmentID: "dr", InstanceID: "node-b", Endpoint: "http://127.0.0.1:1", Token: "secret", Timeout: 20 * time.Millisecond,
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.ReadSummary(context.Background(), "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 2 || result.Nodes[1].Available || result.Nodes[1].ErrorCode == "" {
		t.Fatalf("partial failure was hidden: %+v", result.Nodes)
	}
	if result.Nodes[1].Retained || len(result.Origins) != 1 {
		t.Fatalf("uncached peer unexpectedly retained data: nodes=%+v origins=%+v", result.Nodes, result.Origins)
	}
}

func TestFederatedReaderRetainsLastKnownPeerSummary(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	peerSummary := Summary{
		GeneratedAt: now, TenantID: "tenant-a", Totals: Totals{Receipts: 2, Revisions: 1, RawBytes: 20},
		AcceptedTotal: 2, CommittedTotal: 1,
		ReceiptStateCounts: map[string]int64{"REVISION_COMMITTED": 1}, StatusCounts: map[string]int64{"PARSED": 1},
		Activity: []ActivityBucket{{Time: now.Truncate(activityBucket), Accepted: 2, Committed: 1}},
		RecentEvents: []RecentEvent{{ReceiptID: "receipt-peer", RevisionID: "revision-peer", TenantID: "tenant-a", ReceivedAt: now,
			ReceiptURL: "/api/v1/receipts/receipt-peer", EventURL: "/api/v1/events/revision-peer"}},
	}
	var unavailable atomic.Bool
	peer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if unavailable.Load() {
			http.Error(writer, "stopped", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(writer).Encode(peerSummary)
	}))
	defer peer.Close()
	local := Summary{GeneratedAt: now, TenantID: "tenant-a", Totals: Totals{Receipts: 1}, ReceiptStateCounts: map[string]int64{}, StatusCounts: map[string]int64{}}
	reader, err := NewFederatedReader(staticSummaryReader{local}, "prod", "node-a", []FederationPeer{{
		ID: "peer-b", EnvironmentID: "dr", InstanceID: "node-b", Endpoint: peer.URL, Token: "peer-secret", Timeout: time.Second,
	}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := reader.ReadSummary(context.Background(), "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	unavailable.Store(true)
	second, err := reader.ReadSummary(context.Background(), "tenant-a", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.Totals.Receipts != 3 || second.Totals.Receipts != first.Totals.Receipts || len(second.RecentEvents) != 1 {
		t.Fatalf("last-known data was hidden: first=%+v second=%+v", first, second)
	}
	peerNode := second.Nodes[1]
	if peerNode.Available || !peerNode.Stale || !peerNode.Retained || peerNode.ErrorCode != "HTTP_503" || peerNode.LastSeenAt != now {
		t.Fatalf("retained peer status = %+v", peerNode)
	}
	if len(second.Origins) != 2 || !second.Origins[1].Retained || second.Origins[1].Available || second.Origins[1].Totals.Receipts != 2 {
		t.Fatalf("retained origin = %+v", second.Origins)
	}

	// A cached tenant must never be reused for another tenant.
	otherLocal := local
	otherLocal.TenantID = "tenant-b"
	reader.local = staticSummaryReader{otherLocal}
	other, err := reader.ReadSummary(context.Background(), "tenant-b", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if other.Totals.Receipts != 1 || other.Nodes[1].Retained || len(other.Origins) != 1 {
		t.Fatalf("cross-tenant history leaked: %+v", other)
	}
}

func TestFederatedReaderRejectsOversizedPeerSummary(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	peerSummary := Summary{
		GeneratedAt: now, TenantID: "tenant-a", EnvironmentID: "dr", InstanceID: "node-b",
		ReceiptStateCounts: map[string]int64{}, StatusCounts: map[string]int64{},
	}
	for index := 0; index <= maxPeerActivityBuckets; index++ {
		peerSummary.Activity = append(peerSummary.Activity, ActivityBucket{Time: now.Add(time.Duration(index) * activityBucket)})
	}
	peer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(writer).Encode(peerSummary)
	}))
	defer peer.Close()
	local := Summary{GeneratedAt: now, TenantID: "tenant-a", ReceiptStateCounts: map[string]int64{}, StatusCounts: map[string]int64{}}
	reader, err := NewFederatedReader(staticSummaryReader{local}, "prod", "node-a", []FederationPeer{{
		ID: "peer-b", EnvironmentID: "dr", InstanceID: "node-b", Endpoint: peer.URL, Token: "peer-secret", Timeout: time.Second,
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.ReadSummary(context.Background(), "tenant-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Nodes[1].Available || result.Nodes[1].ErrorCode != "RESPONSE_INVALID" || len(result.Origins) != 1 {
		t.Fatalf("invalid peer response accepted: nodes=%+v origins=%+v", result.Nodes, result.Origins)
	}
}

func TestNewFederatedReaderEnforcesPeerAndOriginBounds(t *testing.T) {
	local := staticSummaryReader{}
	peers := make([]FederationPeer, maxFederationPeers+1)
	for index := range peers {
		peers[index] = FederationPeer{ID: "peer-" + string(rune(index+1)), EnvironmentID: "env", InstanceID: "node-" + string(rune(index+1)), Endpoint: "https://example.com", Token: "secret", Timeout: time.Second}
	}
	if _, err := NewFederatedReader(local, "prod", "node-a", peers); err == nil {
		t.Fatal("peer bound was not enforced")
	}
	duplicateOrigin := []FederationPeer{{ID: "peer-b", EnvironmentID: "prod", InstanceID: "node-a", Endpoint: "https://example.com", Token: "secret", Timeout: time.Second}}
	if _, err := NewFederatedReader(local, "prod", "node-a", duplicateOrigin); err == nil {
		t.Fatal("duplicate origin was not rejected")
	}
}
