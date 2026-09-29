package dashboardapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
}
