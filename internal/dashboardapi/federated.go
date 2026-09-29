package dashboardapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxFederationResponseBytes = 4 << 20

type FederationPeer struct {
	ID            string
	EnvironmentID string
	InstanceID    string
	Endpoint      string
	Token         string
	Timeout       time.Duration
}

type NodeStatus struct {
	ID            string    `json:"id"`
	EnvironmentID string    `json:"environment_id"`
	InstanceID    string    `json:"instance_id"`
	Available     bool      `json:"available"`
	Stale         bool      `json:"stale"`
	GeneratedAt   time.Time `json:"generated_at,omitempty"`
	ErrorCode     string    `json:"error_code,omitempty"`
}

type FederatedReader struct {
	local         Reader
	environmentID string
	instanceID    string
	peers         []FederationPeer
	client        *http.Client
}

func NewFederatedReader(local Reader, environmentID, instanceID string, peers []FederationPeer) (*FederatedReader, error) {
	if local == nil || strings.TrimSpace(environmentID) == "" || strings.TrimSpace(instanceID) == "" {
		return nil, errors.New("local reader and origin identity are required")
	}
	if len(peers) > 64 {
		return nil, errors.New("federation supports at most 64 peers")
	}
	copyPeers := append([]FederationPeer(nil), peers...)
	for _, peer := range copyPeers {
		parsed, err := url.Parse(peer.Endpoint)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost"))) {
			return nil, fmt.Errorf("federation peer %q has an invalid endpoint", peer.ID)
		}
		if peer.ID == "" || peer.EnvironmentID == "" || peer.InstanceID == "" || peer.Token == "" || peer.Timeout <= 0 || peer.Timeout > 30*time.Second {
			return nil, fmt.Errorf("federation peer %q is incomplete", peer.ID)
		}
	}
	return &FederatedReader{local: local, environmentID: environmentID, instanceID: instanceID, peers: copyPeers, client: &http.Client{}}, nil
}

func (reader *FederatedReader) ReadSummary(ctx context.Context, tenantID string, now time.Time) (Summary, error) {
	local, err := reader.local.ReadSummary(ctx, tenantID, now)
	if err != nil {
		return Summary{}, err
	}
	local.EnvironmentID, local.InstanceID = reader.environmentID, reader.instanceID
	local.Nodes = []NodeStatus{{ID: "local", EnvironmentID: reader.environmentID, InstanceID: reader.instanceID, Available: true, GeneratedAt: local.GeneratedAt}}
	for index := range local.RecentEvents {
		if local.RecentEvents[index].EnvironmentID == "" {
			local.RecentEvents[index].EnvironmentID = reader.environmentID
			local.RecentEvents[index].InstanceID = reader.instanceID
		}
	}
	if len(reader.peers) == 0 {
		return local, nil
	}
	type result struct {
		index   int
		summary Summary
		status  NodeStatus
	}
	results := make(chan result, len(reader.peers))
	var group sync.WaitGroup
	for index, peer := range reader.peers {
		group.Add(1)
		go func(index int, peer FederationPeer) {
			defer group.Done()
			summary, status := reader.readPeer(ctx, peer, tenantID, now)
			results <- result{index: index, summary: summary, status: status}
		}(index, peer)
	}
	group.Wait()
	close(results)
	ordered := make([]result, len(reader.peers))
	for value := range results {
		ordered[value.index] = value
	}
	for _, value := range ordered {
		local.Nodes = append(local.Nodes, value.status)
		if value.status.Available {
			mergeSummary(&local, value.summary)
		}
	}
	local.Pipeline = buildPipeline(local.Totals, local.ReceiptStateCounts)
	return local, nil
}

func (reader *FederatedReader) readPeer(parent context.Context, peer FederationPeer, tenantID string, now time.Time) (Summary, NodeStatus) {
	status := NodeStatus{ID: peer.ID, EnvironmentID: peer.EnvironmentID, InstanceID: peer.InstanceID}
	ctx, cancel := context.WithTimeout(parent, peer.Timeout)
	defer cancel()
	endpoint := strings.TrimRight(peer.Endpoint, "/") + "/api/v1/dashboard/summary?tenant_id=" + url.QueryEscape(tenantID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		status.ErrorCode = "REQUEST_INVALID"
		return Summary{}, status
	}
	request.Header.Set("Authorization", "Bearer "+peer.Token)
	request.Header.Set("Accept", "application/json")
	response, err := reader.client.Do(request)
	if err != nil {
		status.ErrorCode = "UNAVAILABLE"
		return Summary{}, status
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		status.ErrorCode = "HTTP_" + fmt.Sprint(response.StatusCode)
		return Summary{}, status
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxFederationResponseBytes+1))
	if err != nil || len(body) > maxFederationResponseBytes {
		status.ErrorCode = "RESPONSE_INVALID"
		return Summary{}, status
	}
	var summary Summary
	if err := json.Unmarshal(body, &summary); err != nil || summary.TenantID != tenantID {
		status.ErrorCode = "RESPONSE_INVALID"
		return Summary{}, status
	}
	status.Available = true
	status.GeneratedAt = summary.GeneratedAt
	status.Stale = summary.GeneratedAt.IsZero() || now.Sub(summary.GeneratedAt) > 2*time.Minute
	for index := range summary.RecentEvents {
		summary.RecentEvents[index].EnvironmentID = peer.EnvironmentID
		summary.RecentEvents[index].InstanceID = peer.InstanceID
		summary.RecentEvents[index].ReceiptURL = proxyPeerURL(peer.ID, summary.RecentEvents[index].ReceiptURL)
		summary.RecentEvents[index].EventURL = proxyPeerURL(peer.ID, summary.RecentEvents[index].EventURL)
	}
	return summary, status
}

func proxyPeerURL(peerID, path string) string {
	const prefix = "/api/v1/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return "/api/v1/federation/" + url.PathEscape(peerID) + "/" + strings.TrimPrefix(path, prefix)
}

func mergeSummary(target *Summary, source Summary) {
	target.Totals.Receipts += source.Totals.Receipts
	target.Totals.Revisions += source.Totals.Revisions
	target.Totals.RawBytes += source.Totals.RawBytes
	target.Totals.Pending += source.Totals.Pending
	target.Totals.Failed += source.Totals.Failed
	target.Totals.Delivered += source.Totals.Delivered
	target.AcceptedTotal += source.AcceptedTotal
	target.CommittedTotal += source.CommittedTotal
	for key, count := range source.ReceiptStateCounts {
		target.ReceiptStateCounts[key] += count
	}
	for key, count := range source.StatusCounts {
		target.StatusCounts[key] += count
	}
	activity := make(map[int64]*ActivityBucket, len(target.Activity))
	for index := range target.Activity {
		activity[target.Activity[index].Time.UnixNano()] = &target.Activity[index]
	}
	for _, bucket := range source.Activity {
		if current := activity[bucket.Time.UnixNano()]; current != nil {
			current.Accepted += bucket.Accepted
			current.Committed += bucket.Committed
		}
	}
	target.RecentEvents = append(target.RecentEvents, source.RecentEvents...)
	sort.Slice(target.RecentEvents, func(left, right int) bool {
		return target.RecentEvents[left].ReceivedAt.After(target.RecentEvents[right].ReceivedAt)
	})
	if len(target.RecentEvents) > recentLimit {
		target.RecentEvents = target.RecentEvents[:recentLimit]
	}
}

var _ Reader = (*FederatedReader)(nil)
