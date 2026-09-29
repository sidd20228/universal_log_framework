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

const (
	maxFederationPeers         = 64
	maxFederationResponseBytes = 4 << 20
	maxPeerActivityBuckets     = int(activityWindow / activityBucket)
	peerStaleAfter             = 2 * time.Minute
	maximumPeerClockSkew       = time.Minute
)

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
	Retained      bool      `json:"retained"`
	GeneratedAt   time.Time `json:"generated_at,omitempty"`
	LastSeenAt    time.Time `json:"last_seen_at,omitempty"`
	ErrorCode     string    `json:"error_code,omitempty"`
}

type cachedPeerSummary struct {
	tenantID   string
	summary    Summary
	lastSeenAt time.Time
}

type FederatedReader struct {
	local         Reader
	environmentID string
	instanceID    string
	peers         []FederationPeer
	client        *http.Client
	historyMu     sync.RWMutex
	history       map[string]cachedPeerSummary
}

func NewFederatedReader(local Reader, environmentID, instanceID string, peers []FederationPeer) (*FederatedReader, error) {
	if local == nil || strings.TrimSpace(environmentID) == "" || strings.TrimSpace(instanceID) == "" {
		return nil, errors.New("local reader and origin identity are required")
	}
	if len(peers) > maxFederationPeers {
		return nil, fmt.Errorf("federation supports at most %d peers", maxFederationPeers)
	}
	copyPeers := append([]FederationPeer(nil), peers...)
	peerIDs := make(map[string]struct{}, len(copyPeers))
	origins := map[string]struct{}{environmentID + "\x00" + instanceID: {}}
	for _, peer := range copyPeers {
		parsed, err := url.Parse(peer.Endpoint)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost"))) {
			return nil, fmt.Errorf("federation peer %q has an invalid endpoint", peer.ID)
		}
		if peer.ID == "" || peer.EnvironmentID == "" || peer.InstanceID == "" || peer.Token == "" || peer.Timeout <= 0 || peer.Timeout > 30*time.Second {
			return nil, fmt.Errorf("federation peer %q is incomplete", peer.ID)
		}
		if _, duplicate := peerIDs[peer.ID]; duplicate {
			return nil, fmt.Errorf("federation peer id %q is duplicated", peer.ID)
		}
		peerIDs[peer.ID] = struct{}{}
		origin := peer.EnvironmentID + "\x00" + peer.InstanceID
		if _, duplicate := origins[origin]; duplicate {
			return nil, fmt.Errorf("federation origin %q/%q is duplicated", peer.EnvironmentID, peer.InstanceID)
		}
		origins[origin] = struct{}{}
	}
	return &FederatedReader{
		local: local, environmentID: environmentID, instanceID: instanceID,
		peers: copyPeers, client: &http.Client{}, history: make(map[string]cachedPeerSummary, len(copyPeers)),
	}, nil
}

func (reader *FederatedReader) ReadSummary(ctx context.Context, tenantID string, now time.Time) (Summary, error) {
	local, err := reader.local.ReadSummary(ctx, tenantID, now)
	if err != nil {
		return Summary{}, err
	}
	local.EnvironmentID, local.InstanceID = reader.environmentID, reader.instanceID
	local.Nodes = []NodeStatus{{
		ID: "local", EnvironmentID: reader.environmentID, InstanceID: reader.instanceID,
		Available: true, GeneratedAt: local.GeneratedAt, LastSeenAt: now,
	}}
	for index := range local.RecentEvents {
		if local.RecentEvents[index].EnvironmentID == "" {
			local.RecentEvents[index].EnvironmentID = reader.environmentID
			local.RecentEvents[index].InstanceID = reader.instanceID
		}
	}
	local.Origins = []OriginSummary{originSummary("local", local, local.Nodes[0])}
	if len(reader.peers) == 0 {
		return local, nil
	}
	type result struct {
		index      int
		summary    Summary
		status     NodeStatus
		hasSummary bool
	}
	results := make(chan result, len(reader.peers))
	var group sync.WaitGroup
	for index, peer := range reader.peers {
		group.Add(1)
		go func(index int, peer FederationPeer) {
			defer group.Done()
			summary, status, hasSummary := reader.readPeer(ctx, peer, tenantID, now)
			results <- result{index: index, summary: summary, status: status, hasSummary: hasSummary}
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
		if value.hasSummary {
			mergeSummary(&local, value.summary)
			local.Origins = append(local.Origins, originSummary(value.status.ID, value.summary, value.status))
		}
	}
	local.Pipeline = buildPipeline(local.Totals, local.ReceiptStateCounts)
	return local, nil
}

func (reader *FederatedReader) readPeer(parent context.Context, peer FederationPeer, tenantID string, now time.Time) (Summary, NodeStatus, bool) {
	status := NodeStatus{ID: peer.ID, EnvironmentID: peer.EnvironmentID, InstanceID: peer.InstanceID}
	ctx, cancel := context.WithTimeout(parent, peer.Timeout)
	defer cancel()
	endpoint := strings.TrimRight(peer.Endpoint, "/") + "/api/v1/dashboard/summary?tenant_id=" + url.QueryEscape(tenantID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return reader.lastKnown(peer, tenantID, status, "REQUEST_INVALID")
	}
	request.Header.Set("Authorization", "Bearer "+peer.Token)
	request.Header.Set("Accept", "application/json")
	response, err := reader.client.Do(request)
	if err != nil {
		return reader.lastKnown(peer, tenantID, status, "UNAVAILABLE")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return reader.lastKnown(peer, tenantID, status, "HTTP_"+fmt.Sprint(response.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxFederationResponseBytes+1))
	if err != nil || len(body) > maxFederationResponseBytes {
		return reader.lastKnown(peer, tenantID, status, "RESPONSE_INVALID")
	}
	var summary Summary
	if err := json.Unmarshal(body, &summary); err != nil || validatePeerSummary(summary, peer, tenantID, now) != nil {
		return reader.lastKnown(peer, tenantID, status, "RESPONSE_INVALID")
	}
	// Only direct peer data is retained. Discard transitive metadata so cyclic
	// federation configurations cannot multiply nested origin histories.
	summary.Nodes = nil
	summary.Origins = nil
	status.Available = true
	status.GeneratedAt = summary.GeneratedAt
	status.LastSeenAt = now
	status.Stale = now.Sub(summary.GeneratedAt) > peerStaleAfter
	for index := range summary.RecentEvents {
		summary.RecentEvents[index].EnvironmentID = peer.EnvironmentID
		summary.RecentEvents[index].InstanceID = peer.InstanceID
		receiptURL := proxyPeerURL(peer.ID, summary.RecentEvents[index].ReceiptURL)
		eventURL := proxyPeerURL(peer.ID, summary.RecentEvents[index].EventURL)
		if receiptURL == "" || eventURL == "" {
			return reader.lastKnown(peer, tenantID, status, "RESPONSE_INVALID")
		}
		summary.RecentEvents[index].ReceiptURL = receiptURL
		summary.RecentEvents[index].EventURL = eventURL
	}
	reader.historyMu.Lock()
	reader.history[peer.ID] = cachedPeerSummary{tenantID: tenantID, summary: cloneSummary(summary), lastSeenAt: now}
	reader.historyMu.Unlock()
	return summary, status, true
}

func (reader *FederatedReader) lastKnown(peer FederationPeer, tenantID string, status NodeStatus, code string) (Summary, NodeStatus, bool) {
	status.ErrorCode = code
	status.Stale = true
	reader.historyMu.RLock()
	cached, found := reader.history[peer.ID]
	reader.historyMu.RUnlock()
	if !found || cached.tenantID != tenantID {
		return Summary{}, status, false
	}
	status.Retained = true
	status.GeneratedAt = cached.summary.GeneratedAt
	status.LastSeenAt = cached.lastSeenAt
	return cloneSummary(cached.summary), status, true
}

func validatePeerSummary(summary Summary, peer FederationPeer, tenantID string, now time.Time) error {
	if summary.TenantID != tenantID || summary.GeneratedAt.IsZero() || summary.GeneratedAt.After(now.Add(maximumPeerClockSkew)) {
		return errors.New("peer summary identity or time is invalid")
	}
	if summary.EnvironmentID != "" && summary.EnvironmentID != peer.EnvironmentID || summary.InstanceID != "" && summary.InstanceID != peer.InstanceID {
		return errors.New("peer summary origin does not match configuration")
	}
	if len(summary.Activity) > maxPeerActivityBuckets || len(summary.RecentEvents) > recentLimit {
		return errors.New("peer summary exceeds bounded collections")
	}
	values := []int64{
		summary.Totals.Receipts, summary.Totals.Revisions, summary.Totals.RawBytes, summary.Totals.Pending,
		summary.Totals.Failed, summary.Totals.Delivered, summary.AcceptedTotal, summary.CommittedTotal,
	}
	for _, value := range values {
		if value < 0 {
			return errors.New("peer summary contains a negative counter")
		}
	}
	if err := validateBoundedCounts(summary.ReceiptStateCounts, receiptStates); err != nil {
		return err
	}
	if err := validateBoundedCounts(summary.StatusCounts, interpretationStatuses); err != nil {
		return err
	}
	for _, event := range summary.RecentEvents {
		if event.TenantID != tenantID {
			return errors.New("peer summary contains a cross-tenant event")
		}
	}
	return nil
}

func validateBoundedCounts(values map[string]int64, allowed []string) error {
	if len(values) > len(allowed) {
		return errors.New("peer summary contains too many counter groups")
	}
	known := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		known[name] = struct{}{}
	}
	for name, count := range values {
		if _, found := known[name]; !found || count < 0 {
			return errors.New("peer summary contains an invalid counter group")
		}
	}
	return nil
}

func proxyPeerURL(peerID, path string) string {
	const prefix = "/api/v1/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 || (parts[0] != "events" && parts[0] != "receipts") || parts[1] == "" || strings.ContainsAny(parts[1], "?#\\") {
		return ""
	}
	return "/api/v1/federation/" + url.PathEscape(peerID) + "/" + parts[0] + "/" + url.PathEscape(parts[1])
}

func originSummary(peerID string, summary Summary, status NodeStatus) OriginSummary {
	return OriginSummary{
		PeerID: peerID, EnvironmentID: status.EnvironmentID, InstanceID: status.InstanceID,
		Available: status.Available, Stale: status.Stale, Retained: status.Retained,
		GeneratedAt: summary.GeneratedAt, LastSeenAt: status.LastSeenAt,
		Totals: summary.Totals, AcceptedTotal: summary.AcceptedTotal, CommittedTotal: summary.CommittedTotal,
		ReceiptStateCounts: cloneCounts(summary.ReceiptStateCounts), StatusCounts: cloneCounts(summary.StatusCounts),
		Pipeline: append([]PipelineStage(nil), summary.Pipeline...), Activity: append([]ActivityBucket(nil), summary.Activity...),
		RecentEvents: append([]RecentEvent(nil), summary.RecentEvents...),
	}
}

func cloneSummary(source Summary) Summary {
	clone := source
	clone.ReceiptStateCounts = cloneCounts(source.ReceiptStateCounts)
	clone.StatusCounts = cloneCounts(source.StatusCounts)
	clone.Pipeline = append([]PipelineStage(nil), source.Pipeline...)
	clone.Activity = append([]ActivityBucket(nil), source.Activity...)
	clone.RecentEvents = append([]RecentEvent(nil), source.RecentEvents...)
	clone.Nodes = append([]NodeStatus(nil), source.Nodes...)
	clone.Origins = append([]OriginSummary(nil), source.Origins...)
	return clone
}

func cloneCounts(source map[string]int64) map[string]int64 {
	clone := make(map[string]int64, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
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
	if target.ReceiptStateCounts == nil {
		target.ReceiptStateCounts = make(map[string]int64)
	}
	if target.StatusCounts == nil {
		target.StatusCounts = make(map[string]int64)
	}
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
