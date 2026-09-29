package analytics_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	parquetgo "github.com/parquet-go/parquet-go"
	"github.com/sidd20228/universal_log_framework/internal/analytics"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

func TestExportDatasetIsTenantScopedDeterministicAndReadable(t *testing.T) {
	partial := analyticsEnvelope(t)
	parsed := partial
	parsed.Receipt.ID = "0199a1f0-7c4a-7b2c-8e25-8b4627a1c002"
	parsed.Receipt.ReceivedAt = partial.Receipt.ReceivedAt.Add(time.Second)
	parsed.Processing.RevisionID = "0199a1f0-81b2-7680-89c3-d5c53fe8e003"
	parsed.Processing.Status = model.StatusParsed
	request := exportRequest(t.TempDir(), analytics.PartialInclude)

	first, err := analytics.ExportDataset(context.Background(), staticEnvelopeSource{partial, parsed}, request)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := analytics.ExportDataset(context.Background(), staticEnvelopeSource{partial, parsed}, request)
	if err != nil || repeated.Manifest.DatasetID != first.Manifest.DatasetID {
		t.Fatalf("idempotent export=%+v err=%v", repeated, err)
	}
	request.OutputRoot = t.TempDir()
	second, err := analytics.ExportDataset(context.Background(), staticEnvelopeSource{parsed, partial}, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Manifest.DatasetID != second.Manifest.DatasetID || first.Manifest.Artifact.SHA256 != second.Manifest.Artifact.SHA256 {
		t.Fatalf("exports differ: first=%+v second=%+v", first.Manifest, second.Manifest)
	}
	rows, err := parquetgo.ReadFile[analytics.DatasetRow](first.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].RevisionID > rows[1].RevisionID {
		t.Fatalf("rows = %#v", rows)
	}
	if rows[0].Split != analytics.AssignSplit(rows[0].RevisionID, request.Split) || !strings.Contains(rows[0].FeaturesJSON, `"action":"deny"`) {
		t.Fatalf("projected row = %#v", rows[0])
	}
	body, err := os.ReadFile(first.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := analytics.LoadDatasetManifest(body)
	if err != nil || loaded.Revisions.Count != 2 || loaded.Selection.PartialEventPolicy != analytics.PartialInclude {
		t.Fatalf("manifest = %+v, %v", loaded, err)
	}
}

func TestExportDatasetPartialPolicyIsExplicit(t *testing.T) {
	partial := analyticsEnvelope(t)
	parsed := partial
	parsed.Receipt.ID = "0199a1f0-7c4a-7b2c-8e25-8b4627a1c002"
	parsed.Receipt.ReceivedAt = partial.Receipt.ReceivedAt.Add(time.Second)
	parsed.Processing.RevisionID = "0199a1f0-81b2-7680-89c3-d5c53fe8e003"
	parsed.Processing.Status = model.StatusParsed

	exclude := exportRequest(t.TempDir(), analytics.PartialExclude)
	result, err := analytics.ExportDataset(context.Background(), staticEnvelopeSource{partial, parsed}, exclude)
	if err != nil || result.Manifest.Revisions.Count != 1 {
		t.Fatalf("exclude result=%+v err=%v", result, err)
	}
	reject := exportRequest(t.TempDir(), analytics.PartialReject)
	if _, err := analytics.ExportDataset(context.Background(), staticEnvelopeSource{partial, parsed}, reject); err == nil || !strings.Contains(err.Error(), "rejected by dataset policy") {
		t.Fatalf("reject error = %v", err)
	}
}

func TestExportDatasetRejectsCrossTenantAndMissingRequiredFeature(t *testing.T) {
	value := analyticsEnvelope(t)
	value.Receipt.TenantID = "other"
	if _, err := analytics.ExportDataset(context.Background(), staticEnvelopeSource{value}, exportRequest(t.TempDir(), analytics.PartialInclude)); err == nil || !strings.Contains(err.Error(), "cross-tenant") {
		t.Fatalf("cross-tenant error = %v", err)
	}
	value = analyticsEnvelope(t)
	request := exportRequest(t.TempDir(), analytics.PartialInclude)
	request.FeatureSet.Features[0].NullPolicy = analytics.NullRequired
	request.FeatureSet.Features[0].SourcePath = "event.activity"
	if _, err := analytics.ExportDataset(context.Background(), staticEnvelopeSource{value}, request); err == nil || !strings.Contains(err.Error(), "missing required feature") {
		t.Fatalf("required feature error = %v", err)
	}
}

type staticEnvelopeSource []envelope.Envelope

func (source staticEnvelopeSource) ListEnvelopes(_ context.Context, _ string, _ time.Time, afterReceipt, _ string, _ int) ([]envelope.Envelope, error) {
	if afterReceipt != "" {
		return nil, nil
	}
	return append([]envelope.Envelope(nil), source...), nil
}

func analyticsEnvelope(t *testing.T) envelope.Envelope {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "envelope", "testdata", "envelope.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var value envelope.Envelope
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func exportRequest(root string, policy analytics.PartialEventPolicy) analytics.ExportRequest {
	return analytics.ExportRequest{
		TenantID: "demo", OutputRoot: root,
		FeatureSet: analytics.FeatureSet{
			ContractVersion: analytics.FeatureSetContractVersion, ID: "network-risk", Version: "1.0.0", EnvelopeSchemaVersion: envelope.SchemaVersion,
			Features: []analytics.FeatureDefinition{
				{Name: "action", Type: analytics.FeatureString, SourcePath: "event.action", NullPolicy: analytics.NullNullable},
				{Name: "quality_score", Type: analytics.FeatureNumber, SourcePath: "quality.score", NullPolicy: analytics.NullRequired},
				{Name: "source_ip", Type: analytics.FeatureIP, SourcePath: "event.src_endpoint.ip", NullPolicy: analytics.NullNullable},
			},
		},
		Selection: analytics.DatasetSelection{
			ReceivedFrom: time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC), ReceivedTo: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
			Statuses: []model.InterpretationStatus{model.StatusParsed, model.StatusPartiallyParsed}, PartialEventPolicy: policy,
		},
		Split: analytics.SplitPolicy{Algorithm: "sha256_revision_id_v1", Seed: "evaluation-v1", TrainBasisPoints: 8000, ValidationBasisPoints: 1000, TestBasisPoints: 1000},
	}
}
