package analytics_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sidd20228/universal_log_framework/internal/analytics"
	"github.com/sidd20228/universal_log_framework/internal/envelope"
	"github.com/sidd20228/universal_log_framework/internal/model"
)

func TestFeatureSetValidationAndDigestAreDeterministic(t *testing.T) {
	set := validFeatureSet()
	first, err := set.Digest()
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.Digest()
	if err != nil || first != second || len(first) != 64 {
		t.Fatalf("digests = %q/%q, error = %v", first, second, err)
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := analytics.LoadFeatureSet(body)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != set.ID || len(loaded.Features) != len(set.Features) {
		t.Fatalf("loaded feature set = %#v", loaded)
	}
}

func TestFeatureSetRejectsUnsafeAmbiguousAndUnknownDefinitions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*analytics.FeatureSet)
	}{
		{"raw source", func(set *analytics.FeatureSet) { set.Features[0].SourcePath = "raw.payload" }},
		{"parsed source", func(set *analytics.FeatureSet) { set.Features[0].SourcePath = "parsed.fields.password" }},
		{"duplicate name", func(set *analytics.FeatureSet) { set.Features[1].Name = set.Features[0].Name }},
		{"duplicate path", func(set *analytics.FeatureSet) { set.Features[1].SourcePath = set.Features[0].SourcePath }},
		{"unordered", func(set *analytics.FeatureSet) { set.Features[0], set.Features[1] = set.Features[1], set.Features[0] }},
		{"invalid type", func(set *analytics.FeatureSet) { set.Features[0].Type = "embedding" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := validFeatureSet()
			test.mutate(&set)
			if err := set.Validate(); err == nil {
				t.Fatal("Validate accepted invalid feature set")
			}
		})
	}
	body, _ := json.Marshal(validFeatureSet())
	body = append(body[:len(body)-1], []byte(`,"unknown":true}`)...)
	if _, err := analytics.LoadFeatureSet(body); err == nil {
		t.Fatal("LoadFeatureSet accepted an unknown field")
	}
	if _, err := analytics.LoadFeatureSet(append(body, []byte(` {}`)...)); err == nil {
		t.Fatal("LoadFeatureSet accepted multiple JSON values")
	}
}

func TestDatasetManifestBindsIdentityAndArtifact(t *testing.T) {
	manifest := validManifest(t)
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := analytics.LoadDatasetManifest(body)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DatasetID != manifest.DatasetID || loaded.Artifact.Rows != 2 {
		t.Fatalf("loaded manifest = %#v", loaded)
	}

	mirrored := manifest
	mirrored.Artifact.Path = "mirror/dataset.parquet"
	mirrored.Artifact.SHA256 = strings.Repeat("c", 64)
	if identity, err := mirrored.ExpectedDatasetID(); err != nil || identity != manifest.DatasetID {
		t.Fatalf("mirrored identity = %q, %v; want %q", identity, err, manifest.DatasetID)
	}
	changed := manifest
	changed.Revisions.SHA256 = strings.Repeat("d", 64)
	if identity, err := changed.ExpectedDatasetID(); err != nil || identity == manifest.DatasetID {
		t.Fatalf("changed identity = %q, %v", identity, err)
	}
}

func TestDatasetManifestRejectsTamperingAndUnsafePaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*analytics.DatasetManifest)
	}{
		{"identity mismatch", func(value *analytics.DatasetManifest) { value.DatasetID = strings.Repeat("0", 64) }},
		{"cross platform traversal", func(value *analytics.DatasetManifest) { value.Artifact.Path = `..\secret.parquet` }},
		{"relative traversal", func(value *analytics.DatasetManifest) { value.Artifact.Path = "../secret.parquet" }},
		{"row mismatch", func(value *analytics.DatasetManifest) { value.Artifact.Rows++ }},
		{"lineage removed", func(value *analytics.DatasetManifest) { value.LineageFields = value.LineageFields[1:] }},
		{"split total", func(value *analytics.DatasetManifest) { value.Split.TestBasisPoints-- }},
		{"statuses unordered", func(value *analytics.DatasetManifest) {
			value.Selection.Statuses = []model.InterpretationStatus{model.StatusUnparsed, model.StatusParsed}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest(t)
			test.mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("Validate accepted tampered manifest")
			}
		})
	}
}

func TestSortedRevisionDigestIsOrderIndependentAndRejectsDuplicates(t *testing.T) {
	first, err := analytics.SortedRevisionDigest([]string{"revision-b", "revision-a"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := analytics.SortedRevisionDigest([]string{"revision-a", "revision-b"})
	if err != nil || first != second {
		t.Fatalf("revision digests = %q/%q, %v", first, second, err)
	}
	if _, err := analytics.SortedRevisionDigest([]string{"revision-a", "revision-a"}); err == nil {
		t.Fatal("SortedRevisionDigest accepted a duplicate")
	}
}

func validFeatureSet() analytics.FeatureSet {
	return analytics.FeatureSet{
		ContractVersion: analytics.FeatureSetContractVersion, ID: "network-risk", Version: "1.0.0",
		EnvelopeSchemaVersion: envelope.SchemaVersion,
		Features: []analytics.FeatureDefinition{
			{Name: "action", Type: analytics.FeatureString, SourcePath: "event.action", NullPolicy: analytics.NullNullable},
			{Name: "quality_score", Type: analytics.FeatureNumber, SourcePath: "quality.score", NullPolicy: analytics.NullRequired},
			{Name: "source_ip", Type: analytics.FeatureIP, SourcePath: "event.src_endpoint.ip", NullPolicy: analytics.NullNullable},
		},
	}
}

func validManifest(t *testing.T) analytics.DatasetManifest {
	t.Helper()
	featureDigest, err := validFeatureSet().Digest()
	if err != nil {
		t.Fatal(err)
	}
	revisionDigest, err := analytics.SortedRevisionDigest([]string{"revision-a", "revision-b"})
	if err != nil {
		t.Fatal(err)
	}
	manifest := analytics.DatasetManifest{
		ContractVersion: analytics.DatasetManifestContractVersion, TenantID: "tenant-a",
		EnvelopeSchemaVersion: envelope.SchemaVersion,
		FeatureSet:            analytics.FeatureSetReference{ID: "network-risk", Version: "1.0.0", SHA256: featureDigest},
		Selection: analytics.DatasetSelection{
			ReceivedFrom: time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC),
			ReceivedTo:   time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC),
			Statuses:     []model.InterpretationStatus{model.StatusParsed, model.StatusUnparsed},
		},
		Revisions: analytics.RevisionSet{Count: 2, SHA256: revisionDigest},
		Split: analytics.SplitPolicy{
			Algorithm: "sha256_revision_id_v1", Seed: "evaluation-v1",
			TrainBasisPoints: 8000, ValidationBasisPoints: 1000, TestBasisPoints: 1000,
		},
		Artifact: analytics.DatasetArtifact{
			Format: "parquet", Path: "tenant=tenant-a/dataset.parquet", SHA256: strings.Repeat("b", 64), Rows: 2,
		},
		LineageFields: analytics.RequiredLineageFields(),
	}
	manifest.DatasetID, err = manifest.ExpectedDatasetID()
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}
