package mapping

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const TaxonomyConfigVersion = "ulpf-taxonomies/1"

// TaxonomyConfig is the optional bundle-level vocabulary artifact. Keeping it
// separate lets multiple mapping revisions reuse a reviewed vocabulary while
// the compiled Engine still owns a complete immutable copy.
type TaxonomyConfig struct {
	ConfigVersion string                         `json:"config_version"`
	Taxonomies    map[string]map[string][]string `json:"taxonomies"`
}

// LoadConfigWithTaxonomies strictly decodes a mapping and an optional external
// taxonomy artifact before compiling one immutable mapping engine.
func LoadConfigWithTaxonomies(mappingJSON, taxonomyJSON []byte) (*Engine, error) {
	config, err := decodeConfig(mappingJSON)
	if err != nil {
		return nil, err
	}
	if len(taxonomyJSON) == 0 {
		return New(config)
	}
	if len(taxonomyJSON) > maxConfigSize {
		return nil, fmt.Errorf("taxonomy config exceeds %d bytes", maxConfigSize)
	}
	decoder := json.NewDecoder(bytes.NewReader(taxonomyJSON))
	decoder.DisallowUnknownFields()
	var external TaxonomyConfig
	if err := decoder.Decode(&external); err != nil {
		return nil, fmt.Errorf("decode taxonomy config: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if external.ConfigVersion != TaxonomyConfigVersion {
		return nil, fmt.Errorf("taxonomy config_version must be %q", TaxonomyConfigVersion)
	}
	if len(external.Taxonomies) == 0 {
		return nil, errors.New("taxonomy config must contain at least one taxonomy")
	}
	if config.Taxonomies == nil {
		config.Taxonomies = make(map[string]map[string][]string, len(external.Taxonomies))
	}
	for name, values := range external.Taxonomies {
		if _, duplicate := config.Taxonomies[name]; duplicate {
			return nil, fmt.Errorf("taxonomy %q is declared in both mapping and taxonomy artifacts", name)
		}
		config.Taxonomies[name] = values
	}
	return New(config)
}

func decodeConfig(encoded []byte) (Config, error) {
	if len(encoded) > maxConfigSize {
		return Config{}, fmt.Errorf("mapping config exceeds %d bytes", maxConfigSize)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode mapping config: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Config{}, err
	}
	return config, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing mapping config: %w", err)
	}
	return errors.New("mapping config contains more than one JSON value")
}
