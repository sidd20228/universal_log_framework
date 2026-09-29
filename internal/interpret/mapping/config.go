package mapping

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)*$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
)

type targetKind uint8

const (
	targetString targetKind = iota + 1
	targetString64
	targetString128
	targetString255
	targetString512
	targetNonNegativeInteger
	targetSeverityID
	targetProtocolNumber
	targetIP
	targetPort
	targetTimestamp
	targetAction
	targetDevice
	targetSeverity
	targetProtocol
	targetMAC
	targetExtension
)

var allowedTargets = map[string]targetKind{
	"event.class_uid":                     targetNonNegativeInteger,
	"event.class_name":                    targetString128,
	"event.activity_id":                   targetNonNegativeInteger,
	"event.activity":                      targetString128,
	"event.time":                          targetTimestamp,
	"event.action":                        targetAction,
	"event.status":                        targetString64,
	"event.severity_id":                   targetSeverityID,
	"event.severity":                      targetSeverity,
	"event.src_endpoint.ip":               targetIP,
	"event.src_endpoint.port":             targetPort,
	"event.src_endpoint.hostname":         targetString255,
	"event.src_endpoint.mac":              targetMAC,
	"event.dst_endpoint.ip":               targetIP,
	"event.dst_endpoint.port":             targetPort,
	"event.dst_endpoint.hostname":         targetString255,
	"event.dst_endpoint.mac":              targetMAC,
	"event.connection_info.protocol_name": targetProtocol,
	"event.connection_info.protocol_num":  targetProtocolNumber,
	"event.device.type":                   targetDevice,
	"event.device.hostname":               targetString255,
	"event.device.vendor_name":            targetString128,
	"event.device.product_name":           targetString128,
	"event.finding.signature":             targetString512,
	"event.finding.signature_id":          targetNonNegativeInteger,
}

var allowedActions = map[string]struct{}{
	"allow": {}, "deny": {}, "observe": {}, "quarantine": {},
	"reset": {}, "redirect": {}, "unknown": {},
}

var allowedDeviceTypes = map[string]struct{}{
	"firewall": {}, "router": {}, "switch": {}, "ids": {}, "ips": {},
	"proxy": {}, "vpn": {}, "unknown": {},
}

var allowedSeverities = map[string]struct{}{
	"unknown": {}, "informational": {}, "low": {}, "medium": {}, "high": {}, "critical": {},
}

func LoadConfig(encoded []byte) (*Engine, error) {
	config, err := decodeConfig(encoded)
	if err != nil {
		return nil, err
	}
	return New(config)
}

func New(config Config) (*Engine, error) {
	if config.ConfigVersion != ConfigVersion {
		return nil, fmt.Errorf("config_version must be %q", ConfigVersion)
	}
	if !identifierPattern.MatchString(config.ID) {
		return nil, errors.New("mapping id must be a lowercase identifier")
	}
	if !versionPattern.MatchString(config.Version) {
		return nil, errors.New("mapping version must be a semantic version")
	}
	if len(config.Rules) == 0 {
		return nil, errors.New("mapping must contain at least one rule")
	}
	if len(config.Rules) > MaxRules {
		return nil, fmt.Errorf("mapping has %d rules; maximum is %d", len(config.Rules), MaxRules)
	}
	if len(config.Taxonomies) > MaxTaxonomies {
		return nil, fmt.Errorf("mapping has %d taxonomies; maximum is %d", len(config.Taxonomies), MaxTaxonomies)
	}

	compiledTaxonomies, err := compileTaxonomies(config.Taxonomies)
	if err != nil {
		return nil, err
	}
	rules := make([]compiledRule, 0, len(config.Rules))
	seenRules := make(map[string]struct{}, len(config.Rules))
	seenTargets := make(map[string]struct{}, len(config.Rules))
	for index, original := range config.Rules {
		rule := cloneRule(original)
		if err := validateRule(rule, compiledTaxonomies); err != nil {
			return nil, fmt.Errorf("rule %d: %w", index, err)
		}
		if _, exists := seenRules[rule.ID]; exists {
			return nil, fmt.Errorf("rule %d: duplicate rule id %q", index, rule.ID)
		}
		if _, exists := seenTargets[rule.To]; exists {
			return nil, fmt.Errorf("rule %d: duplicate target %q", index, rule.To)
		}
		seenRules[rule.ID] = struct{}{}
		seenTargets[rule.To] = struct{}{}
		rules = append(rules, compiledRule{
			rule:       rule,
			path:       strings.Split(strings.TrimPrefix(rule.From, "fields."), "."),
			targetPath: strings.Split(strings.TrimPrefix(rule.To, "event."), "."),
			taxonomy:   compiledTaxonomies[rule.Lookup],
		})
	}

	owned := cloneConfig(config)
	digest, err := digestConfig(owned)
	if err != nil {
		return nil, fmt.Errorf("digest mapping config: %w", err)
	}
	return &Engine{
		descriptor: Descriptor{id: owned.ID, version: owned.Version, digest: digest},
		rules:      rules,
	}, nil
}

func validateRule(rule Rule, taxonomies map[string]map[string]string) error {
	if !identifierPattern.MatchString(rule.ID) {
		return errors.New("id must be a lowercase identifier")
	}
	if !validSourcePath(rule.From) {
		return fmt.Errorf("invalid explicit source path %q", rule.From)
	}
	kind, allowed := targetForPath(rule.To)
	if !allowed {
		return fmt.Errorf("target %q is not allowlisted", rule.To)
	}
	if !validConversion(rule.Convert) {
		return fmt.Errorf("unsupported conversion %q", rule.Convert)
	}
	if rule.Lookup != "" {
		if _, exists := taxonomies[rule.Lookup]; !exists {
			return fmt.Errorf("unknown taxonomy %q", rule.Lookup)
		}
	}
	if err := validateTargetConversion(kind, rule); err != nil {
		return err
	}
	if rule.Convert == ConvertTimestamp {
		if len(rule.TimestampLayouts) == 0 {
			return errors.New("timestamp conversion requires timestamp_layouts")
		}
		for _, layout := range rule.TimestampLayouts {
			if layout == "" {
				return errors.New("timestamp layout must not be empty")
			}
		}
		if _, err := parseFixedTimezone(rule.Timezone); err != nil {
			return err
		}
	} else if len(rule.TimestampLayouts) != 0 || rule.Timezone != "" {
		return errors.New("timestamp options require timestamp conversion")
	}
	if rule.Lookup != "" {
		for canonical := range configCanonicalValues(taxonomies[rule.Lookup]) {
			if err := validateCanonical(kind, canonical); err != nil {
				return fmt.Errorf("taxonomy %q canonical value %q: %w", rule.Lookup, canonical, err)
			}
		}
	}
	return nil
}

func validConversion(conversion Conversion) bool {
	switch conversion {
	case ConvertString, ConvertIP, ConvertInteger, ConvertPort, ConvertUint16, ConvertTimestamp, ConvertLowercase:
		return true
	default:
		return false
	}
}

func validateTargetConversion(kind targetKind, rule Rule) error {
	allowed := false
	switch kind {
	case targetIP:
		allowed = rule.Convert == ConvertIP && rule.Lookup == ""
	case targetPort:
		allowed = (rule.Convert == ConvertPort || rule.Convert == ConvertUint16) && rule.Lookup == ""
	case targetTimestamp:
		allowed = rule.Convert == ConvertTimestamp && rule.Lookup == ""
	case targetNonNegativeInteger, targetSeverityID, targetProtocolNumber:
		allowed = rule.Convert == ConvertInteger || rule.Lookup != ""
	case targetAction, targetDevice, targetSeverity:
		allowed = rule.Convert == ConvertLowercase && rule.Lookup != ""
	case targetProtocol:
		allowed = rule.Convert == ConvertLowercase
	case targetString, targetString64, targetString128, targetString255, targetString512, targetMAC:
		allowed = rule.Convert == ConvertString || rule.Convert == ConvertLowercase || rule.Lookup != ""
	case targetExtension:
		allowed = validConversion(rule.Convert)
	}
	if !allowed {
		return fmt.Errorf("conversion %q and lookup %q do not satisfy target %q", rule.Convert, rule.Lookup, rule.To)
	}
	return nil
}

func compileTaxonomies(configured map[string]map[string][]string) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string, len(configured))
	totalAliases := 0
	names := make([]string, 0, len(configured))
	for name := range configured {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !identifierPattern.MatchString(name) {
			return nil, fmt.Errorf("taxonomy name %q is invalid", name)
		}
		entries := configured[name]
		if len(entries) == 0 {
			return nil, fmt.Errorf("taxonomy %q is empty", name)
		}
		reverse := make(map[string]string)
		canonicals := make([]string, 0, len(entries))
		for canonical := range entries {
			canonicals = append(canonicals, canonical)
		}
		sort.Strings(canonicals)
		for _, canonical := range canonicals {
			if canonical == "" {
				return nil, fmt.Errorf("taxonomy %q has an empty canonical value", name)
			}
			aliases := append([]string{canonical}, entries[canonical]...)
			for _, alias := range aliases {
				totalAliases++
				if totalAliases > MaxAliases {
					return nil, fmt.Errorf("taxonomies exceed %d aliases", MaxAliases)
				}
				if alias == "" {
					return nil, fmt.Errorf("taxonomy %q has an empty alias", name)
				}
				if existing, exists := reverse[alias]; exists && existing != canonical {
					return nil, fmt.Errorf("taxonomy %q alias %q maps to both %q and %q", name, alias, existing, canonical)
				}
				reverse[alias] = canonical
			}
		}
		result[name] = reverse
	}
	return result, nil
}

func configCanonicalValues(reverse map[string]string) map[string]struct{} {
	values := make(map[string]struct{})
	for _, value := range reverse {
		values[value] = struct{}{}
	}
	return values
}

func validateCanonical(kind targetKind, value string) error {
	if _, err := coerceTarget(kind, value); err != nil {
		return err
	}
	return nil
}

func targetForPath(value string) (targetKind, bool) {
	if kind, found := allowedTargets[value]; found {
		return kind, true
	}
	const prefix = "event.extensions."
	if !strings.HasPrefix(value, prefix) || len(value) > 512 {
		return 0, false
	}
	parts := strings.Split(strings.TrimPrefix(value, prefix), ".")
	if len(parts) == 0 || len(parts) > 64 {
		return 0, false
	}
	for _, part := range parts {
		if !identifierPattern.MatchString(part) {
			return 0, false
		}
	}
	return targetExtension, true
}

func validSourcePath(path string) bool {
	if !strings.HasPrefix(path, "fields.") || len(path) > 512 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "fields."), ".")
	if len(parts) == 0 || len(parts) > 64 {
		return false
	}
	for _, part := range parts {
		if !identifierPattern.MatchString(part) && !allDigits(part) {
			return false
		}
	}
	return true
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func cloneRule(rule Rule) Rule {
	rule.TimestampLayouts = append([]string(nil), rule.TimestampLayouts...)
	return rule
}

func cloneConfig(config Config) Config {
	copyConfig := config
	copyConfig.Rules = make([]Rule, len(config.Rules))
	for index, rule := range config.Rules {
		copyConfig.Rules[index] = cloneRule(rule)
	}
	copyConfig.Taxonomies = make(map[string]map[string][]string, len(config.Taxonomies))
	for name, values := range config.Taxonomies {
		copyValues := make(map[string][]string, len(values))
		for canonical, aliases := range values {
			copyValues[canonical] = append([]string(nil), aliases...)
		}
		copyConfig.Taxonomies[name] = copyValues
	}
	return copyConfig
}
