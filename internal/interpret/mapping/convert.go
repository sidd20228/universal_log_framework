package mapping

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func convertValue(value any, rule Rule) (any, error) {
	switch rule.Convert {
	case ConvertString:
		return asString(value)
	case ConvertLowercase:
		text, err := asString(value)
		if err != nil {
			return nil, err
		}
		return strings.ToLower(text), nil
	case ConvertIP:
		text, err := asString(value)
		if err != nil {
			return nil, err
		}
		address, err := netip.ParseAddr(text)
		if err != nil {
			return nil, errors.New("value is not an IP address")
		}
		return address.Unmap(), nil
	case ConvertInteger:
		return asInt64(value)
	case ConvertPort, ConvertUint16:
		integer, err := asInt64(value)
		if err != nil {
			return nil, err
		}
		if integer < 0 || integer > 65535 {
			return nil, errors.New("port is outside 0..65535")
		}
		return uint16(integer), nil
	case ConvertTimestamp:
		text, err := asString(value)
		if err != nil {
			return nil, err
		}
		return parseTimestamp(text, rule.TimestampLayouts, rule.Timezone)
	default:
		return nil, fmt.Errorf("unsupported conversion %q", rule.Convert)
	}
}

func asString(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		if !utf8.ValidString(typed) {
			return "", errors.New("string is not valid UTF-8")
		}
		return typed, nil
	case []byte:
		if !utf8.Valid(typed) {
			return "", errors.New("bytes are not valid UTF-8")
		}
		return string(typed), nil
	default:
		return "", fmt.Errorf("value of type %T is not text", value)
	}
}

func asInt64(value any) (int64, error) {
	switch typed := value.(type) {
	case int:
		return int64(typed), nil
	case int8:
		return int64(typed), nil
	case int16:
		return int64(typed), nil
	case int32:
		return int64(typed), nil
	case int64:
		return typed, nil
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return 0, errors.New("integer overflows int64")
		}
		return int64(typed), nil
	case uint8:
		return int64(typed), nil
	case uint16:
		return int64(typed), nil
	case uint32:
		return int64(typed), nil
	case uint64:
		if typed > math.MaxInt64 {
			return 0, errors.New("integer overflows int64")
		}
		return int64(typed), nil
	case json.Number:
		integer, err := strconv.ParseInt(string(typed), 10, 64)
		if err != nil {
			return 0, errors.New("JSON number is not an int64")
		}
		return integer, nil
	case string:
		integer, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return 0, errors.New("text is not a base-10 int64")
		}
		return integer, nil
	default:
		return 0, fmt.Errorf("value of type %T is not an integer", value)
	}
}

func parseTimestamp(value string, layouts []string, timezone string) (time.Time, error) {
	location, err := parseFixedTimezone(timezone)
	if err != nil {
		return time.Time{}, err
	}
	for _, configuredLayout := range layouts {
		layout := timestampLayout(configuredLayout)
		var parsed time.Time
		if layoutHasZone(layout) {
			parsed, err = time.Parse(layout, value)
		} else {
			parsed, err = time.ParseInLocation(layout, value, location)
		}
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, errors.New("value did not match any declared timestamp layout")
}

func timestampLayout(layout string) string {
	switch layout {
	case "RFC3339":
		return time.RFC3339
	case "RFC3339Nano":
		return time.RFC3339Nano
	default:
		return layout
	}
}

func layoutHasZone(layout string) bool {
	return strings.Contains(layout, "Z07") || strings.Contains(layout, "-0700") ||
		strings.Contains(layout, "-07:00") || strings.Contains(layout, "MST")
}

func parseFixedTimezone(value string) (*time.Location, error) {
	if value == "" || value == "UTC" {
		return time.UTC, nil
	}
	if len(value) != 6 || (value[0] != '+' && value[0] != '-') || value[3] != ':' {
		return nil, errors.New("timezone must be UTC or a fixed offset such as +05:30")
	}
	hours, hourErr := strconv.Atoi(value[1:3])
	minutes, minuteErr := strconv.Atoi(value[4:6])
	if hourErr != nil || minuteErr != nil || hours > 23 || minutes > 59 {
		return nil, errors.New("timezone has an invalid fixed offset")
	}
	offset := hours*60*60 + minutes*60
	if value[0] == '-' {
		offset = -offset
	}
	return time.FixedZone(value, offset), nil
}

func coerceTarget(kind targetKind, value any) (any, error) {
	switch kind {
	case targetInteger:
		return asInt64(value)
	case targetIP:
		if _, ok := value.(netip.Addr); !ok {
			return nil, errors.New("target requires netip.Addr")
		}
	case targetPort:
		if _, ok := value.(uint16); !ok {
			return nil, errors.New("target requires uint16")
		}
	case targetTimestamp:
		if _, ok := value.(time.Time); !ok {
			return nil, errors.New("target requires time.Time")
		}
	case targetAction:
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("action target requires text")
		}
		if _, allowed := allowedActions[text]; !allowed {
			return nil, errors.New("action is outside the controlled vocabulary")
		}
	case targetDevice:
		text, ok := value.(string)
		if !ok {
			return nil, errors.New("device type target requires text")
		}
		if _, allowed := allowedDeviceTypes[text]; !allowed {
			return nil, errors.New("device type is outside the controlled vocabulary")
		}
	case targetProtocol, targetString:
		if _, ok := value.(string); !ok {
			return nil, errors.New("target requires text")
		}
	}
	return value, nil
}
