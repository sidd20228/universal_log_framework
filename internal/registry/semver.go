package registry

import (
	"fmt"
	"strconv"
	"strings"
)

type semanticVersion struct {
	major      uint64
	minor      uint64
	patch      uint64
	prerelease []semanticIdentifier
}

type semanticIdentifier struct {
	value   string
	number  uint64
	numeric bool
}

func parseSemanticVersion(value string) (semanticVersion, error) {
	var parsed semanticVersion
	withoutBuild, _, _ := strings.Cut(value, "+")
	core, prerelease, hasPrerelease := strings.Cut(withoutBuild, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return parsed, fmt.Errorf("invalid semantic version %q", value)
	}
	numbers := []*uint64{&parsed.major, &parsed.minor, &parsed.patch}
	for index, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return parsed, fmt.Errorf("invalid semantic version %q", value)
		}
		number, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return parsed, fmt.Errorf("invalid semantic version %q", value)
		}
		*numbers[index] = number
	}
	if hasPrerelease {
		if prerelease == "" {
			return parsed, fmt.Errorf("invalid semantic version %q", value)
		}
		for _, identifier := range strings.Split(prerelease, ".") {
			if identifier == "" || !validSemanticIdentifier(identifier) {
				return parsed, fmt.Errorf("invalid semantic version %q", value)
			}
			item := semanticIdentifier{value: identifier}
			if allDigits(identifier) {
				if len(identifier) > 1 && identifier[0] == '0' {
					return parsed, fmt.Errorf("invalid semantic version %q", value)
				}
				number, err := strconv.ParseUint(identifier, 10, 64)
				if err != nil {
					return parsed, fmt.Errorf("invalid semantic version %q", value)
				}
				item.numeric = true
				item.number = number
			}
			parsed.prerelease = append(parsed.prerelease, item)
		}
	}
	if build, found := strings.CutPrefix(value, withoutBuild+"+"); found {
		if build == "" {
			return parsed, fmt.Errorf("invalid semantic version %q", value)
		}
		for _, identifier := range strings.Split(build, ".") {
			if identifier == "" || !validSemanticIdentifier(identifier) {
				return parsed, fmt.Errorf("invalid semantic version %q", value)
			}
		}
	}
	return parsed, nil
}

func compareSemanticVersions(first, second semanticVersion) int {
	for _, pair := range [][2]uint64{{first.major, second.major}, {first.minor, second.minor}, {first.patch, second.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if len(first.prerelease) == 0 && len(second.prerelease) == 0 {
		return 0
	}
	if len(first.prerelease) == 0 {
		return 1
	}
	if len(second.prerelease) == 0 {
		return -1
	}
	limit := min(len(first.prerelease), len(second.prerelease))
	for index := 0; index < limit; index++ {
		left, right := first.prerelease[index], second.prerelease[index]
		switch {
		case left.numeric && right.numeric && left.number < right.number:
			return -1
		case left.numeric && right.numeric && left.number > right.number:
			return 1
		case left.numeric && !right.numeric:
			return -1
		case !left.numeric && right.numeric:
			return 1
		case left.value < right.value:
			return -1
		case left.value > right.value:
			return 1
		}
	}
	if len(first.prerelease) < len(second.prerelease) {
		return -1
	}
	if len(first.prerelease) > len(second.prerelease) {
		return 1
	}
	return 0
}

func validSemanticIdentifier(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}

func allDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
