package mapping

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var errAmbiguousPath = errors.New("source path selector is ambiguous")

func resolveSource(fields map[string]any, path []string) (any, string, bool, error) {
	var current any = fields
	concrete := make([]string, 0, len(path)+1)
	concrete = append(concrete, "fields")
	for _, segment := range path {
		value := unwrapValue(reflect.ValueOf(current))
		if !value.IsValid() {
			return nil, "", false, nil
		}
		switch value.Kind() {
		case reflect.Map:
			if value.Type().Key().Kind() != reflect.String {
				return nil, "", false, nil
			}
			entry := value.MapIndex(reflect.ValueOf(segment).Convert(value.Type().Key()))
			if !entry.IsValid() {
				return nil, "", false, nil
			}
			current = entry.Interface()
			concrete = append(concrete, segment)
		case reflect.Struct:
			field, found := structField(value, segment)
			if !found {
				return nil, "", false, nil
			}
			current = field.Interface()
			concrete = append(concrete, segment)
		case reflect.Slice, reflect.Array:
			index, err := selectSlice(value, segment)
			if err != nil {
				return nil, "", false, err
			}
			if index < 0 {
				return nil, "", false, nil
			}
			current = value.Index(index).Interface()
			concrete = append(concrete, strconv.Itoa(index))
		default:
			return nil, "", false, nil
		}
	}
	return current, strings.Join(concrete, "."), true, nil
}

func selectSlice(value reflect.Value, segment string) (int, error) {
	if allDigits(segment) {
		index, err := strconv.Atoi(segment)
		if err != nil || index < 0 || index >= value.Len() {
			return -1, nil
		}
		return index, nil
	}
	found := -1
	for index := 0; index < value.Len(); index++ {
		candidate := unwrapValue(value.Index(index))
		if !candidate.IsValid() {
			continue
		}
		matches := false
		for _, discriminator := range []string{"id", "name", "key"} {
			field, ok := valueByName(candidate, discriminator)
			if ok && field.Kind() == reflect.String && field.String() == segment {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		if found >= 0 {
			return -1, errAmbiguousPath
		}
		found = index
	}
	return found, nil
}

func valueByName(value reflect.Value, name string) (reflect.Value, bool) {
	switch value.Kind() {
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return reflect.Value{}, false
		}
		field := value.MapIndex(reflect.ValueOf(name).Convert(value.Type().Key()))
		if field.IsValid() {
			return unwrapValue(field), true
		}
	case reflect.Struct:
		return structField(value, name)
	}
	return reflect.Value{}, false
}

func structField(value reflect.Value, name string) (reflect.Value, bool) {
	typeInfo := value.Type()
	for index := 0; index < value.NumField(); index++ {
		fieldInfo := typeInfo.Field(index)
		if fieldInfo.PkgPath != "" {
			continue
		}
		fieldName := jsonFieldName(fieldInfo)
		if fieldName == name {
			return unwrapValue(value.Field(index)), true
		}
	}
	return reflect.Value{}, false
}

func jsonFieldName(field reflect.StructField) string {
	if tag := field.Tag.Get("json"); tag != "" {
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			return name
		}
	}
	runes := []rune(field.Name)
	var builder strings.Builder
	for index, character := range runes {
		if unicode.IsUpper(character) {
			previousIsLower := index > 0 && unicode.IsLower(runes[index-1])
			nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
			if index > 0 && (previousIsLower || nextIsLower) {
				builder.WriteByte('_')
			}
			builder.WriteRune(unicode.ToLower(character))
		} else {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

func unwrapValue(value reflect.Value) reflect.Value {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	return value
}

func flattenFields(fields map[string]any) map[string]any {
	result := make(map[string]any)
	flattenValue(result, "fields", reflect.ValueOf(fields), 0)
	return result
}

func flattenValue(target map[string]any, path string, source reflect.Value, depth int) {
	if depth > 64 {
		return
	}
	source = unwrapValue(source)
	if !source.IsValid() {
		target[path] = nil
		return
	}
	if source.Type() == reflect.TypeOf(time.Time{}) || source.Type() == reflect.TypeOf(netip.Addr{}) {
		target[path] = source.Interface()
		return
	}
	if source.Kind() == reflect.Slice && source.Type().Elem().Kind() == reflect.Uint8 {
		target[path] = append([]byte(nil), source.Bytes()...)
		return
	}
	switch source.Kind() {
	case reflect.Map:
		if source.Type().Key().Kind() != reflect.String || source.Len() == 0 {
			target[path] = source.Interface()
			return
		}
		keys := make([]string, 0, source.Len())
		iterator := source.MapRange()
		for iterator.Next() {
			keys = append(keys, iterator.Key().String())
		}
		sort.Strings(keys)
		for _, key := range keys {
			mapValue := source.MapIndex(reflect.ValueOf(key).Convert(source.Type().Key()))
			flattenValue(target, path+"."+key, mapValue, depth+1)
		}
	case reflect.Struct:
		count := 0
		for index := 0; index < source.NumField(); index++ {
			info := source.Type().Field(index)
			if info.PkgPath != "" || jsonFieldName(info) == "-" {
				continue
			}
			count++
			flattenValue(target, path+"."+jsonFieldName(info), source.Field(index), depth+1)
		}
		if count == 0 {
			target[path] = source.Interface()
		}
	case reflect.Slice, reflect.Array:
		if source.Len() == 0 {
			target[path] = source.Interface()
			return
		}
		for index := 0; index < source.Len(); index++ {
			flattenValue(target, fmt.Sprintf("%s.%d", path, index), source.Index(index), depth+1)
		}
	default:
		target[path] = source.Interface()
	}
}

func setTarget(event map[string]any, path []string, value any) error {
	current := event
	for index, segment := range path {
		if index == len(path)-1 {
			if _, exists := current[segment]; exists {
				return errors.New("target already has a value")
			}
			current[segment] = value
			return nil
		}
		next, exists := current[segment]
		if !exists {
			child := make(map[string]any)
			current[segment] = child
			current = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return errors.New("target parent already has a scalar value")
		}
		current = child
	}
	return errors.New("target path is empty")
}
