package envelope

import (
	"errors"
	"net/netip"
	"reflect"
	"time"
)

const maxCloneDepth = 64

func cloneMap(source map[string]any) (map[string]any, error) {
	if source == nil {
		return nil, nil
	}
	cloned, err := cloneValue(reflect.ValueOf(source), 0)
	if err != nil {
		return nil, err
	}
	return cloned.Interface().(map[string]any), nil
}

func cloneValue(source reflect.Value, depth int) (reflect.Value, error) {
	if depth > maxCloneDepth {
		return reflect.Value{}, errors.New("value exceeds maximum copy depth")
	}
	if !source.IsValid() {
		return reflect.Value{}, nil
	}
	if source.Type() == reflect.TypeOf(time.Time{}) || source.Type() == reflect.TypeOf(netip.Addr{}) {
		return source, nil
	}
	switch source.Kind() {
	case reflect.Interface:
		if source.IsNil() {
			return reflect.Zero(source.Type()), nil
		}
		value, err := cloneValue(source.Elem(), depth+1)
		if err != nil {
			return reflect.Value{}, err
		}
		wrapped := reflect.New(source.Type()).Elem()
		wrapped.Set(value)
		return wrapped, nil
	case reflect.Pointer:
		if source.IsNil() {
			return reflect.Zero(source.Type()), nil
		}
		value, err := cloneValue(source.Elem(), depth+1)
		if err != nil {
			return reflect.Value{}, err
		}
		pointer := reflect.New(source.Type().Elem())
		pointer.Elem().Set(value)
		return pointer, nil
	case reflect.Map:
		if source.Type().Key().Kind() != reflect.String {
			return reflect.Value{}, errors.New("only string-keyed parsed maps are supported")
		}
		result := reflect.MakeMapWithSize(source.Type(), source.Len())
		iterator := source.MapRange()
		for iterator.Next() {
			value, err := cloneValue(iterator.Value(), depth+1)
			if err != nil {
				return reflect.Value{}, err
			}
			result.SetMapIndex(iterator.Key(), value)
		}
		return result, nil
	case reflect.Slice:
		if source.IsNil() {
			return reflect.Zero(source.Type()), nil
		}
		result := reflect.MakeSlice(source.Type(), source.Len(), source.Len())
		for index := 0; index < source.Len(); index++ {
			value, err := cloneValue(source.Index(index), depth+1)
			if err != nil {
				return reflect.Value{}, err
			}
			result.Index(index).Set(value)
		}
		return result, nil
	case reflect.Array:
		result := reflect.New(source.Type()).Elem()
		for index := 0; index < source.Len(); index++ {
			value, err := cloneValue(source.Index(index), depth+1)
			if err != nil {
				return reflect.Value{}, err
			}
			result.Index(index).Set(value)
		}
		return result, nil
	case reflect.Struct:
		result := reflect.New(source.Type()).Elem()
		for index := 0; index < source.NumField(); index++ {
			if !result.Field(index).CanSet() || source.Type().Field(index).PkgPath != "" {
				return source, nil
			}
			value, err := cloneValue(source.Field(index), depth+1)
			if err != nil {
				return reflect.Value{}, err
			}
			result.Field(index).Set(value)
		}
		return result, nil
	default:
		return source, nil
	}
}
