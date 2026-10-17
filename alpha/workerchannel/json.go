// SPDX-License-Identifier: BUSL-1.1
package workerchannel

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// Validate tokens before decoding: Go's ordinary struct decoder accepts duplicate
// keys and case aliases, which are not valid private protocol identities.
func strictDecode(b []byte, out any) error {
	if !utf8.Valid(b) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	budget := 250000
	typ := reflect.TypeOf(out)
	if typ == nil || typ.Kind() != reflect.Pointer {
		return errors.New("invalid response target")
	}
	if e := walkJSON(d, typ.Elem(), 0, &budget); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func walkJSON(d *json.Decoder, t reflect.Type, depth int, budget *int) error {
	*budget--
	if depth > 64 || *budget < 0 {
		return errors.New("JSON budget exceeded")
	}
	v, e := d.Token()
	if e != nil {
		return e
	}
	if v == nil {
		return errors.New("null protocol value")
	}
	if t == reflect.TypeOf(time.Time{}) {
		if _, ok := v.(string); !ok {
			return errors.New("invalid timestamp")
		}
		return nil
	}
	delim, complex := v.(json.Delim)
	if !complex {
		switch t.Kind() {
		case reflect.String:
			if _, ok := v.(string); !ok {
				return errors.New("invalid string")
			}
		case reflect.Bool:
			if _, ok := v.(bool); !ok {
				return errors.New("invalid bool")
			}
		case reflect.Int, reflect.Int64:
			if _, ok := v.(json.Number); !ok {
				return errors.New("invalid number")
			}
		default:
			return errors.New("invalid scalar")
		}
		return nil
	}
	switch delim {
	case '{':
		if t.Kind() != reflect.Struct {
			return errors.New("unexpected object")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = f.Type
			}
		}
		seen := map[string]bool{}
		for d.More() {
			*budget--
			if *budget < 0 {
				return errors.New("JSON budget exceeded")
			}
			key, e := d.Token()
			if e != nil {
				return e
			}
			k, ok := key.(string)
			if !ok {
				return errors.New("invalid key")
			}
			ft, ok := fields[k]
			if !ok || seen[k] {
				return errors.New("unknown or duplicate key")
			}
			seen[k] = true
			if e = walkJSON(d, ft, depth+1, budget); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return errors.New("invalid object")
		}
	case '[':
		if t.Kind() != reflect.Slice {
			return errors.New("unexpected array")
		}
		for d.More() {
			if e = walkJSON(d, t.Elem(), depth+1, budget); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return errors.New("invalid array")
		}
	default:
		return errors.New("invalid delimiter")
	}
	return nil
}
