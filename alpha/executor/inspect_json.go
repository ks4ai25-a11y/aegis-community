// SPDX-License-Identifier: BUSL-1.1
package executor

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// Engine metadata uses a fixed template. Reject duplicate/case-aliased keys,
// malformed UTF-8, excessive nesting and trailing values before typed decode.
func inspectionJSON(b []byte, out any, max int) error {
	if len(b) > max || !utf8.Valid(b) {
		return ErrObservation
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 || tokens > 200000 {
			return ErrObservation
		}
		tokens++
		token, e := d.Token()
		if e != nil {
			return ErrObservation
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				name, ok := key.(string)
				fold := strings.ToLower(name)
				if e != nil || !ok || keys[fold] {
					return ErrObservation
				}
				keys[fold] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrObservation
			}
		case '[':
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrObservation
			}
		default:
			return ErrObservation
		}
		return nil
	}
	if walk(0) != nil {
		return ErrObservation
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrObservation
	}
	typed := json.NewDecoder(bytes.NewReader(b))
	typed.DisallowUnknownFields()
	if typed.Decode(out) != nil {
		return ErrObservation
	}
	return nil
}

// A false/missing/null safety value must not acquire authority through Go's
// zero values. Fixed engine-template objects require every selected key.
func inspectionShape(b []byte, prototype any) error {
	var raw, expected map[string]json.RawMessage
	shape, e := json.Marshal(prototype)
	if e != nil || json.Unmarshal(shape, &expected) != nil || json.Unmarshal(b, &raw) != nil || len(raw) != len(expected) {
		return ErrObservation
	}
	for key, value := range expected {
		actual, ok := raw[key]
		if !ok {
			return ErrObservation
		}
		if !bytes.Equal(value, []byte("null")) && bytes.Equal(bytes.TrimSpace(actual), []byte("null")) {
			return ErrObservation
		}
	}
	return nil
}
