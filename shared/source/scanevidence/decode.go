// SPDX-License-Identifier: Apache-2.0
package scanevidence

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// Decode accepts exactly the canonical receipt fields. It does not authenticate
// the caller or validate bindings; Normalize must follow with trusted Expected.
func Decode(b []byte) (Execution, error) {
	var r Execution
	if validateJSON(b) != nil || canonicalKeys(b, reflect.TypeOf(r)) != nil {
		return Execution{}, ErrReceipt
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		return Execution{}, ErrReceipt
	}
	return r, nil
}
func canonicalKeys(b []byte, t reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return ErrReceipt
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		return nil
	} // The SBOM has its own finite schema in Normalize.
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) != nil || fields == nil {
			return ErrReceipt
		}
		known := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			if key != "" && key != "-" {
				known[key] = f.Type
			}
		}
		for key, value := range fields {
			field, ok := known[key]
			if !ok || canonicalKeys(value, field) != nil {
				return ErrReceipt
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if json.Unmarshal(b, &items) != nil || items == nil {
			return ErrReceipt
		}
		for _, v := range items {
			if canonicalKeys(v, t.Elem()) != nil {
				return ErrReceipt
			}
		}
	}
	return nil
}
