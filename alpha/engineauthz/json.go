// SPDX-License-Identifier: Apache-2.0
package engineauthz

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode"
	"unicode/utf8"
)

// Engine metadata uses a fixed template. Reject duplicate/case-aliased keys,
// malformed UTF-8, excessive nesting and trailing values before typed decode.
func strict(b []byte, out any, max int) error {
	if len(b) > max || !utf8.Valid(b) {
		return ErrPolicy
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 || tokens > 200000 {
			return ErrPolicy
		}
		tokens++
		token, e := d.Token()
		if e != nil {
			return ErrPolicy
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
				fold := folded(name)
				if e != nil || !ok || keys[fold] {
					return ErrPolicy
				}
				keys[fold] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrPolicy
			}
		case '[':
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrPolicy
			}
		default:
			return ErrPolicy
		}
		return nil
	}
	if walk(0) != nil {
		return ErrPolicy
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrPolicy
	}
	typed := json.NewDecoder(bytes.NewReader(b))
	typed.DisallowUnknownFields()
	if typed.Decode(out) != nil {
		return ErrPolicy
	}
	return nil
}

func folded(s string) string {
	r := []rune(s)
	for i, c := range r {
		small := c
		for n := unicode.SimpleFold(c); n != c; n = unicode.SimpleFold(n) {
			if n < small {
				small = n
			}
		}
		r[i] = small
	}
	return string(r)
}
