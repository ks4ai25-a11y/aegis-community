// SPDX-License-Identifier: Apache-2.0
package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// Go's struct decoder matches field names without case. Reject all equivalent
// object keys before decoding, including escaped names and Unicode folds.
func foldedKey(s string) string {
	runes := []rune(s)
	for i, r := range runes {
		min := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < min {
				min = next
			}
		}
		runes[i] = min
	}
	return string(runes)
}
func validateJSON(b []byte) error {
	if len(b) == 0 || len(b) > MaxOutput || !utf8.Valid(b) {
		return fmt.Errorf("invalid bounded scanner JSON")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	tokens := 0
	var value func(int) error
	take := func() (json.Token, error) {
		tokens++
		if tokens > 250000 {
			return nil, fmt.Errorf("scanner JSON token budget exceeded")
		}
		return d.Token()
	}
	value = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("scanner JSON nesting exceeded")
		}
		token, e := take()
		if e != nil {
			return e
		}
		switch v := token.(type) {
		case string:
			if len(v) > 1<<20 {
				return fmt.Errorf("scanner JSON string budget exceeded")
			}
		case json.Delim:
			switch v {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := take()
					if e != nil {
						return e
					}
					name, ok := key.(string)
					if !ok || len(name) > 1024 {
						return fmt.Errorf("invalid scanner JSON key")
					}
					fold := foldedKey(name)
					if seen[fold] || len(seen) >= 10000 {
						return fmt.Errorf("ambiguous or excessive scanner JSON fields")
					}
					seen[fold] = true
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := take()
				if e != nil || end != json.Delim('}') {
					return fmt.Errorf("invalid scanner JSON object")
				}
			case '[':
				count := 0
				for d.More() {
					count++
					if count > 10000 {
						return fmt.Errorf("scanner JSON array budget exceeded")
					}
					if e = value(depth + 1); e != nil {
						return e
					}
				}
				end, e := take()
				if e != nil || end != json.Delim(']') {
					return fmt.Errorf("invalid scanner JSON array")
				}
			default:
				return fmt.Errorf("unexpected scanner JSON delimiter")
			}
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return fmt.Errorf("trailing scanner JSON")
	}
	return nil
}
