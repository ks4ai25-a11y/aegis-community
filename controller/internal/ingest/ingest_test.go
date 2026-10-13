package ingest

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestOversizedLineDoesNotHideNextRecord(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 1<<20)+"\n{}\n"), 8193)
	b, n, large, e := boundedLine(r)
	if e != nil || !large || n != (1<<20)+1 || len(b) != 0 {
		t.Fatalf("oversized line: %d %v %v", n, large, e)
	}
	b, n, large, e = boundedLine(r)
	if e != nil || large || string(b) != "{}\n" || n != 3 {
		t.Fatal("next record lost")
	}
}
func TestPartialRecordIsNotCommitted(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("{\"partial\":"), 8193)
	_, _, _, e := boundedLine(r)
	if e != io.EOF {
		t.Fatal(e)
	}
}
func TestTrailingJSONRejected(t *testing.T) {
	if _, e := Normalize([]byte(`{"source_schema":"caddy-2.11.4-coraza-2.6.2","source":"coraza","ts":1} {}`)); e == nil {
		t.Fatal("trailing data accepted")
	}
}
func FuzzNormalize(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 9000 {
			Normalize(b)
		}
	})
}
