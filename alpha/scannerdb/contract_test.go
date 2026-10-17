package scannerdb

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

// The manifest written by WriteManifest must use exactly the fields of the
// generated ScannerDatabaseManifestV1 contract, at every nesting level.
func TestManifestMatchesContract(t *testing.T) {
	raw, e := os.ReadFile("../../contracts/schemas/ScannerDatabaseManifestV1.json")
	if e != nil {
		t.Fatal(e)
	}
	var schema map[string]any
	json.Unmarshal(raw, &schema)
	m := Manifest{Schema: Schema, CreatedAt: "2026-10-17T00:00:00Z", Digest: "sha256:x", Databases: []Database{{Tool: "osv_v2", Files: []File{{Path: "a"}}}}}
	b, _ := json.Marshal(m)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	compare(t, "manifest", schema, doc)
	db := schema["properties"].(map[string]any)["databases"].(map[string]any)["items"].(map[string]any)
	compare(t, "database", db, doc["databases"].([]any)[0].(map[string]any))
	file := db["properties"].(map[string]any)["files"].(map[string]any)["items"].(map[string]any)
	compare(t, "file", file, doc["databases"].([]any)[0].(map[string]any)["files"].([]any)[0].(map[string]any))
	if c := schema["properties"].(map[string]any)["schema_version"].(map[string]any)["const"]; c != Schema {
		t.Fatalf("schema_version const %v != %s", c, Schema)
	}
}

func compare(t *testing.T, name string, schema map[string]any, doc map[string]any) {
	var want, got []string
	for k := range schema["properties"].(map[string]any) {
		want = append(want, k)
	}
	for k := range doc {
		got = append(got, k)
	}
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%s fields: contract %v, Go %v", name, want, got)
	}
}
