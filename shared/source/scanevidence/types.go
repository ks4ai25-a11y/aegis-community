// SPDX-License-Identifier: Apache-2.0
// Package scanevidence defines scanner evidence data without executor access.
package scanevidence

import (
	"aegis.local/source"
	"encoding/json"
)

const ParserVersion = "1.2"
const MaxOutput = 8 << 20

type Source struct {
	Tool        string `json:"tool_id"`
	Version     string `json:"tool_version"`
	ImageDigest string `json:"tool_image_digest"`
	Parser      string `json:"parser_version"`
	InputDigest string `json:"input_digest"`
	Rule        string `json:"rule_id,omitempty"`
	Severity    string `json:"severity_claimed,omitempty"`
}
type Finding struct {
	Schema            string   `json:"schema_version"`
	ID                string   `json:"id"`
	App               string   `json:"app_id"`
	Repository        string   `json:"repository_id"`
	Category          string   `json:"category"`
	Summary           string   `json:"summary"`
	Status            string   `json:"status"`
	Severity          string   `json:"severity"`
	Confidence        string   `json:"confidence"`
	Tier              string   `json:"evidence_tier"`
	Path              string   `json:"path,omitempty"`
	Line              int      `json:"line,omitempty"`
	Package           string   `json:"package_url,omitempty"`
	PackageName       string   `json:"package_name,omitempty"`
	Version           string   `json:"installed_version,omitempty"`
	Advisories        []string `json:"advisories,omitempty"`
	SecretFingerprint string   `json:"secret_fingerprint,omitempty"`
	Provenance        []Source `json:"provenance"`
	Coverage          string   `json:"coverage_note"`
	Created           string   `json:"created_at"`
}
type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Result struct {
	Status      string          `json:"status"`
	Findings    []Finding       `json:"findings"`
	Diagnostics []Diagnostic    `json:"diagnostics"`
	SBOM        json.RawMessage `json:"sbom,omitempty"`
}

type Invocation struct {
	Args             []string `json:"args"`
	Network          string   `json:"network_profile"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	MaxOutput        int      `json:"max_output_bytes"`
	FindingExitCodes []int    `json:"finding_exit_codes"`
}

type Execution struct {
	Parser        string          `json:"parser_version"`
	Invocation    Invocation      `json:"invocation"`
	Profile       string          `json:"sandbox_profile"`
	GuardDigest   string          `json:"guard_binary_digest"`
	DurationLimit int             `json:"duration_limit_seconds"`
	Schema        string          `json:"schema_version"`
	Tool          string          `json:"tool_id"`
	Version       string          `json:"tool_version"`
	Image         string          `json:"tool_image_digest"`
	LockDigest    string          `json:"tool_lock_digest"`
	RulesDigest   string          `json:"rule_pack_digest,omitempty"`
	Snapshot      source.Manifest `json:"source_snapshot"`
	Started       string          `json:"started_at"`
	Duration      int64           `json:"duration_ms"`
	Exit          int             `json:"exit_code"`
	Status        string          `json:"status"`
	Cleanup       string          `json:"cleanup_state"`
	Container     string          `json:"container_id"`
	Result        Result          `json:"result"`
	Limitations   []string        `json:"limitations"`
	Database      *DatabaseUse    `json:"advisory_database,omitempty"`
}

// DatabaseUse records the operator-provisioned offline advisory database
// (ADR 068) that was verified on the worker and mounted read-only for this run.
type DatabaseUse struct {
	ManifestDigest string `json:"manifest_digest"`
	Digest         string `json:"database_digest"`
	BuiltAt        string `json:"upstream_built_at"`
	AgeHours       int    `json:"age_hours"`
	Stale          bool   `json:"stale"`
	ContainerPath  string `json:"container_path"`
}
