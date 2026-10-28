package version

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	info := Get()
	if info.Version == "" {
		t.Errorf("expected non-empty Version")
	}
	if info.GoVersion == "" {
		t.Errorf("expected non-empty GoVersion")
	}
	if info.Platform == "" {
		t.Errorf("expected non-empty Platform")
	}
}

func TestString(t *testing.T) {
	info := Info{
		Version:   "v1.2.3",
		Commit:    "abcdef1",
		Date:      "2026-09-17T00:00:00Z",
		GoVersion: "go1.26.1",
		Platform:  "darwin/arm64",
	}

	str := info.String()
	if !strings.Contains(str, "v1.2.3") {
		t.Errorf("expected version v1.2.3 in %q", str)
	}
	if !strings.Contains(str, "abcdef1") {
		t.Errorf("expected commit abcdef1 in %q", str)
	}
	if !strings.Contains(str, "darwin/arm64") {
		t.Errorf("expected platform darwin/arm64 in %q", str)
	}
}

func TestJSON(t *testing.T) {
	info := Info{
		Version:   "v1.2.3",
		Commit:    "abcdef1",
		Date:      "2026-09-17T00:00:00Z",
		GoVersion: "go1.26.1",
		Platform:  "darwin/arm64",
	}

	jsonStr, err := info.JSON()
	if err != nil {
		t.Fatalf("unexpected error from JSON(): %v", err)
	}

	var parsed Info
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}

	if parsed.Version != info.Version {
		t.Errorf("expected version %s, got %s", info.Version, parsed.Version)
	}
	if parsed.Commit != info.Commit {
		t.Errorf("expected commit %s, got %s", info.Commit, parsed.Commit)
	}
	if parsed.Platform != info.Platform {
		t.Errorf("expected platform %s, got %s", info.Platform, parsed.Platform)
	}
}
