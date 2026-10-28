package registry_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/loganprice/treeguard/internal/registry"
)

func createTestTarGz(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestIsRemoteURITableDriven(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"http://example.com/rules.rego", true},
		{"https://raw.githubusercontent.com/rules/pack.tar.gz", true},
		{"pack:owasp-top10", true},
		{"pack:default", true},
		{"registry:cwe-top25", true},
		{"./rules", false},
		{"/usr/local/rules/rule.rego", false},
		{"rules/python/eval.rego", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := registry.IsRemoteURI(tt.input)
			if got != tt.want {
				t.Errorf("IsRemoteURI(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestRegistryClientTableDriven(t *testing.T) {
	ctx := context.Background()

	// Setup mock HTTP server
	tarGzBytes := createTestTarGz(t, map[string]string{
		"eval.rego": `package rules.eval
deny[f] { f := "eval detected" }
`,
		"crypto.rego": `package rules.crypto
deny[f] { f := "weak prng" }
`,
	})

	singleRegoContent := `package rules.single
deny[f] { f := "single rule" }
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pack.tar.gz":
			w.Header().Set("Content-Type", "application/gzip")
			w.WriteHeader(http.StatusOK)
			w.Write(tarGzBytes)
		case "/rule.rego":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(singleRegoContent))
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	tests := []struct {
		name         string
		pathOrURI    string
		forceUpdate  bool
		wantSubstr   string
		wantErr      bool
		setupAliases func(client *registry.Client)
	}{
		{
			name:        "Resolve valid local directory",
			pathOrURI:   os.TempDir(),
			forceUpdate: false,
			wantErr:     false,
		},
		{
			name:        "Resolve non-existent local directory error",
			pathOrURI:   "/non_existent_directory_xyz_12345",
			forceUpdate: false,
			wantErr:     true,
		},
		{
			name:        "Download and extract remote .tar.gz rule pack",
			pathOrURI:   server.URL + "/pack.tar.gz",
			forceUpdate: false,
			wantErr:     false,
		},
		{
			name:        "Download single remote .rego file",
			pathOrURI:   server.URL + "/rule.rego",
			forceUpdate: false,
			wantErr:     false,
		},
		{
			name:        "HTTP 404 error",
			pathOrURI:   server.URL + "/notfound",
			forceUpdate: false,
			wantErr:     true,
		},
		{
			name:        "Resolve custom registry alias",
			pathOrURI:   "pack:mock-owasp",
			forceUpdate: false,
			wantErr:     false,
			setupAliases: func(c *registry.Client) {
				c.Aliases["mock-owasp"] = server.URL + "/pack.tar.gz"
			},
		},
		{
			name:        "Unknown registry alias error",
			pathOrURI:   "pack:unknown-alias",
			forceUpdate: false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpCache := t.TempDir()
			client := registry.NewClient(tmpCache)
			if tt.setupAliases != nil {
				tt.setupAliases(client)
			}

			resolvedPath, err := client.ResolveRulePath(ctx, tt.pathOrURI, tt.forceUpdate)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveRulePath(%q) error = %v, wantErr %v", tt.pathOrURI, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if info, err := os.Stat(resolvedPath); err != nil || (!info.IsDir() && !strings.HasSuffix(resolvedPath, ".rego")) {
				t.Errorf("Resolved path %q does not exist or is invalid", resolvedPath)
			}

			// Test cache hit on second resolve
			cachedPath, err := client.ResolveRulePath(ctx, tt.pathOrURI, false)
			if err != nil || cachedPath != resolvedPath {
				t.Errorf("Cache hit failed: got %q, want %q", cachedPath, resolvedPath)
			}
		})
	}
}

func TestPackListAndCleanTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpCache := t.TempDir()
	client := registry.NewClient(tmpCache)

	tarGzBytes := createTestTarGz(t, map[string]string{
		"test.rego": `package rules.test`,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(tarGzBytes)
	}))
	defer server.Close()

	client.Aliases["test-pack"] = server.URL + "/pack.tar.gz"

	// 1. Initially empty cache
	packs, err := client.ListPacks()
	if err != nil {
		t.Fatalf("ListPacks() error = %v", err)
	}
	if len(packs) != 0 {
		t.Fatalf("Expected 0 cached packs initially, got %d", len(packs))
	}

	// 2. Resolve a pack to populate cache
	_, err = client.ResolveRulePath(ctx, "pack:test-pack", false)
	if err != nil {
		t.Fatalf("ResolveRulePath() error = %v", err)
	}

	packs, err = client.ListPacks()
	if err != nil {
		t.Fatalf("ListPacks() error = %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("Expected 1 cached pack after download, got %d", len(packs))
	}
	if packs[0].Name != "test-pack" {
		t.Errorf("Pack name = %q, want 'test-pack'", packs[0].Name)
	}

	// 3. Test UpdatePack
	if err := client.UpdatePack(ctx, "pack:test-pack"); err != nil {
		t.Fatalf("UpdatePack() error = %v", err)
	}

	// 4. Test CleanCache
	if err := client.CleanCache(); err != nil {
		t.Fatalf("CleanCache() error = %v", err)
	}

	packs, err = client.ListPacks()
	if err != nil {
		t.Fatalf("ListPacks() after clean error = %v", err)
	}
	if len(packs) != 0 {
		t.Fatalf("Expected 0 cached packs after clean, got %d", len(packs))
	}
}

func TestAvailableAliases(t *testing.T) {
	client := registry.NewClient(t.TempDir())
	aliases := client.AvailableAliases()
	if !strings.Contains(aliases, "owasp") || !strings.Contains(aliases, "default") {
		t.Errorf("AvailableAliases missing default aliases: %s", aliases)
	}
}

func TestResolveRulePathWithChecksum(t *testing.T) {
	ctx := context.Background()
	payload := []byte("package rules.test\nmetadata := {\"id\": \"sha-test\"}\ndeny[f] { f := 1 }")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	// Compute expected SHA256
	h := sha256.Sum256(payload)
	validSHA := hex.EncodeToString(h[:])
	invalidSHA := "0000000000000000000000000000000000000000000000000000000000000000"

	client := registry.NewClient(t.TempDir())

	// 1. Valid checksum matches
	packDir, err := client.ResolveRulePathWithChecksum(ctx, server.URL, validSHA, true)
	if err != nil {
		t.Fatalf("ResolveRulePathWithChecksum() with valid SHA error = %v", err)
	}
	if packDir == "" {
		t.Fatalf("Expected packDir, got empty")
	}

	// Verify manifest has recorded SHA256
	packs, err := client.ListPacks()
	if err != nil || len(packs) != 1 {
		t.Fatalf("ListPacks() failed or count != 1: err=%v, count=%d", err, len(packs))
	}
	if packs[0].SHA256 != validSHA {
		t.Errorf("Pack SHA256 = %q, want %q", packs[0].SHA256, validSHA)
	}

	// 2. Invalid checksum fails and cleans up
	client2 := registry.NewClient(t.TempDir())
	_, err = client2.ResolveRulePathWithChecksum(ctx, server.URL, invalidSHA, true)
	if err == nil {
		t.Fatalf("Expected checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("Expected 'checksum mismatch' in error, got: %v", err)
	}
}
