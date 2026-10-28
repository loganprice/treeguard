package registry

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ManifestFilename = "manifest.json"
)

// PackMeta contains metadata for a cached remote rule pack.
type PackMeta struct {
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	Version      string    `json:"version,omitempty"`
	Path         string    `json:"path"`
	DownloadedAt time.Time `json:"downloaded_at"`
	FilesCount   int       `json:"files_count"`
	SHA256       string    `json:"sha256,omitempty"`
}

// Client manages downloading, caching, and resolving remote rule packs.
type Client struct {
	mu         sync.RWMutex
	CacheDir   string
	HTTPClient *http.Client
	Aliases    map[string]string
}

// DefaultClient is the global default registry client using ~/.treeguard/cache/packs.
var DefaultClient = NewClient("")

// NewClient creates a new Client instance.
func NewClient(cacheDir string) *Client {
	if cacheDir == "" {
		if envDir := os.Getenv("TREEGUARD_CACHE_DIR"); envDir != "" {
			cacheDir = filepath.Join(envDir, "packs")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				home = os.TempDir()
			}
			cacheDir = filepath.Join(home, ".treeguard", "cache", "packs")
		}
	}

	return &Client{
		CacheDir: cacheDir,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		Aliases: map[string]string{
			"default":     "https://raw.githubusercontent.com/treeguard/rules/main/packs/default.tar.gz",
			"community":   "https://raw.githubusercontent.com/treeguard/rules/main/packs/default.tar.gz",
			"owasp":       "https://raw.githubusercontent.com/treeguard/rules/main/packs/owasp-top10.tar.gz",
			"owasp-top10": "https://raw.githubusercontent.com/treeguard/rules/main/packs/owasp-top10.tar.gz",
			"cwe-top25":   "https://raw.githubusercontent.com/treeguard/rules/main/packs/cwe-top25.tar.gz",
		},
	}
}

// IsRemoteURI checks if the given string represents a remote URL or registry alias.
func IsRemoteURI(pathOrURI string) bool {
	lower := strings.ToLower(strings.TrimSpace(pathOrURI))
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "pack:") ||
		strings.HasPrefix(lower, "registry:")
}

// ResolveRulePath resolves a rule path, URL, or pack alias to local filesystem path(s).
func (c *Client) ResolveRulePath(ctx context.Context, pathOrURI string, forceUpdate bool) (string, error) {
	return c.ResolveRulePathWithChecksum(ctx, pathOrURI, "", forceUpdate)
}

// ResolveRulePathWithChecksum resolves a rule path, URL, or pack alias and optionally validates SHA-256 hash.
func (c *Client) ResolveRulePathWithChecksum(ctx context.Context, pathOrURI string, expectedSHA256 string, forceUpdate bool) (string, error) {
	if !IsRemoteURI(pathOrURI) {
		cleanLocal := filepath.Clean(pathOrURI)
		// Local file or directory
		if _, err := os.Stat(cleanLocal); err != nil {
			return "", fmt.Errorf("local rule path not found: %w", err)
		}
		return cleanLocal, nil
	}

	targetURL, packName, err := c.resolveURI(pathOrURI)
	if err != nil {
		return "", err
	}

	packDir := c.getPackDir(packName, targetURL)
	manifestPath := filepath.Clean(filepath.Join(packDir, ManifestFilename))

	c.mu.RLock()
	if !forceUpdate {
		if info, err := os.Stat(manifestPath); err == nil && !info.IsDir() {
			c.mu.RUnlock()
			return packDir, nil
		}
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check under write lock
	if !forceUpdate {
		if info, err := os.Stat(manifestPath); err == nil && !info.IsDir() {
			return packDir, nil
		}
	}

	if err := c.downloadAndExtract(ctx, targetURL, packDir, packName, expectedSHA256); err != nil {
		return "", fmt.Errorf("failed to download remote pack %s (%s): %w", packName, targetURL, err)
	}

	return packDir, nil
}

func (c *Client) resolveURI(pathOrURI string) (string, string, error) {
	trimmed := strings.TrimSpace(pathOrURI)
	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, "pack:") || strings.HasPrefix(lower, "registry:") {
		parts := strings.SplitN(trimmed, ":", 2)
		aliasName := strings.ToLower(strings.TrimSpace(parts[1]))

		c.mu.RLock()
		targetURL, ok := c.Aliases[aliasName]
		c.mu.RUnlock()

		if !ok {
			return "", "", fmt.Errorf("unknown registry alias %q. Available aliases: %s", aliasName, c.AvailableAliases())
		}
		return targetURL, aliasName, nil
	}

	// It's a direct URL
	hash := sha256.Sum256([]byte(lower))
	packName := fmt.Sprintf("url-%s", hex.EncodeToString(hash[:8]))
	return trimmed, packName, nil
}

func (c *Client) getPackDir(packName, url string) string {
	hash := sha256.Sum256([]byte(url))
	slug := fmt.Sprintf("%s-%s", sanitizeSlug(packName), hex.EncodeToString(hash[:6]))
	return filepath.Join(c.CacheDir, slug)
}

func sanitizeSlug(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, " ", "-")
	if s == "" {
		return "pack"
	}
	return s
}

// AvailableAliases returns a comma-separated list of registered pack aliases.
func (c *Client) AvailableAliases() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	aliases := make([]string, 0, len(c.Aliases))
	for a := range c.Aliases {
		aliases = append(aliases, a)
	}
	return strings.Join(aliases, ", ")
}

func (c *Client) downloadAndExtract(ctx context.Context, url string, packDir string, packName string, expectedSHA256 string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "TreeGuard-SAST/1.0")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, resp.Status)
	}

	if err := os.MkdirAll(packDir, 0755); err != nil {
		return err
	}

	hasher := sha256.New()
	bodyReader := io.TeeReader(resp.Body, hasher)

	isTarGz := strings.HasSuffix(strings.ToLower(url), ".tar.gz") ||
		strings.HasSuffix(strings.ToLower(url), ".tgz") ||
		strings.Contains(resp.Header.Get("Content-Type"), "gzip") ||
		strings.Contains(resp.Header.Get("Content-Type"), "tar")

	filesCount := 0

	if isTarGz {
		cnt, err := extractTarGz(bodyReader, packDir)
		if err != nil {
			// Fallback: if tar extraction fails, attempt reading as single file
			_ = os.RemoveAll(packDir)
			_ = os.MkdirAll(packDir, 0755)
			cnt, err = saveSingleFile(bodyReader, packDir, "rule.rego")
			if err != nil {
				return fmt.Errorf("extract tar.gz: %w", err)
			}
		}
		filesCount = cnt
	} else {
		filename := filepath.Base(url)
		if !strings.HasSuffix(strings.ToLower(filename), ".rego") {
			filename = "rule.rego"
		}
		cnt, err := saveSingleFile(bodyReader, packDir, filename)
		if err != nil {
			return fmt.Errorf("save rule file: %w", err)
		}
		filesCount = cnt
	}

	computedHash := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA256 != "" && !strings.EqualFold(expectedSHA256, computedHash) {
		_ = os.RemoveAll(packDir)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSHA256, computedHash)
	}

	// Write manifest.json
	meta := PackMeta{
		Name:         packName,
		URL:          url,
		Path:         packDir,
		DownloadedAt: time.Now(),
		FilesCount:   filesCount,
		SHA256:       computedHash,
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(packDir, ManifestFilename), data, 0644)
}

func extractTarGz(r io.Reader, destDir string) (int, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return 0, err
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	count := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}

		cleanPath := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
			continue // Protect against zip-slip path traversal
		}

		target := filepath.Join(destDir, cleanPath)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return count, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return count, err
			}
			if err := func() error {
				outFile, err := os.Create(target)
				if err != nil {
					return err
				}
				defer func() { _ = outFile.Close() }()
				// Limit extraction to 50MB per file to prevent decompression bombs (G110)
				limitedReader := io.LimitReader(tr, 50*1024*1024)
				if _, err := io.Copy(outFile, limitedReader); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return count, err
			}

			if strings.HasSuffix(strings.ToLower(target), ".rego") {
				count++
			}
		}
	}

	return count, nil
}

func saveSingleFile(r io.Reader, destDir string, filename string) (int, error) {
	target := filepath.Join(destDir, filename)
	outFile, err := os.Create(target)
	if err != nil {
		return 0, err
	}
	defer func() { _ = outFile.Close() }()

	// Limit to 50MB
	limitedReader := io.LimitReader(r, 50*1024*1024)
	if _, err := io.Copy(outFile, limitedReader); err != nil {
		return 0, err
	}

	return 1, nil
}

// ListPacks lists all locally cached rule packs.
func (c *Client) ListPacks() ([]PackMeta, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var packs []PackMeta
	entries, err := os.ReadDir(c.CacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifestPath := filepath.Join(c.CacheDir, entry.Name(), ManifestFilename)
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			continue
		}

		var meta PackMeta
		if err := json.Unmarshal(data, &meta); err == nil {
			packs = append(packs, meta)
		}
	}

	return packs, nil
}

// CleanCache removes all cached rule packs.
func (c *Client) CleanCache() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return os.RemoveAll(c.CacheDir)
}

// UpdatePack forces re-downloading a cached pack or all cached packs if URI is empty.
func (c *Client) UpdatePack(ctx context.Context, packOrURI string) error {
	if packOrURI == "" {
		packs, err := c.ListPacks()
		if err != nil {
			return err
		}
		for _, p := range packs {
			if _, err := c.ResolveRulePath(ctx, p.URL, true); err != nil {
				return err
			}
		}
		return nil
	}

	_, err := c.ResolveRulePath(ctx, packOrURI, true)
	return err
}
