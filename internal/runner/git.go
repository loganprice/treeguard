package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/loganprice/treeguard/internal/parser"
)

// DiscoverGitChangedFiles discovers modified, added, or changed files relative to Git baseRef or uncommitted working tree diff.
func DiscoverGitChangedFiles(ctx context.Context, targetDir string, baseRef string, changedOnly bool) ([]string, error) {
	if targetDir == "" {
		targetDir = "."
	}

	absTargetDir, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("abs target dir %s: %w", targetDir, err)
	}

	var changedPaths []string

	if baseRef != "" {
		// git diff --name-only <baseRef>
		out, err := runGitCmd(ctx, absTargetDir, "diff", "--name-only", baseRef)
		if err != nil {
			return nil, fmt.Errorf("git diff against %s: %w", baseRef, err)
		}
		changedPaths = append(changedPaths, parseGitFileList(out)...)
	}

	if changedOnly || baseRef == "" {
		// Working tree uncommitted changes
		outDiff, err := runGitCmd(ctx, absTargetDir, "diff", "--name-only", "HEAD")
		if err == nil {
			changedPaths = append(changedPaths, parseGitFileList(outDiff)...)
		} else {
			// Fallback: git diff --name-only (unstaged)
			outUnstaged, err := runGitCmd(ctx, absTargetDir, "diff", "--name-only")
			if err == nil {
				changedPaths = append(changedPaths, parseGitFileList(outUnstaged)...)
			}
		}

		// Untracked new files: git ls-files --others --exclude-standard
		outUntracked, err := runGitCmd(ctx, absTargetDir, "ls-files", "--others", "--exclude-standard")
		if err == nil {
			changedPaths = append(changedPaths, parseGitFileList(outUntracked)...)
		}
	}

	// Filter and normalize paths
	seen := make(map[string]bool)
	var validFiles []string

	for _, relPath := range changedPaths {
		relPath = strings.TrimSpace(relPath)
		if relPath == "" {
			continue
		}

		// Resolve path relative to working directory or repo root
		fullPath := relPath
		if !filepath.IsAbs(relPath) {
			fullPath = filepath.Join(absTargetDir, relPath)
			if _, err := os.Stat(fullPath); err != nil {
				// Try relative to current working directory
				if _, err2 := os.Stat(relPath); err2 == nil {
					fullPath = relPath
				}
			}
		}

		// Skip deleted or inaccessible files
		fi, err := os.Stat(fullPath)
		if err != nil || fi.IsDir() {
			continue
		}

		if !parser.IsSupportedFile(fullPath) {
			continue
		}

		cleanPath := filepath.Clean(fullPath)
		if !seen[cleanPath] {
			seen[cleanPath] = true
			validFiles = append(validFiles, cleanPath)
		}
	}

	return validFiles, nil
}

func runGitCmd(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s failed: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

func parseGitFileList(output string) []string {
	lines := strings.Split(output, "\n")
	var result []string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
