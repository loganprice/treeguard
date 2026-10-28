package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/parser"
	"github.com/loganprice/treeguard/internal/registry"
	"github.com/loganprice/treeguard/internal/reporter"
)

var defaultIgnoredDirs = map[string]struct{}{
	".git":         {},
	".github":      {},
	"node_modules": {},
	"vendor":       {},
	".venv":        {},
	"venv":         {},
	"__pycache__":  {},
	"dist":         {},
	"build":        {},
	".idea":        {},
	".vscode":      {},
}

// ScanOptions configures the scan execution.
type ScanOptions struct {
	TargetPaths  []string
	RulePaths    []string
	Language     string
	MinSeverity  string
	Threads      int
	IgnoreDirs   []string
	Fix          bool
	DryRun       bool
	RefreshRules bool
	ChangedOnly  bool
	BaselineRef  string
	MaxFileSize  int64
	Timeout      time.Duration
}

// FixResult contains details about applied or previewed autofixes.
type FixResult struct {
	FilesFixed   int        `json:"files_fixed"`
	FixesApplied int        `json:"fixes_applied"`
	Diffs        []FileDiff `json:"diffs,omitempty"`
}

type FileDiff struct {
	File string `json:"file"`
	Diff string `json:"diff"`
}

// Scanner orchestrates file discovery, parsing, and rule evaluation.
type Scanner struct {
	engine *engine.Engine
	parser *parser.Parser
}

// NewScanner creates a new Scanner.
func NewScanner() *Scanner {
	return &Scanner{
		engine: engine.New(),
		parser: parser.New(),
	}
}

// ScanResult contains all findings and summary statistics from a scan run.
type ScanResult struct {
	Findings  []engine.Finding     `json:"findings"`
	Stats     reporter.ReportStats `json:"stats"`
	FixResult FixResult            `json:"fix_result,omitempty"`
}

// Run executes the complete scanning pipeline against target paths.
func (s *Scanner) Run(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	start := time.Now()

	if len(opts.RulePaths) == 0 {
		return nil, fmt.Errorf("no rule paths provided")
	}

	// 1. Resolve and load rules
	regClient := registry.DefaultClient
	for _, rp := range opts.RulePaths {
		resolvedPath, err := regClient.ResolveRulePath(ctx, rp, opts.RefreshRules)
		if err != nil {
			return nil, fmt.Errorf("resolve rule path %s: %w", rp, err)
		}

		cleanResolved := filepath.Clean(resolvedPath)
		info, err := os.Stat(cleanResolved)
		if err != nil {
			return nil, fmt.Errorf("access rule path %s: %w", cleanResolved, err)
		}
		if info.IsDir() {
			if err := s.engine.LoadRuleDir(cleanResolved); err != nil {
				return nil, fmt.Errorf("load rule directory %s: %w", cleanResolved, err)
			}
		} else {
			if err := s.engine.LoadRuleFile(cleanResolved); err != nil {
				return nil, fmt.Errorf("load rule file %s: %w", cleanResolved, err)
			}
		}
	}

	if err := s.engine.Compile(ctx); err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}

	// 2. Discover target files
	files, err := s.discoverFiles(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("discover files: %w", err)
	}

	if len(files) == 0 {
		return &ScanResult{
			Findings: nil,
			Stats: reporter.ReportStats{
				FilesScanned: 0,
				RulesCount:   len(opts.RulePaths),
				Duration:     time.Since(start),
			},
		}, nil
	}

	// 3. Worker pool setup
	numWorkers := opts.Threads
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers > len(files) {
		numWorkers = len(files)
	}
	if numWorkers <= 0 {
		numWorkers = 1
	}

	maxFileSize := opts.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = 5 * 1024 * 1024 // 5 MB default limit
	}

	evalTimeout := opts.Timeout
	if evalTimeout <= 0 {
		evalTimeout = 30 * time.Second
	}

	// Pre-parse target files and build project call graph for inter-procedural analysis
	callGraph := engine.NewProjectCallGraph()
	parsedFiles := make([]*parser.ParsedFile, 0, len(files))

	for _, file := range files {
		cleanFile := filepath.Clean(file)
		if fi, err := os.Stat(cleanFile); err == nil && fi.Size() > maxFileSize {
			// Skip oversized file to protect memory and AST traversal
			continue
		}

		parsed, err := s.parser.ParseFile(cleanFile)
		if err != nil {
			continue
		}
		callGraph.IndexFile(parsed)
		parsedFiles = append(parsedFiles, parsed)
	}
	defer func() {
		for _, pf := range parsedFiles {
			pf.Close()
		}
	}()

	fileChan := make(chan *parser.ParsedFile, len(parsedFiles))
	for _, pf := range parsedFiles {
		fileChan <- pf
	}
	close(fileChan)

	var wg sync.WaitGroup
	var findingsMu sync.Mutex
	var allFindings []engine.Finding

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for parsed := range fileChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				fileCtx, fileCancel := context.WithTimeout(ctx, evalTimeout)
				findings, err := s.engine.EvalFileWithCallGraph(fileCtx, parsed, callGraph)
				fileCancel()
				if err != nil {
					continue
				}

				if len(findings) > 0 {
					findingsMu.Lock()
					allFindings = append(allFindings, findings...)
					findingsMu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	// Deduplicate and filter by severity
	uniqueFindings := engine.DeduplicateFindings(allFindings)
	if opts.MinSeverity != "" {
		uniqueFindings = engine.FilterBySeverity(uniqueFindings, opts.MinSeverity)
	}

	// Filter inline code suppressions
	fileSuppressions := make(map[string]FileSuppressions)
	unsuppressedFindings, suppressedCount := FilterSuppressedFindings(uniqueFindings, fileSuppressions)

	var fixRes FixResult
	if opts.Fix || opts.DryRun {
		var err error
		fixRes, err = ApplyFixes(unsuppressedFindings, opts.DryRun)
		if err != nil {
			return nil, fmt.Errorf("apply fixes: %w", err)
		}
	}

	stats := reporter.ReportStats{
		FilesScanned:    len(files),
		RulesCount:      len(opts.RulePaths),
		Duration:        time.Since(start),
		SuppressedCount: suppressedCount,
	}

	return &ScanResult{
		Findings:  unsuppressedFindings,
		Stats:     stats,
		FixResult: fixRes,
	}, nil
}

func (s *Scanner) discoverFiles(ctx context.Context, opts ScanOptions) ([]string, error) {
	if opts.ChangedOnly || opts.BaselineRef != "" {
		targetDir := "."
		if len(opts.TargetPaths) > 0 {
			targetDir = opts.TargetPaths[0]
		}
		gitFiles, err := DiscoverGitChangedFiles(ctx, targetDir, opts.BaselineRef, opts.ChangedOnly)
		if err == nil && len(gitFiles) > 0 {
			var filtered []string
			for _, gf := range gitFiles {
				if s.isTargetFile(gf, opts.Language) {
					filtered = append(filtered, gf)
				}
			}
			return filtered, nil
		}
	}

	targets := opts.TargetPaths
	langFilter := opts.Language
	extraIgnores := opts.IgnoreDirs

	ignored := make(map[string]struct{}, len(defaultIgnoredDirs)+len(extraIgnores))
	for k := range defaultIgnoredDirs {
		ignored[k] = struct{}{}
	}
	for _, ig := range extraIgnores {
		ignored[ig] = struct{}{}
	}

	var matchedFiles []string

	for _, target := range targets {
		info, err := os.Stat(target)
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", target, err)
		}

		if !info.IsDir() {
			if s.isTargetFile(target, langFilter) {
				matchedFiles = append(matchedFiles, target)
			}
			continue
		}

		err = filepath.Walk(target, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if fi.IsDir() {
				name := fi.Name()
				if _, skip := ignored[name]; skip {
					return filepath.SkipDir
				}
				return nil
			}

			if s.isTargetFile(path, langFilter) {
				matchedFiles = append(matchedFiles, path)
			}
			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", target, err)
		}
	}

	return matchedFiles, nil
}

func (s *Scanner) isTargetFile(path string, langFilter string) bool {
	if !parser.IsSupportedFile(path) {
		return false
	}
	if langFilter != "" {
		lang, err := parser.DetectLanguage(path)
		if err != nil || !strings.EqualFold(lang, langFilter) {
			return false
		}
	}
	return true
}

// ApplyFixes applies or previews automated remediations for findings.
func ApplyFixes(findings []engine.Finding, dryRun bool) (FixResult, error) {
	var res FixResult

	fixesByFile := make(map[string][]engine.Finding)
	for _, f := range findings {
		if f.Fix != nil && f.Fix.Replacement != "" && f.File != "" {
			fixesByFile[f.File] = append(fixesByFile[f.File], f)
		}
	}

	for filePath, fList := range fixesByFile {
		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		// Sort findings by byte range start descending
		sort.Slice(fList, func(i, j int) bool {
			return fList[i].Fix.Range.Start.Byte > fList[j].Fix.Range.Start.Byte
		})

		newContent := make([]byte, len(content))
		copy(newContent, content)

		lastStart := uint(len(content))
		fileApplied := 0

		for _, f := range fList {
			start := f.Fix.Range.Start.Byte
			end := f.Fix.Range.End.Byte
			if start > end || end > uint(len(newContent)) {
				continue
			}
			if end > lastStart {
				// Skip overlapping edit
				continue
			}
			lastStart = start

			replBytes := []byte(f.Fix.Replacement)
			updated := make([]byte, 0, len(newContent)-int(end-start)+len(replBytes))
			updated = append(updated, newContent[:start]...)
			updated = append(updated, replBytes...)
			updated = append(updated, newContent[end:]...)
			newContent = updated
			fileApplied++
		}

		if fileApplied > 0 {
			res.FixesApplied += fileApplied
			res.FilesFixed++

			diff := generateDiff(filePath, string(content), string(newContent))
			res.Diffs = append(res.Diffs, FileDiff{
				File: filePath,
				Diff: diff,
			})

			if !dryRun {
				cleanPath := filepath.Clean(filePath)
				if err := os.WriteFile(cleanPath, newContent, 0644); err != nil {
					return res, fmt.Errorf("write fixed file %s: %w", cleanPath, err)
				}
			}
		}
	}

	return res, nil
}

func generateDiff(filePath string, origText, newText string) string {
	origLines := strings.Split(origText, "\n")
	newLines := strings.Split(newText, "\n")

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", filePath, filePath)

	i, j := 0, 0
	for i < len(origLines) || j < len(newLines) {
		if i < len(origLines) && j < len(newLines) && origLines[i] == newLines[j] {
			i++
			j++
			continue
		}
		fmt.Fprintf(&sb, "@@ -%d +%d @@\n", i+1, j+1)
		if i < len(origLines) {
			fmt.Fprintf(&sb, "-%s\n", origLines[i])
			i++
		}
		if j < len(newLines) {
			fmt.Fprintf(&sb, "+%s\n", newLines[j])
			j++
		}
	}

	return sb.String()
}
