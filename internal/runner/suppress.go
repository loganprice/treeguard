package runner

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/loganprice/treeguard/internal/engine"
)

var (
	// Matches: // treeguard:ignore, # treeguard:ignore:rule-1,rule-2 justification text
	suppressRegex = regexp.MustCompile(`(?:#|//|/\*|--)\s*treeguard:ignore(?::([a-zA-Z0-9_\-\.,\s]+))?`)
)

// SuppressionDirective represents a parsed inline suppression rule on a specific line.
type SuppressionDirective struct {
	Line  int
	Rules map[string]bool // map of rule ID -> true, or "*" -> true for all rules
}

// FileSuppressions maps line numbers (1-indexed) to suppression directives.
type FileSuppressions map[int][]SuppressionDirective

// ParseFileSuppressions parses inline code comments from a file on disk.
func ParseFileSuppressions(filePath string) (FileSuppressions, error) {
	filePath = filepath.Clean(filePath)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ParseSourceSuppressions(string(content)), nil
}

// ParseSourceSuppressions parses inline code comments from a source string.
func ParseSourceSuppressions(content string) FileSuppressions {
	fs := make(FileSuppressions)

	scanner := bufio.NewScanner(bytes.NewBufferString(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		matches := suppressRegex.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}

		rulesMap := make(map[string]bool)
		if len(matches) > 1 && strings.TrimSpace(matches[1]) != "" {
			// Extract rule IDs (stop at whitespace if justification message is provided)
			rawRules := strings.TrimSpace(matches[1])
			rulePart := strings.Fields(rawRules)[0] // Take first token before justification text
			parts := strings.Split(rulePart, ",")
			for _, p := range parts {
				clean := strings.TrimSpace(p)
				if clean != "" {
					rulesMap[clean] = true
				}
			}
		}

		if len(rulesMap) == 0 {
			rulesMap["*"] = true // Suppress all rules if no specific ID provided
		}

		dir := SuppressionDirective{
			Line:  lineNum,
			Rules: rulesMap,
		}

		fs[lineNum] = append(fs[lineNum], dir)
	}

	return fs
}

// IsSuppressed checks whether a finding with ruleID on findingLine is suppressed by an inline comment.
func (fs FileSuppressions) IsSuppressed(ruleID string, findingLine int) bool {
	if len(fs) == 0 || findingLine <= 0 {
		return false
	}

	// Check same-line comment (line == findingLine) and preceding-line comment (line == findingLine - 1)
	checkLines := []int{findingLine, findingLine - 1}

	for _, l := range checkLines {
		directives, exists := fs[l]
		if !exists {
			continue
		}

		for _, dir := range directives {
			if dir.Rules["*"] || dir.Rules[ruleID] {
				return true
			}
		}
	}

	return false
}

// FilterSuppressedFindings removes findings that match inline code suppressions.
func FilterSuppressedFindings(findings []engine.Finding, fileSuppressions map[string]FileSuppressions) ([]engine.Finding, int) {
	if len(findings) == 0 {
		return nil, 0
	}

	filtered := make([]engine.Finding, 0, len(findings))
	suppressedCount := 0

	for _, f := range findings {
		fs, exists := fileSuppressions[f.File]
		if !exists && f.File != "" {
			// Parse file suppressions on demand if not cached
			var err error
			fs, err = ParseFileSuppressions(f.File)
			if err == nil {
				fileSuppressions[f.File] = fs
				exists = true
			}
		}

		if exists && fs.IsSuppressed(f.RuleID, f.Range.Start.Line) {
			suppressedCount++
			continue
		}

		filtered = append(filtered, f)
	}

	return filtered, suppressedCount
}
