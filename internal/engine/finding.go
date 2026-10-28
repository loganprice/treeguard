package engine

import (
	"fmt"
	"strings"

	"github.com/loganprice/treeguard/internal/parser"
)

// Severity levels matching Semgrep / SARIF conventions.
const (
	SeverityError   = "ERROR"
	SeverityWarning = "WARNING"
	SeverityInfo    = "INFO"
)

// Fix defines an automated code replacement/remediation.
type Fix struct {
	Replacement string       `json:"replacement"`
	Range       parser.Range `json:"range"`
}

// Finding represents a vulnerability or code smell detected by a rule.
type Finding struct {
	RuleID   string                 `json:"rule_id"`
	Title    string                 `json:"title,omitempty"`
	Message  string                 `json:"message"`
	Severity string                 `json:"severity"`
	File     string                 `json:"file"`
	Range    parser.Range           `json:"range"`
	Code     string                 `json:"code,omitempty"`
	CWE      string                 `json:"cwe,omitempty"`
	OWASP    string                 `json:"owasp,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	Fix      *Fix                   `json:"fix,omitempty"`
}

// NormalizeSeverity normalizes severity strings to ERROR, WARNING, or INFO.
func NormalizeSeverity(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "ERROR", "CRITICAL", "HIGH":
		return SeverityError
	case "WARNING", "WARN", "MEDIUM":
		return SeverityWarning
	default:
		return SeverityInfo
	}
}

// Key returns a unique identifier for finding deduplication.
func (f Finding) Key() string {
	return fmt.Sprintf("%s:%s:%d:%d:%d:%d",
		f.RuleID,
		f.File,
		f.Range.Start.Line,
		f.Range.Start.Column,
		f.Range.End.Line,
		f.Range.End.Column,
	)
}

// DeduplicateFindings removes duplicate findings based on their unique key.
func DeduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]struct{}, len(findings))
	unique := make([]Finding, 0, len(findings))

	for _, f := range findings {
		key := f.Key()
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			unique = append(unique, f)
		}
	}

	return unique
}

// FilterBySeverity filters findings to only those with at least minSeverity.
func FilterBySeverity(findings []Finding, minSeverity string) []Finding {
	minLevel := severityLevel(minSeverity)
	filtered := make([]Finding, 0, len(findings))

	for _, f := range findings {
		if severityLevel(f.Severity) >= minLevel {
			filtered = append(filtered, f)
		}
	}

	return filtered
}

func severityLevel(sev string) int {
	switch NormalizeSeverity(sev) {
	case SeverityError:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
