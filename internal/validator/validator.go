package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/loganprice/treeguard/internal/engine"
)

// ValidationOptions controls the behavior of rule validation.
type ValidationOptions struct {
	Strict bool
}

// ValidationIssue represents a single rule linting error or warning.
type ValidationIssue struct {
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Severity string `json:"severity"` // "ERROR" or "WARNING"
	Message  string `json:"message"`
	RuleID   string `json:"rule_id,omitempty"`
}

// RuleValidationResult contains lint results for a single .rego file.
type RuleValidationResult struct {
	File   string            `json:"file"`
	RuleID string            `json:"rule_id,omitempty"`
	Valid  bool              `json:"valid"`
	Issues []ValidationIssue `json:"issues"`
}

// ValidationReport summarizes rule linting results across all target files.
type ValidationReport struct {
	FilesScanned int                    `json:"files_scanned"`
	RulesCount   int                    `json:"rules_count"`
	Passed       bool                   `json:"passed"`
	ErrorsCount  int                    `json:"errors_count"`
	WarnsCount   int                    `json:"warns_count"`
	Results      []RuleValidationResult `json:"results"`
}

// RuleValidator provides static linting and compilation validation for Rego rules.
type RuleValidator struct{}

// New creates a new RuleValidator instance.
func New() *RuleValidator {
	return &RuleValidator{}
}

// ValidatePaths scans target paths for .rego files and validates them against TreeGuard rule standards.
func (v *RuleValidator) ValidatePaths(ctx context.Context, paths []string, opts ValidationOptions) (*ValidationReport, error) {
	ruleFiles, err := discoverRegoFiles(paths)
	if err != nil {
		return nil, err
	}

	report := &ValidationReport{
		FilesScanned: len(ruleFiles),
		Passed:       true,
		Results:      make([]RuleValidationResult, 0, len(ruleFiles)),
	}

	for _, filePath := range ruleFiles {
		res := v.ValidateFile(ctx, filePath, opts)
		if !res.Valid {
			report.Passed = false
		}
		for _, issue := range res.Issues {
			if issue.Severity == "ERROR" {
				report.ErrorsCount++
			} else {
				report.WarnsCount++
			}
		}
		if res.RuleID != "" {
			report.RulesCount++
		}
		report.Results = append(report.Results, res)
	}

	return report, nil
}

// ValidateFile performs linting and validation on a single .rego file.
func (v *RuleValidator) ValidateFile(ctx context.Context, filePath string, opts ValidationOptions) RuleValidationResult {
	filePath = filepath.Clean(filePath)
	res := RuleValidationResult{
		File:  filePath,
		Valid: true,
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		res.Valid = false
		res.Issues = append(res.Issues, ValidationIssue{
			File:     filePath,
			Severity: "ERROR",
			Message:  fmt.Sprintf("Failed to read file: %v", err),
		})
		return res
	}

	// 1. OPA AST Syntax Parsing
	mod, err := ast.ParseModule(filePath, string(content))
	if err != nil {
		res.Valid = false
		if astErrs, ok := err.(ast.Errors); ok {
			for _, astErr := range astErrs {
				res.Issues = append(res.Issues, ValidationIssue{
					File:     filePath,
					Line:     astErr.Location.Row,
					Column:   astErr.Location.Col,
					Severity: "ERROR",
					Message:  astErr.Message,
				})
			}
		} else {
			res.Issues = append(res.Issues, ValidationIssue{
				File:     filePath,
				Severity: "ERROR",
				Message:  err.Error(),
			})
		}
		return res
	}

	// Helper modules (e.g. lib/sast.rego) can omit rule metadata
	isHelper := strings.Contains(filePath, "lib/") || strings.HasSuffix(filePath, "sast.rego")

	// 2. Package declaration check
	pkgPath := mod.Package.Path.String()
	if !isHelper && !strings.HasPrefix(pkgPath, "data.rules") && !strings.HasPrefix(pkgPath, "rules") {
		issueSev := "WARNING"
		if opts.Strict {
			issueSev = "ERROR"
			res.Valid = false
		}
		res.Issues = append(res.Issues, ValidationIssue{
			File:     filePath,
			Severity: issueSev,
			Message:  fmt.Sprintf("Package %q does not follow standard 'package rules.<lang>.<rule>' naming convention", pkgPath),
		})
	}

	// 3. Rego Policy Compilation Check
	var queryParts []string
	for _, term := range mod.Package.Path[1:] {
		queryParts = append(queryParts, strings.Trim(term.Value.String(), `"`))
	}
	queryStr := "data." + strings.Join(queryParts, ".")

	regoEval := rego.New(
		rego.Query(queryStr),
		rego.Module("sast.rego", engine.EmbeddedSastLib()),
		rego.Module(filePath, string(content)),
	)
	evalCtx := context.Background()
	evalRs, err := regoEval.Eval(evalCtx)
	if err != nil {
		res.Valid = false
		res.Issues = append(res.Issues, ValidationIssue{
			File:     filePath,
			Severity: "ERROR",
			Message:  fmt.Sprintf("OPA Compilation failure: %v", err),
		})
		return res
	}

	if isHelper {
		return res
	}

	// 4. Metadata and Entrypoint Validation via compiled data evaluation
	var metaMap map[string]interface{}
	hasDenyOrFindings := false

	if len(evalRs) > 0 && len(evalRs[0].Expressions) > 0 {
		if pkgData, ok := evalRs[0].Expressions[0].Value.(map[string]interface{}); ok {
			if mVal, exists := pkgData["metadata"]; exists {
				if m, isMap := mVal.(map[string]interface{}); isMap {
					metaMap = m
				}
			}
			if _, exists := pkgData["deny"]; exists {
				hasDenyOrFindings = true
			}
			if _, exists := pkgData["findings"]; exists {
				hasDenyOrFindings = true
			}
		}
	}

	// Check metadata presence
	if metaMap == nil {
		res.Valid = false
		res.Issues = append(res.Issues, ValidationIssue{
			File:     filePath,
			Severity: "ERROR",
			Message:  "Rule file missing required 'metadata := { ... }' object declaration",
		})
	} else {
		// Check metadata.id
		ruleID, _ := metaMap["id"].(string)
		if strings.TrimSpace(ruleID) == "" {
			res.Valid = false
			res.Issues = append(res.Issues, ValidationIssue{
				File:     filePath,
				Severity: "ERROR",
				Message:  "metadata.id must be a non-empty string",
			})
		} else {
			res.RuleID = ruleID
		}

		// Check metadata.severity
		sev, _ := metaMap["severity"].(string)
		normSev := engine.NormalizeSeverity(sev)
		if strings.TrimSpace(sev) == "" {
			res.Valid = false
			res.Issues = append(res.Issues, ValidationIssue{
				File:     filePath,
				RuleID:   ruleID,
				Severity: "ERROR",
				Message:  "metadata.severity is missing",
			})
		} else if normSev != "ERROR" && normSev != "WARNING" && normSev != "INFO" {
			res.Valid = false
			res.Issues = append(res.Issues, ValidationIssue{
				File:     filePath,
				RuleID:   ruleID,
				Severity: "ERROR",
				Message:  fmt.Sprintf("Invalid metadata.severity %q (must be ERROR, WARNING, or INFO)", sev),
			})
		}

		// Check message or title
		msg, _ := metaMap["message"].(string)
		title, _ := metaMap["title"].(string)
		if strings.TrimSpace(msg) == "" && strings.TrimSpace(title) == "" {
			issueSev := "WARNING"
			if opts.Strict {
				issueSev = "ERROR"
				res.Valid = false
			}
			res.Issues = append(res.Issues, ValidationIssue{
				File:     filePath,
				RuleID:   ruleID,
				Severity: issueSev,
				Message:  "metadata missing descriptive 'message' or 'title' field",
			})
		}

		// Check CWE advisory
		cwe, _ := metaMap["cwe"].(string)
		if strings.TrimSpace(cwe) == "" {
			issueSev := "WARNING"
			if opts.Strict {
				issueSev = "ERROR"
				res.Valid = false
			}
			res.Issues = append(res.Issues, ValidationIssue{
				File:     filePath,
				RuleID:   ruleID,
				Severity: issueSev,
				Message:  "Advisory: rule metadata missing 'cwe' taxonomy reference (e.g. CWE-79)",
			})
		}
	}

	// Check rule entrypoints
	if !hasDenyOrFindings {
		res.Valid = false
		res.Issues = append(res.Issues, ValidationIssue{
			File:     filePath,
			RuleID:   res.RuleID,
			Severity: "ERROR",
			Message:  "Rule file must define at least one policy entrypoint ('deny[finding]' or 'findings[item]')",
		})
	}

	return res
}

func discoverRegoFiles(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("stat path %s: %w", p, err)
		}
		if !info.IsDir() {
			if strings.HasSuffix(strings.ToLower(p), ".rego") {
				files = append(files, p)
			}
			continue
		}

		err = filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".rego") {
				if !strings.HasSuffix(strings.ToLower(info.Name()), "_test.rego") {
					files = append(files, path)
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk directory %s: %w", p, err)
		}
	}
	return files, nil
}

// RenderConsole renders a human-readable validation report to the given writer with colors.
func (v *RuleValidator) RenderConsole(w io.Writer, report *ValidationReport) error {
	fmt.Fprintln(w, "\nValidating Rego rule files...")
	fmt.Fprintln(w)

	for _, res := range report.Results {
		if res.Valid && len(res.Issues) == 0 {
			color.New(color.FgGreen, color.Bold).Fprintf(w, "  ✓ ")
			fmt.Fprintf(w, "%s\n", res.File)
		} else {
			if !res.Valid {
				color.New(color.FgRed, color.Bold).Fprintf(w, "  ✗ ")
			} else {
				color.New(color.FgYellow, color.Bold).Fprintf(w, "  ⚠ ")
			}
			fmt.Fprintf(w, "%s", res.File)
			if res.RuleID != "" {
				fmt.Fprintf(w, " [%s]", res.RuleID)
			}
			fmt.Fprintln(w)

			for _, issue := range res.Issues {
				if issue.Severity == "ERROR" {
					color.New(color.FgRed).Fprintf(w, "      [ERROR] ")
				} else {
					color.New(color.FgYellow).Fprintf(w, "      [WARN]  ")
				}
				if issue.Line > 0 {
					fmt.Fprintf(w, "line %d: ", issue.Line)
				}
				fmt.Fprintf(w, "%s\n", issue.Message)
			}
		}
	}

	fmt.Fprintln(w)
	if report.Passed && report.ErrorsCount == 0 {
		color.New(color.FgGreen, color.Bold).Fprintf(w,
			"✓ Rule validation passed! Verified %d file(s) across %d rule(s).\n\n",
			report.FilesScanned, report.RulesCount)
		return nil
	}

	color.New(color.FgRed, color.Bold).Fprintf(w,
		"✗ Validation failed! Found %d error(s) and %d warning(s) across %d file(s).\n\n",
		report.ErrorsCount, report.WarnsCount, report.FilesScanned)
	return fmt.Errorf("rule validation failed with %d error(s)", report.ErrorsCount)
}

// RenderJSON writes the validation report formatted as indented JSON to the given writer.
func (v *RuleValidator) RenderJSON(w io.Writer, report *ValidationReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
