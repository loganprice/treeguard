package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"

	"github.com/loganprice/treeguard/internal/engine"
)

var (
	ruleIDRegex = regexp.MustCompile(`(?:#|//|/\*)\s*ruleid:\s*([a-zA-Z0-9_\-\.]+)`)
	okIDRegex   = regexp.MustCompile(`(?:#|//|/\*)\s*ok(?::\s*([a-zA-Z0-9_\-\.]+))?`)
)

// ExpectedAnnotation represents an expected rule match in a test file.
type ExpectedAnnotation struct {
	RuleID  string
	Line    int
	Matched bool
	Comment int
}

// ForbiddenAnnotation represents an assertion that no finding should occur.
type ForbiddenAnnotation struct {
	RuleID  string
	Line    int
	Comment int
}

// TestFailure describes a mismatch during rule testing.
type TestFailure struct {
	File   string
	Line   int
	RuleID string
	Reason string
}

// TestResult contains the outcome of testing rules against annotated fixtures.
type TestResult struct {
	TotalTests  int
	PassedTests int
	FailedTests int
	Failures    []TestFailure
}

// RuleTester tests rules against Semgrep-style annotated test fixtures.
type RuleTester struct {
	scanner *Scanner
}

// NewRuleTester creates a new RuleTester.
func NewRuleTester() *RuleTester {
	return &RuleTester{
		scanner: NewScanner(),
	}
}

// RunTests executes rule testing on the specified test fixture files or directories.
func (t *RuleTester) RunTests(ctx context.Context, rulePaths []string, testPaths []string) (*TestResult, error) {
	// Discover test fixture files
	testFiles, err := t.scanner.discoverFiles(ctx, ScanOptions{TargetPaths: testPaths})
	if err != nil {
		return nil, fmt.Errorf("discover test files: %w", err)
	}

	res := &TestResult{}

	for _, file := range testFiles {
		expected, forbidden, err := parseAnnotations(file)
		if err != nil {
			return nil, fmt.Errorf("parse annotations in %s: %w", file, err)
		}

		if len(expected) == 0 && len(forbidden) == 0 {
			// Not an annotated test fixture, skip
			continue
		}

		// Run scan on this test file
		scanRes, err := t.scanner.Run(ctx, ScanOptions{
			TargetPaths: []string{file},
			RulePaths:   rulePaths,
			Threads:     1,
		})
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", file, err)
		}

		t.verifyFileResults(file, expected, forbidden, scanRes.Findings, res)
	}

	return res, nil
}

func parseAnnotations(filePath string) ([]*ExpectedAnnotation, []*ForbiddenAnnotation, error) {
	filePath = filepath.Clean(filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = file.Close() }()

	var expected []*ExpectedAnnotation
	var forbidden []*ForbiddenAnnotation

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if match := ruleIDRegex.FindStringSubmatch(line); len(match) > 1 {
			ruleID := strings.TrimSpace(match[1])
			expected = append(expected, &ExpectedAnnotation{
				RuleID:  ruleID,
				Line:    lineNum + 1, // Usually target code is on the next line
				Comment: lineNum,
			})
			continue
		}

		if match := okIDRegex.FindStringSubmatch(line); len(match) > 0 {
			ruleID := ""
			if len(match) > 1 {
				ruleID = strings.TrimSpace(match[1])
			}
			forbidden = append(forbidden, &ForbiddenAnnotation{
				RuleID:  ruleID,
				Line:    lineNum + 1,
				Comment: lineNum,
			})
		}
	}

	return expected, forbidden, scanner.Err()
}

func (t *RuleTester) verifyFileResults(
	file string,
	expected []*ExpectedAnnotation,
	forbidden []*ForbiddenAnnotation,
	findings []engine.Finding,
	res *TestResult,
) {
	findingMatched := make([]bool, len(findings))

	// Verify expected findings
	for _, exp := range expected {
		res.TotalTests++
		matched := false

		for i, f := range findings {
			if f.RuleID == exp.RuleID {
				// Match if finding is on the annotated line, or next line, or previous line
				if f.Range.Start.Line == exp.Line || f.Range.Start.Line == exp.Comment || f.Range.Start.Line == exp.Line+1 {
					matched = true
					findingMatched[i] = true
					break
				}
			}
		}

		if matched {
			res.PassedTests++
			exp.Matched = true
		} else {
			res.FailedTests++
			res.Failures = append(res.Failures, TestFailure{
				File:   file,
				Line:   exp.Comment,
				RuleID: exp.RuleID,
				Reason: fmt.Sprintf("False negative: expected rule %q on line %d, but no finding was reported", exp.RuleID, exp.Line),
			})
		}
	}

	// Verify forbidden (ok) annotations
	for _, fbd := range forbidden {
		for i, f := range findings {
			if fbd.RuleID == "" || f.RuleID == fbd.RuleID {
				if f.Range.Start.Line == fbd.Line || f.Range.Start.Line == fbd.Comment {
					res.TotalTests++
					res.FailedTests++
					findingMatched[i] = true
					res.Failures = append(res.Failures, TestFailure{
						File:   file,
						Line:   fbd.Comment,
						RuleID: f.RuleID,
						Reason: fmt.Sprintf("False positive: line marked 'ok', but finding %q was reported on line %d", f.RuleID, f.Range.Start.Line),
					})
				}
			}
		}
	}

	// Verify no unexpected findings
	for i, f := range findings {
		if !findingMatched[i] {
			// Check if it matched any expected
			isExpected := false
			for _, exp := range expected {
				if exp.RuleID == f.RuleID && (f.Range.Start.Line == exp.Line || f.Range.Start.Line == exp.Comment) {
					isExpected = true
					break
				}
			}
			if !isExpected {
				res.TotalTests++
				res.FailedTests++
				res.Failures = append(res.Failures, TestFailure{
					File:   file,
					Line:   f.Range.Start.Line,
					RuleID: f.RuleID,
					Reason: fmt.Sprintf("Unexpected finding: rule %q reported on line %d with no '# ruleid:' comment", f.RuleID, f.Range.Start.Line),
				})
			}
		}
	}
}

// RenderTestResults formats test failures and test summary metrics to the given writers.
func (t *RuleTester) RenderTestResults(out, errOut io.Writer, res *TestResult) error {
	fmt.Fprintf(out, "\nRunning rule tests...\n\n")

	if len(res.Failures) > 0 {
		for _, fail := range res.Failures {
			color.New(color.FgRed, color.Bold).Fprintf(errOut, " FAIL ")
			fmt.Fprintf(errOut, " %s:%d [%s]\n", fail.File, fail.Line, fail.RuleID)
			fmt.Fprintf(errOut, "        %s\n\n", fail.Reason)
		}
	}

	if res.FailedTests == 0 && res.TotalTests > 0 {
		color.New(color.FgGreen, color.Bold).Fprintf(out, "✓ All %d rule tests passed!\n\n", res.PassedTests)
		return nil
	}

	fmt.Fprintf(out, "Test Summary: %d total assertions, %d passed, %d failed.\n\n",
		res.TotalTests, res.PassedTests, res.FailedTests)

	if res.FailedTests > 0 {
		return fmt.Errorf("%d rule test assertion(s) failed", res.FailedTests)
	}
	return nil
}
