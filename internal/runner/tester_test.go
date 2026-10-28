package runner_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/loganprice/treeguard/internal/runner"
)

func TestRuleTesterTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	ruleDir := filepath.Join(tmpDir, "rules")
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		t.Fatal(err)
	}

	ruleFile := filepath.Join(ruleDir, "eval.rego")
	ruleContent := `
package rules.python.eval
metadata := { "id": "py-eval", "severity": "ERROR" }
deny[finding] {
	input.file.language == "python"
	call := input.nodes[_]
	call.type == "call"
	call.fields.function.text == "eval"
	finding := call
}
`
	if err := os.WriteFile(ruleFile, []byte(ruleContent), 0644); err != nil {
		t.Fatal(err)
	}

	testDir := filepath.Join(tmpDir, "tests")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	// 1. Passing test fixture
	passFixture := filepath.Join(testDir, "pass_test.py")
	os.WriteFile(passFixture, []byte("# ruleid: py-eval\neval('1')\n# ok: py-eval\nprint('safe')\n"), 0644)

	// 2. Failing test fixture (false negative)
	fnFixture := filepath.Join(testDir, "fn_test.py")
	os.WriteFile(fnFixture, []byte("# ruleid: py-eval\nprint('safe')\n"), 0644)

	// 3. Unannotated file (should be skipped)
	unannotatedFixture := filepath.Join(testDir, "plain.py")
	os.WriteFile(unannotatedFixture, []byte("print('hello')\n"), 0644)

	tests := []struct {
		name       string
		rulePaths  []string
		testPaths  []string
		wantPassed int
		wantFailed int
		wantErr    bool
	}{
		{
			name:       "All passing rule assertions",
			rulePaths:  []string{ruleDir},
			testPaths:  []string{passFixture},
			wantPassed: 1,
			wantFailed: 0,
			wantErr:    false,
		},
		{
			name:       "Failing assertion (false negative)",
			rulePaths:  []string{ruleDir},
			testPaths:  []string{fnFixture},
			wantPassed: 0,
			wantFailed: 1,
			wantErr:    false,
		},
		{
			name:       "Unannotated file skip",
			rulePaths:  []string{ruleDir},
			testPaths:  []string{unannotatedFixture},
			wantPassed: 0,
			wantFailed: 0,
			wantErr:    false,
		},
		{
			name:       "Non-existent test path error",
			rulePaths:  []string{ruleDir},
			testPaths:  []string{filepath.Join(tmpDir, "missing_test")},
			wantPassed: 0,
			wantFailed: 0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := runner.NewRuleTester()
			res, err := rt.RunTests(ctx, tt.rulePaths, tt.testPaths)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RunTests() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if res.PassedTests != tt.wantPassed {
				t.Errorf("PassedTests = %d, want %d", res.PassedTests, tt.wantPassed)
			}
			if res.FailedTests != tt.wantFailed {
				t.Errorf("FailedTests = %d, want %d", res.FailedTests, tt.wantFailed)
			}
		})
	}
}

func TestRuleTesterRenderTestResults(t *testing.T) {
	rt := runner.NewRuleTester()

	t.Run("All Passed", func(t *testing.T) {
		res := &runner.TestResult{
			TotalTests:  2,
			PassedTests: 2,
			FailedTests: 0,
		}
		var out, errOut bytes.Buffer
		err := rt.RenderTestResults(&out, &errOut, res)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Contains(out.Bytes(), []byte("All 2 rule tests passed!")) {
			t.Errorf("output missing success text: %s", out.String())
		}
	})

	t.Run("Failures", func(t *testing.T) {
		res := &runner.TestResult{
			TotalTests:  2,
			PassedTests: 1,
			FailedTests: 1,
			Failures: []runner.TestFailure{
				{
					File:   "test.py",
					Line:   10,
					RuleID: "py-eval",
					Reason: "rule failed",
				},
			},
		}
		var out, errOut bytes.Buffer
		err := rt.RenderTestResults(&out, &errOut, res)
		if err == nil {
			t.Fatal("expected error on failed tests, got nil")
		}
		if !bytes.Contains(errOut.Bytes(), []byte("FAIL")) {
			t.Errorf("expected FAIL in errOut: %s", errOut.String())
		}
	})
}
