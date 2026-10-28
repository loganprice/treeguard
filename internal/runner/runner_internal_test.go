package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAnnotationsTableDriven(t *testing.T) {
	tmpDir := t.TempDir()

	validAnnotated := filepath.Join(tmpDir, "valid.py")
	content := `# ruleid: py-eval-rule
eval("1+1")
# ok: py-eval-rule
print("safe")
# ok
print("also safe")
`
	if err := os.WriteFile(validAnnotated, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	nonExistent := filepath.Join(tmpDir, "missing.py")

	tests := []struct {
		name          string
		filePath      string
		wantExpected  int
		wantForbidden int
		wantErr       bool
	}{
		{
			name:          "Parse valid annotations",
			filePath:      validAnnotated,
			wantExpected:  1,
			wantForbidden: 2,
			wantErr:       false,
		},
		{
			name:          "Parse missing file error",
			filePath:      nonExistent,
			wantExpected:  0,
			wantForbidden: 0,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp, fbd, err := parseAnnotations(tt.filePath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAnnotations() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(exp) != tt.wantExpected {
				t.Errorf("Expected annotations count = %d, want %d", len(exp), tt.wantExpected)
			}
			if len(fbd) != tt.wantForbidden {
				t.Errorf("Forbidden annotations count = %d, want %d", len(fbd), tt.wantForbidden)
			}
		})
	}
}

func TestGenerateDiffTableDriven(t *testing.T) {
	tests := []struct {
		name       string
		filePath   string
		origText   string
		newText    string
		wantSubstr string
	}{
		{
			name:       "Diff with changed line",
			filePath:   "test.py",
			origText:   "eval(x)\n",
			newText:    "ast.literal_eval(x)\n",
			wantSubstr: "-eval(x)",
		},
		{
			name:       "Diff with identical content",
			filePath:   "test.py",
			origText:   "same\n",
			newText:    "same\n",
			wantSubstr: "--- test.py",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := generateDiff(tt.filePath, tt.origText, tt.newText)
			if !strings.Contains(diff, tt.wantSubstr) {
				t.Errorf("generateDiff() output missing %q\nGot:\n%s", tt.wantSubstr, diff)
			}
		})
	}
}
