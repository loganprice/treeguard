package engine_test

import (
	"testing"

	"github.com/loganprice/treeguard/internal/engine"
	"github.com/loganprice/treeguard/internal/parser"
)

func TestProjectCallGraphTableDriven(t *testing.T) {
	p := parser.New()

	tests := []struct {
		name          string
		sourceFiles   map[string]string
		language      string
		lookupName    string
		wantFound     bool
		wantFile      string
		wantParamLen  int
		wantParamName string
	}{
		{
			name: "Index Python function definition and parameter",
			sourceFiles: map[string]string{
				"service.py": `
def process_data(raw_input):
    return raw_input
`,
			},
			language:      "python",
			lookupName:    "process_data",
			wantFound:     true,
			wantFile:      "service.py",
			wantParamLen:  1,
			wantParamName: "raw_input",
		},
		{
			name: "Index Go function declaration",
			sourceFiles: map[string]string{
				"query.go": `
package main

func ExecuteQuery(sqlText string) {
    _ = sqlText
}
`,
			},
			language:      "go",
			lookupName:    "ExecuteQuery",
			wantFound:     true,
			wantFile:      "query.go",
			wantParamLen:  1,
			wantParamName: "sqlText",
		},
		{
			name: "Index JavaScript function declaration",
			sourceFiles: map[string]string{
				"app.js": `
function handleRequest(req, res) {
    res.send(req);
}
`,
			},
			language:      "javascript",
			lookupName:    "handleRequest",
			wantFound:     true,
			wantFile:      "app.js",
			wantParamLen:  2,
			wantParamName: "req",
		},
		{
			name: "Lookup non-existent function returns empty",
			sourceFiles: map[string]string{
				"app.py": `x = 10`,
			},
			language:   "python",
			lookupName: "nonExistentFunc",
			wantFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cg := engine.NewProjectCallGraph()

			for filePath, src := range tt.sourceFiles {
				pf, err := p.ParseSource(filePath, []byte(src), tt.language)
				if err != nil {
					t.Fatalf("ParseSource failed for %s: %v", filePath, err)
				}
				defer pf.Close()
				cg.IndexFile(pf)
			}

			syms := cg.FindFunctions(tt.lookupName)
			if (len(syms) > 0) != tt.wantFound {
				t.Fatalf("FindFunctions(%q) found = %v, wantFound = %v", tt.lookupName, len(syms) > 0, tt.wantFound)
			}

			if tt.wantFound {
				sym := syms[0]
				if sym.FilePath != tt.wantFile {
					t.Errorf("sym.FilePath = %q, want %q", sym.FilePath, tt.wantFile)
				}
				if len(sym.ParamNames) != tt.wantParamLen {
					t.Errorf("len(ParamNames) = %d, want %d", len(sym.ParamNames), tt.wantParamLen)
				}
				if tt.wantParamLen > 0 && sym.ParamNames[0] != tt.wantParamName {
					t.Errorf("ParamNames[0] = %q, want %q", sym.ParamNames[0], tt.wantParamName)
				}
			}
		})
	}
}

func TestProjectCallGraphNilAndEdgeCases(t *testing.T) {
	cg := engine.NewProjectCallGraph()

	// Test indexing nil ParsedFile safely
	cg.IndexFile(nil)

	syms := cg.FindFunctions("anything")
	if len(syms) != 0 {
		t.Errorf("expected empty symbols for nil lookup, got %d", len(syms))
	}
}
