package parser_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loganprice/treeguard/internal/parser"
)

func TestParseSourceTableDriven(t *testing.T) {
	p := parser.New()

	tests := []struct {
		name         string
		filePath     string
		source       string
		lang         string
		minNodes     int
		expectedRoot string
		wantErr      bool
	}{
		{
			name:         "Python function",
			filePath:     "test.py",
			source:       "def hello(name):\n    print('Hello, ' + name)\n",
			lang:         "python",
			minNodes:     5,
			expectedRoot: "module",
			wantErr:      false,
		},
		{
			name:         "JavaScript function",
			filePath:     "test.js",
			source:       "function add(a, b) {\n    return a + b;\n}\n",
			lang:         "javascript",
			minNodes:     5,
			expectedRoot: "program",
			wantErr:      false,
		},
		{
			name:         "TypeScript const",
			filePath:     "test.ts",
			source:       "const num: number = 42;\n",
			lang:         "typescript",
			minNodes:     4,
			expectedRoot: "program",
			wantErr:      false,
		},
		{
			name:         "TSX element",
			filePath:     "test.tsx",
			source:       "const Component = () => <div>Hello</div>;\n",
			lang:         "tsx",
			minNodes:     5,
			expectedRoot: "program",
			wantErr:      false,
		},
		{
			name:         "Go package",
			filePath:     "test.go",
			source:       "package main\n\nfunc main() {\n    println(\"hello\")\n}\n",
			lang:         "go",
			minNodes:     5,
			expectedRoot: "source_file",
			wantErr:      false,
		},
		{
			name:         "Java class",
			filePath:     "Test.java",
			source:       "public class Test {\n    public static void main(String[] args) {}\n}\n",
			lang:         "java",
			minNodes:     5,
			expectedRoot: "program",
			wantErr:      false,
		},
		{
			name:         "Rust fn",
			filePath:     "test.rs",
			source:       "fn main() {\n    println!(\"hello\");\n}\n",
			lang:         "rust",
			minNodes:     5,
			expectedRoot: "source_file",
			wantErr:      false,
		},
		{
			name:         "Ruby def",
			filePath:     "test.rb",
			source:       "def greet\n    puts 'hi'\nend\n",
			lang:         "ruby",
			minNodes:     4,
			expectedRoot: "program",
			wantErr:      false,
		},
		{
			name:         "C function",
			filePath:     "test.c",
			source:       "int main() { return 0; }\n",
			lang:         "c",
			minNodes:     4,
			expectedRoot: "translation_unit",
			wantErr:      false,
		},
		{
			name:         "C++ function",
			filePath:     "test.cpp",
			source:       "#include <iostream>\nint main() { std::cout << 42; return 0; }\n",
			lang:         "cpp",
			minNodes:     5,
			expectedRoot: "translation_unit",
			wantErr:      false,
		},
		{
			name:         "PHP script",
			filePath:     "test.php",
			source:       "<?php\necho 'hello';\n",
			lang:         "php",
			minNodes:     3,
			expectedRoot: "program",
			wantErr:      false,
		},
		{
			name:         "JSON object",
			filePath:     "test.json",
			source:       "{\"name\": \"treeguard\", \"version\": 1}\n",
			lang:         "json",
			minNodes:     4,
			expectedRoot: "document",
			wantErr:      false,
		},
		{
			name:         "Dockerfile instructions",
			filePath:     "Dockerfile",
			source:       "FROM node:18-alpine\nUSER node\n",
			lang:         "dockerfile",
			minNodes:     3,
			expectedRoot: "source_file",
			wantErr:      false,
		},
		{
			name:     "Invalid language",
			filePath: "test.unknown",
			source:   "some content",
			lang:     "invalid_language",
			wantErr:  true,
		},
		{
			name:         "Empty source",
			filePath:     "empty.py",
			source:       "",
			lang:         "python",
			minNodes:     1,
			expectedRoot: "module",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := p.ParseSource(tt.filePath, []byte(tt.source), tt.lang)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSource() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			defer parsed.Close()

			if parsed.Input.AST == nil {
				t.Fatal("expected non-nil AST root")
			}

			if parsed.Input.AST.Type != tt.expectedRoot {
				t.Errorf("AST root type = %q, want %q", parsed.Input.AST.Type, tt.expectedRoot)
			}

			if len(parsed.Input.Nodes) < tt.minNodes {
				t.Errorf("Nodes count = %d, want at least %d", len(parsed.Input.Nodes), tt.minNodes)
			}

			// Verify node indexing and parent-child consistency
			for i, node := range parsed.Input.Nodes {
				if node.ID != i {
					t.Errorf("node ID mismatch: got %d, want %d", node.ID, i)
				}
				if node.ParentID >= 0 && node.ParentID >= len(parsed.Input.Nodes) {
					t.Errorf("invalid ParentID %d for node %d", node.ParentID, node.ID)
				}
			}
		})
	}
}

func TestParseFileTableDriven(t *testing.T) {
	p := parser.New()
	tmpDir := t.TempDir()

	validFile := filepath.Join(tmpDir, "sample.go")
	if err := os.WriteFile(validFile, []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	unsupportedExtFile := filepath.Join(tmpDir, "sample.unknown")
	if err := os.WriteFile(unsupportedExtFile, []byte("unknown content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	missingFile := filepath.Join(tmpDir, "non_existent.go")

	tests := []struct {
		name     string
		filePath string
		wantErr  bool
	}{
		{
			name:     "Valid Go file",
			filePath: validFile,
			wantErr:  false,
		},
		{
			name:     "Unsupported file extension",
			filePath: unsupportedExtFile,
			wantErr:  true,
		},
		{
			name:     "Non-existent file",
			filePath: missingFile,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := p.ParseFile(tt.filePath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseFile(%q) error = %v, wantErr %v", tt.filePath, err, tt.wantErr)
			}
			if parsed != nil {
				parsed.Close()
				// Test double Close safety
				parsed.Close()
			}
		})
	}
}
