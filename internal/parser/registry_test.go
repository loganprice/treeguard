package parser_test

import (
	"testing"

	"github.com/loganprice/treeguard/internal/parser"
)

func TestDetectLanguageTableDriven(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
		wantErr  bool
	}{
		{"Python py", "app.py", "python", false},
		{"Python pyi", "script.pyi", "python", false},
		{"JS js", "index.js", "javascript", false},
		{"JS jsx", "component.jsx", "javascript", false},
		{"JS mjs", "module.mjs", "javascript", false},
		{"JS cjs", "server.cjs", "javascript", false},
		{"Go go", "main.go", "go", false},
		{"TS ts", "service.ts", "typescript", false},
		{"TS mts", "types.mts", "typescript", false},
		{"TSX tsx", "component.tsx", "tsx", false},
		{"Java java", "App.java", "java", false},
		{"Rust rs", "lib.rs", "rust", false},
		{"Ruby rb", "script.rb", "ruby", false},
		{"Ruby rake", "Rakefile.rake", "ruby", false},
		{"Ruby gemspec", "treeguard.gemspec", "ruby", false},
		{"C c", "main.c", "c", false},
		{"C h", "header.h", "c", false},
		{"C++ cpp", "main.cpp", "cpp", false},
		{"C++ cc", "main.cc", "cpp", false},
		{"PHP php", "index.php", "php", false},
		{"JSON json", "config.json", "json", false},
		{"Dockerfile standard", "Dockerfile", "dockerfile", false},
		{"Dockerfile prod", "Dockerfile.prod", "dockerfile", false},
		{"Containerfile standard", "Containerfile", "dockerfile", false},
		{"Unknown txt", "unknown.txt", "", true},
		{"No extension", "noext", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lang, err := parser.DetectLanguage(tt.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("DetectLanguage(%q) error = %v, wantErr %v", tt.filePath, err, tt.wantErr)
				return
			}
			if lang != tt.want {
				t.Errorf("DetectLanguage(%q) = %q, want %q", tt.filePath, lang, tt.want)
			}
		})
	}
}

func TestGetLanguageTableDriven(t *testing.T) {
	tests := []struct {
		name     string
		langName string
		wantErr  bool
	}{
		{"Valid Go", "go", false},
		{"Valid Python uppercase", "PYTHON", false},
		{"Valid JavaScript", "javascript", false},
		{"Valid Dockerfile", "dockerfile", false},
		{"Invalid lang", "brainfuck", true},
		{"Empty lang", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lang, err := parser.GetLanguage(tt.langName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLanguage(%q) error = %v, wantErr %v", tt.langName, err, tt.wantErr)
			}
			if !tt.wantErr && lang == nil {
				t.Errorf("GetLanguage(%q) returned nil language", tt.langName)
			}
		})
	}
}

func TestRegistryHelpersTableDriven(t *testing.T) {
	t.Run("SupportedLanguages", func(t *testing.T) {
		langs := parser.SupportedLanguages()
		if len(langs) < 10 {
			t.Errorf("SupportedLanguages() returned %d languages, expected at least 10", len(langs))
		}
	})

	t.Run("SupportedExtensions", func(t *testing.T) {
		exts := parser.SupportedExtensions()
		if len(exts) < 15 {
			t.Errorf("SupportedExtensions() returned %d extensions, expected at least 15", len(exts))
		}
	})

	isSupportedTests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{"Supported .go", "main.go", true},
		{"Supported .py", "app.py", true},
		{"Unsupported .txt", "notes.txt", false},
		{"Supported Dockerfile", "Dockerfile", true},
		{"Supported Containerfile", "Containerfile.prod", true},
	}

	for _, tt := range isSupportedTests {
		t.Run("IsSupportedFile_"+tt.name, func(t *testing.T) {
			got := parser.IsSupportedFile(tt.filePath)
			if got != tt.want {
				t.Errorf("IsSupportedFile(%q) = %v, want %v", tt.filePath, got, tt.want)
			}
		})
	}
}
