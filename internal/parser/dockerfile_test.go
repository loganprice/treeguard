package parser_test

import (
	"testing"

	tree_sitter_dockerfile "github.com/loganprice/tree-sitter-docker/bindings/go"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/loganprice/treeguard/internal/parser"
)

func TestDockerfileLanguage(t *testing.T) {
	lang := tree_sitter.NewLanguage(tree_sitter_dockerfile.Language())
	if lang == nil {
		t.Fatal("tree_sitter_dockerfile.Language() returned nil")
	}

	p := tree_sitter.NewParser()
	defer p.Close()

	if err := p.SetLanguage(lang); err != nil {
		t.Fatalf("SetLanguage() error = %v", err)
	}

	code := []byte("FROM alpine:3.18\nUSER root\nRUN echo hello\n")
	tree := p.Parse(code, nil)
	if tree == nil {
		t.Fatal("Parse() returned nil tree")
	}
	defer tree.Close()

	root := tree.RootNode()
	if root.Kind() != "source_file" && root.Kind() != "dockerfile" {
		t.Errorf("root node kind = %s, want source_file or dockerfile", root.Kind())
	}

	if root.ChildCount() == 0 {
		t.Errorf("root child count = 0, expected instruction nodes")
	}
}

func TestDockerfileParserRegistry(t *testing.T) {
	p := parser.New()
	code := []byte("FROM alpine:3.18\nUSER root\nRUN echo hello\n")
	parsed, err := p.ParseSource("Dockerfile", code, "dockerfile")
	if err != nil {
		t.Fatalf("ParseSource() error = %v", err)
	}
	defer parsed.Close()

	if parsed.Input.File.Language != "dockerfile" {
		t.Errorf("got language %s, want dockerfile", parsed.Input.File.Language)
	}

	if len(parsed.Input.Nodes) == 0 {
		t.Fatal("expected parsed nodes, got 0")
	}

	// Verify instruction nodes exist
	var hasFrom, hasUser, hasRun bool
	for _, n := range parsed.Input.Nodes {
		switch n.Type {
		case "from_instruction":
			hasFrom = true
		case "user_instruction":
			hasUser = true
		case "run_instruction":
			hasRun = true
		}
	}

	if !hasFrom || !hasUser || !hasRun {
		t.Errorf("missing instructions: hasFrom=%v, hasUser=%v, hasRun=%v", hasFrom, hasUser, hasRun)
	}
}
