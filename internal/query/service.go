package query

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/rego"

	"github.com/loganprice/treeguard/internal/parser"
)

// Service provides AST inspection and ad-hoc Rego query execution over source code.
type Service struct {
	parser *parser.Parser
}

// NewService creates a new query service.
func NewService() *Service {
	return &Service{
		parser: parser.New(),
	}
}

// DumpAST parses the target file and returns either the full AST input structure or the flattened nodes list.
func (s *Service) DumpAST(filePath string, langOverride string, nodesOnly bool) (any, error) {
	filePath = filepath.Clean(filePath)
	lang := langOverride
	var err error
	if lang == "" {
		lang, err = parser.DetectLanguage(filePath)
		if err != nil {
			return nil, err
		}
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", filePath, err)
	}

	parsed, err := s.parser.ParseSource(filePath, content, lang)
	if err != nil {
		return nil, err
	}
	defer parsed.Close()

	if nodesOnly {
		return parsed.Input.Nodes, nil
	}
	return parsed.Input, nil
}

// Eval parses the target file and evaluates an ad-hoc Rego expression against the AST input.
func (s *Service) Eval(ctx context.Context, filePath string, langOverride string, expr string) ([]rego.Vars, error) {
	if expr == "" {
		return nil, fmt.Errorf("query expression required")
	}

	filePath = filepath.Clean(filePath)
	lang := langOverride
	var err error
	if lang == "" {
		lang, err = parser.DetectLanguage(filePath)
		if err != nil {
			return nil, err
		}
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", filePath, err)
	}

	parsed, err := s.parser.ParseSource(filePath, content, lang)
	if err != nil {
		return nil, err
	}
	defer parsed.Close()

	queryStr := fmt.Sprintf("result = %s", expr)
	r := rego.New(
		rego.Query(queryStr),
		rego.Input(parsed.Input),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluate query: %w", err)
	}

	var results []rego.Vars
	for _, result := range rs {
		results = append(results, result.Bindings)
	}

	return results, nil
}
