package engine

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/rego"

	"github.com/loganprice/treeguard/internal/parser"
)

//go:embed lib/sast.rego
var embeddedSastLib string

// EmbeddedSastLib returns the standard embedded Rego SAST helper library content.
func EmbeddedSastLib() string {
	return embeddedSastLib
}

// RuleInfo contains metadata about a registered Rego rule.
type RuleInfo struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Language    string
	CWE         string
	OWASP       string
	PackagePath string
	FilePath    string
}

// Engine compiles Rego policies and evaluates them against parsed AST inputs.
type Engine struct {
	mu            sync.RWMutex
	preparedQuery *rego.PreparedEvalQuery
	modules       map[string]string
	rules         []RuleInfo
}

// New creates a new Engine instance and embeds the standard sast.rego library.
func New() *Engine {
	e := &Engine{
		modules: make(map[string]string),
		rules:   make([]RuleInfo, 0),
	}
	// Add embedded standard library
	e.modules["sast.rego"] = embeddedSastLib
	return e
}

// LoadRuleFile loads a single .rego rule file.
func (e *Engine) LoadRuleFile(filePath string) error {
	filePath = filepath.Clean(filePath)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read rule file %s: %w", filePath, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.modules[filePath] = string(content)
	return nil
}

// LoadRuleDir recursively loads all .rego files from a directory.
func (e *Engine) LoadRuleDir(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".rego") {
			// Skip test files if any
			if strings.HasSuffix(strings.ToLower(info.Name()), "_test.rego") {
				return nil
			}
			return e.LoadRuleFile(path)
		}
		return nil
	})
}

// AddRuleModule adds a named Rego rule module directly from source string.
func (e *Engine) AddRuleModule(name, content string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.modules[name] = content
}

// Compile compiles all loaded modules into a prepared query for fast evaluation.
func (e *Engine) Compile(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var regoOpts []func(*rego.Rego)
	regoOpts = append(regoOpts, rego.Query("data.rules"))

	for name, content := range e.modules {
		regoOpts = append(regoOpts, rego.Module(name, content))
	}

	r := rego.New(regoOpts...)
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("compile rego policies: %w", err)
	}

	e.preparedQuery = &prepared
	return nil
}

// EvalFile evaluates the compiled policies against a parsed file and returns any findings.
func (e *Engine) EvalFile(ctx context.Context, parsed *parser.ParsedFile) ([]Finding, error) {
	return e.EvalFileWithCallGraph(ctx, parsed, nil)
}

// EvalFileWithCallGraph evaluates compiled policies with an optional ProjectCallGraph for inter-procedural taint analysis.
func (e *Engine) EvalFileWithCallGraph(ctx context.Context, parsed *parser.ParsedFile, callGraph *ProjectCallGraph) ([]Finding, error) {
	e.mu.RLock()
	prepared := e.preparedQuery
	e.mu.RUnlock()

	if prepared == nil {
		return nil, fmt.Errorf("engine is not compiled, call Compile() first")
	}

	// Prepare active context for built-ins
	lang, _ := parser.GetLanguage(parsed.Input.File.Language)
	act := &ActiveContext{
		ParsedFile: parsed,
		Source:     []byte(parsed.Input.File.Content),
		Language:   lang,
		CallGraph:  callGraph,
	}
	evalCtx := WithActiveContext(ctx, act)

	resultSet, err := prepared.Eval(evalCtx, rego.EvalInput(parsed.Input))
	if err != nil {
		return nil, fmt.Errorf("evaluating rules on %s: %w", parsed.Input.File.Path, err)
	}

	if len(resultSet) == 0 || len(resultSet[0].Expressions) == 0 {
		return nil, nil
	}

	rulesData, ok := resultSet[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	var findings []Finding
	extractFindingsFromData(rulesData, parsed, &findings)

	return DeduplicateFindings(findings), nil
}

// extractFindingsFromData recursively traverses data.rules extracting findings from deny/findings collections.
func extractFindingsFromData(data map[string]interface{}, parsed *parser.ParsedFile, out *[]Finding) {
	// Look for package metadata in this scope
	meta := extractMetadata(data)

	// Check for "deny" collection
	if denyVal, exists := data["deny"]; exists {
		processRuleCollection(denyVal, meta, parsed, out)
	}

	// Check for "findings" collection
	if findingsVal, exists := data["findings"]; exists {
		processRuleCollection(findingsVal, meta, parsed, out)
	}

	// Recurse into nested sub-packages
	for k, v := range data {
		if k == "deny" || k == "findings" || k == "metadata" {
			continue
		}
		if subMap, ok := v.(map[string]interface{}); ok {
			extractFindingsFromData(subMap, parsed, out)
		}
	}
}

func extractMetadata(data map[string]interface{}) map[string]interface{} {
	if metaVal, ok := data["metadata"]; ok {
		if metaMap, isMap := metaVal.(map[string]interface{}); isMap {
			return metaMap
		}
	}
	return nil
}

func processRuleCollection(val interface{}, meta map[string]interface{}, parsed *parser.ParsedFile, out *[]Finding) {
	switch items := val.(type) {
	case []interface{}:
		for _, item := range items {
			if f := itemToFinding(item, meta, parsed); f != nil {
				*out = append(*out, *f)
			}
		}
	case map[string]interface{}:
		// Sometimes Rego sets evaluate to map[string]interface{} where keys are JSON representations
		for _, item := range items {
			if f := itemToFinding(item, meta, parsed); f != nil {
				*out = append(*out, *f)
			}
		}
	}
}

func itemToFinding(item interface{}, meta map[string]interface{}, parsed *parser.ParsedFile) *Finding {
	if item == nil {
		return nil
	}

	finding := &Finding{
		File: parsed.Input.File.Path,
	}

	// Populate defaults from rule package metadata
	if meta != nil {
		if id, ok := meta["id"].(string); ok {
			finding.RuleID = id
		}
		if title, ok := meta["title"].(string); ok {
			finding.Title = title
		}
		if msg, ok := meta["message"].(string); ok {
			finding.Message = msg
		}
		if sev, ok := meta["severity"].(string); ok {
			finding.Severity = NormalizeSeverity(sev)
		}
		if cwe, ok := meta["cwe"].(string); ok {
			finding.CWE = cwe
		}
		if owasp, ok := meta["owasp"].(string); ok {
			finding.OWASP = owasp
		}
	}

	if finding.Severity == "" {
		finding.Severity = SeverityWarning
	}

	itemMap, isMap := item.(map[string]interface{})
	if !isMap {
		// If item is string, treat it as finding message
		if strMsg, isStr := item.(string); isStr {
			finding.Message = strMsg
		}
		return finding
	}

	// Extract explicitly provided finding fields
	if id, ok := itemMap["rule_id"].(string); ok && id != "" {
		finding.RuleID = id
	} else if id, ok := itemMap["id"].(string); ok && id != "" {
		finding.RuleID = id
	}

	if title, ok := itemMap["title"].(string); ok && title != "" {
		finding.Title = title
	}
	if msg, ok := itemMap["message"].(string); ok && msg != "" {
		finding.Message = msg
	}
	if sev, ok := itemMap["severity"].(string); ok && sev != "" {
		finding.Severity = NormalizeSeverity(sev)
	}
	if cwe, ok := itemMap["cwe"].(string); ok && cwe != "" {
		finding.CWE = cwe
	}
	if owasp, ok := itemMap["owasp"].(string); ok && owasp != "" {
		finding.OWASP = owasp
	}
	if code, ok := itemMap["code"].(string); ok && code != "" {
		finding.Code = code
	}
	if file, ok := itemMap["file"].(string); ok && file != "" {
		finding.File = file
	}

	// Extract Range if provided directly
	if rangeVal, ok := itemMap["range"].(map[string]interface{}); ok {
		finding.Range = parseRangeFromMap(rangeVal)
	}

	// Extract Fix if provided
	if fixVal, ok := itemMap["fix"].(map[string]interface{}); ok {
		fixObj := &Fix{}
		if repl, ok := fixVal["replacement"].(string); ok {
			fixObj.Replacement = repl
		}
		if rngVal, ok := fixVal["range"].(map[string]interface{}); ok {
			fixObj.Range = parseRangeFromMap(rngVal)
		}
		finding.Fix = fixObj
	} else if replStr, ok := itemMap["fix"].(string); ok && replStr != "" {
		finding.Fix = &Fix{
			Replacement: replStr,
		}
	}

	// If node was passed directly: finding := node or finding.node := node
	if nodeVal, ok := itemMap["node"].(map[string]interface{}); ok {
		if finding.Code == "" {
			if text, ok := nodeVal["text"].(string); ok {
				finding.Code = text
			}
		}
		if finding.Range.Start.Line == 0 {
			if rangeMap, ok := nodeVal["range"].(map[string]interface{}); ok {
				finding.Range = parseRangeFromMap(rangeMap)
			}
		}
	}

	// If the entire item is an AST node
	if _, hasType := itemMap["type"]; hasType {
		if _, hasChildren := itemMap["children"]; hasChildren {
			if text, ok := itemMap["text"].(string); ok && finding.Code == "" {
				finding.Code = text
			}
			if rangeMap, ok := itemMap["range"].(map[string]interface{}); ok && finding.Range.Start.Line == 0 {
				finding.Range = parseRangeFromMap(rangeMap)
			}
		}
	}

	// Ensure Fix.Range defaults to finding.Range if empty
	if finding.Fix != nil && finding.Fix.Range.Start.Line == 0 && finding.Fix.Range.Start.Byte == 0 {
		finding.Fix.Range = finding.Range
	}

	return finding
}

func parseRangeFromMap(m map[string]interface{}) parser.Range {
	var r parser.Range
	if start, ok := m["start"].(map[string]interface{}); ok {
		r.Start.Line = intFromMap(start, "line")
		r.Start.Column = intFromMap(start, "column")
		r.Start.Byte = uint(intFromMap(start, "byte"))
	}
	if end, ok := m["end"].(map[string]interface{}); ok {
		r.End.Line = intFromMap(end, "line")
		r.End.Column = intFromMap(end, "column")
		r.End.Byte = uint(intFromMap(end, "byte"))
	}
	return r
}

func intFromMap(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case float64:
			return int(v)
		case float32:
			return int(v)
		case int:
			return v
		case int64:
			return int(v)
		case int32:
			return int(v)
		case uint:
			return int(v)
		case uint64:
			return int(v)
		case uint32:
			return int(v)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return int(i)
			}
		case string:
			var i int
			if _, err := fmt.Sscanf(v, "%d", &i); err == nil {
				return i
			}
		case fmt.Stringer:
			var i int
			if _, err := fmt.Sscanf(v.String(), "%d", &i); err == nil {
				return i
			}
		}
	}
	return 0
}
