package engine

import (
	"path/filepath"
	"strings"
	"sync"

	"github.com/loganprice/treeguard/internal/parser"
)

// FunctionSymbol represents a function or method definition indexed across project files.
type FunctionSymbol struct {
	Name       string
	FilePath   string
	NodeID     int
	ParamNames []string
	ParamIDs   []int
	ReturnIDs  []int
	File       *parser.ParsedFile
}

// ProjectCallGraph maintains an index of function symbols and file ASTs across a codebase.
type ProjectCallGraph struct {
	mu              sync.RWMutex
	FunctionsByName map[string][]*FunctionSymbol
	FilesByPath     map[string]*parser.ParsedFile
}

// NewProjectCallGraph creates an empty ProjectCallGraph.
func NewProjectCallGraph() *ProjectCallGraph {
	return &ProjectCallGraph{
		FunctionsByName: make(map[string][]*FunctionSymbol),
		FilesByPath:     make(map[string]*parser.ParsedFile),
	}
}

// IndexFile parses and indexes all function symbols in a ParsedFile into the call graph.
func (cg *ProjectCallGraph) IndexFile(pf *parser.ParsedFile) {
	if pf == nil {
		return
	}

	cg.mu.Lock()
	defer cg.mu.Unlock()

	cg.FilesByPath[pf.Input.File.Path] = pf

	for i := 0; i < len(pf.Input.Nodes); i++ {
		node := pf.Input.Nodes[i]
		if !isFunctionDefType(node.Type) {
			continue
		}

		funcName := extractFuncName(pf.Input.Nodes, node)
		if funcName == "" {
			continue
		}

		params, paramIDs := extractFuncParams(pf.Input.Nodes, node)
		returnIDs := extractReturnNodeIDs(pf.Input.Nodes, node.ID)

		sym := &FunctionSymbol{
			Name:       funcName,
			FilePath:   pf.Input.File.Path,
			NodeID:     node.ID,
			ParamNames: params,
			ParamIDs:   paramIDs,
			ReturnIDs:  returnIDs,
			File:       pf,
		}

		cg.FunctionsByName[funcName] = append(cg.FunctionsByName[funcName], sym)

		// Also index basename/short name if funcName contains package/module qualifier
		if idx := strings.LastIndex(funcName, "."); idx >= 0 && idx < len(funcName)-1 {
			shortName := funcName[idx+1:]
			if shortName != funcName {
				cg.FunctionsByName[shortName] = append(cg.FunctionsByName[shortName], sym)
			}
		}
	}
}

// FindFunctions retrieves indexed function symbols matching funcName.
func (cg *ProjectCallGraph) FindFunctions(funcName string) []*FunctionSymbol {
	cg.mu.RLock()
	defer cg.mu.RUnlock()

	if syms, ok := cg.FunctionsByName[funcName]; ok {
		return syms
	}

	// Fallback: check base name match
	base := filepath.Base(funcName)
	if syms, ok := cg.FunctionsByName[base]; ok {
		return syms
	}

	return nil
}

func isFunctionDefType(nodeType string) bool {
	switch nodeType {
	case "function_definition", "function_declaration", "method_declaration",
		"method_definition", "func_literal", "arrow_function":
		return true
	default:
		return false
	}
}

func extractFuncName(nodes []parser.ASTNode, funcNode parser.ASTNode) string {
	if nameSummary, hasName := funcNode.Fields["name"]; hasName {
		return nameSummary.Text
	}
	if declaratorSummary, hasDecl := funcNode.Fields["declarator"]; hasDecl {
		// C/C++ function declarator
		declNode := nodes[declaratorSummary.ID]
		if declNode.Type == "function_declarator" {
			if nameSummary, hasName := declNode.Fields["declarator"]; hasName {
				return nameSummary.Text
			}
		}
		return declaratorSummary.Text
	}
	return ""
}

func extractFuncParams(nodes []parser.ASTNode, funcNode parser.ASTNode) ([]string, []int) {
	var paramNames []string
	var paramIDs []int

	var paramsNodeID = -1
	if paramsSummary, hasParams := funcNode.Fields["parameters"]; hasParams {
		paramsNodeID = paramsSummary.ID
	}

	if paramsNodeID < 0 {
		for _, cid := range funcNode.Children {
			if cid >= 0 && cid < len(nodes) {
				t := nodes[cid].Type
				if t == "parameters" || t == "parameter_list" || t == "formal_parameters" {
					paramsNodeID = cid
					break
				}
			}
		}
	}

	if paramsNodeID >= 0 && paramsNodeID < len(nodes) {
		pNode := nodes[paramsNodeID]
		for _, cid := range pNode.Children {
			if cid >= 0 && cid < len(nodes) {
				child := nodes[cid]
				if child.IsNamed {
					// Extract parameter identifier
					paramName := ""
					extractIdentifiers(nodes, child.ID, func(name string) {
						if paramName == "" {
							paramName = name
						}
					})
					if paramName != "" {
						paramNames = append(paramNames, paramName)
						paramIDs = append(paramIDs, child.ID)
					}
				}
			}
		}
	}

	return paramNames, paramIDs
}

func extractReturnNodeIDs(nodes []parser.ASTNode, funcNodeID int) []int {
	var returns []int
	if funcNodeID < 0 || funcNodeID >= len(nodes) {
		return returns
	}

	var traverse func(id int)
	traverse = func(id int) {
		if id < 0 || id >= len(nodes) {
			return
		}
		n := nodes[id]
		if n.Type == "return_statement" || n.Type == "return" {
			returns = append(returns, n.ID)
			return
		}
		// Do not enter nested functions
		if n.ID != funcNodeID && isFunctionDefType(n.Type) {
			return
		}
		for _, cid := range n.Children {
			traverse(cid)
		}
	}

	traverse(funcNodeID)
	return returns
}
