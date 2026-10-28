package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/loganprice/treeguard/internal/parser"
)

type activeContextKey struct{}

// ActiveContext holds the active parsed file and source information for a scan task.
type ActiveContext struct {
	ParsedFile *parser.ParsedFile
	Source     []byte
	Language   *tree_sitter.Language
	CallGraph  *ProjectCallGraph
}

// WithActiveContext attaches an ActiveContext to the context.Context.
func WithActiveContext(ctx context.Context, act *ActiveContext) context.Context {
	return context.WithValue(ctx, activeContextKey{}, act)
}

// GetActiveContext retrieves the ActiveContext from the context.Context.
func GetActiveContext(ctx context.Context) *ActiveContext {
	if val, ok := ctx.Value(activeContextKey{}).(*ActiveContext); ok {
		return val
	}
	return nil
}

func init() {
	// Register sast.ts_query(queryString) -> returns array of matches
	rego.RegisterBuiltin1(
		&rego.Function{
			Name: "sast.ts_query",
			Decl: types.NewFunction(types.Args(types.S), types.NewArray(nil, types.A)),
		},
		builtinTSQuery,
	)

	// Register sast.taint_flow(sourceNode, sinkNode, sanitizersList) -> returns object {has_flow: bool, ...}
	rego.RegisterBuiltin3(
		&rego.Function{
			Name: "sast.taint_flow",
			Decl: types.NewFunction(
				types.Args(types.A, types.A, types.NewArray(nil, types.A)),
				types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)),
			),
		},
		builtinTaintFlow,
	)
}

func builtinTSQuery(bctx rego.BuiltinContext, queryTerm *ast.Term) (*ast.Term, error) {
	queryStr, err := getStringFromTerm(queryTerm)
	if err != nil {
		return nil, fmt.Errorf("sast.ts_query argument: %w", err)
	}

	act := GetActiveContext(bctx.Context)
	if act == nil || act.ParsedFile == nil || act.ParsedFile.Tree == nil || act.Language == nil {
		return ast.NewTerm(ast.NewArray()), nil
	}

	tsQuery, qErr := tree_sitter.NewQuery(act.Language, queryStr)
	if qErr != nil {
		return nil, fmt.Errorf("compile tree-sitter query %q: %w", queryStr, qErr)
	}
	defer tsQuery.Close()

	cursor := tree_sitter.NewQueryCursor()
	defer cursor.Close()

	root := act.ParsedFile.Tree.RootNode()
	matchesIter := cursor.Matches(tsQuery, root, act.Source)

	var results []interface{}
	captureNames := tsQuery.CaptureNames()

	for {
		match := matchesIter.Next()
		if match == nil {
			break
		}

		capturesMap := make(map[string]interface{})
		for _, cap := range match.Captures {
			if int(cap.Index) < len(captureNames) {
				capName := captureNames[cap.Index]
				startPos := cap.Node.StartPosition()
				endPos := cap.Node.EndPosition()

				capturesMap[capName] = map[string]interface{}{
					"type": cap.Node.Kind(),
					"text": cap.Node.Utf8Text(act.Source),
					"range": map[string]interface{}{
						"start": map[string]interface{}{
							"line":   int(startPos.Row) + 1,
							"column": int(startPos.Column) + 1,
							"byte":   cap.Node.StartByte(),
						},
						"end": map[string]interface{}{
							"line":   int(endPos.Row) + 1,
							"column": int(endPos.Column) + 1,
							"byte":   cap.Node.EndByte(),
						},
					},
				}
			}
		}

		matchObj := map[string]interface{}{
			"pattern_index": match.PatternIndex,
			"captures":      capturesMap,
		}
		results = append(results, matchObj)
	}

	val, err := ast.InterfaceToValue(results)
	if err != nil {
		return nil, fmt.Errorf("convert query results to ast value: %w", err)
	}

	return ast.NewTerm(val), nil
}

func builtinTaintFlow(bctx rego.BuiltinContext, sourceTerm, sinkTerm, sanitizersTerm *ast.Term) (*ast.Term, error) {
	act := GetActiveContext(bctx.Context)
	if act == nil || act.ParsedFile == nil {
		return makeTaintFlowResult(false, nil), nil
	}

	sourceID := getNodeIDFromTerm(sourceTerm)
	sinkID := getNodeIDFromTerm(sinkTerm)
	if sourceID < 0 || sinkID < 0 || sourceID >= len(act.ParsedFile.Input.Nodes) || sinkID >= len(act.ParsedFile.Input.Nodes) {
		return makeTaintFlowResult(false, nil), nil
	}

	sanitizerIDs := make(map[int]struct{})
	if sanitizersTerm != nil {
		if arr, ok := sanitizersTerm.Value.(*ast.Array); ok {
			for i := 0; i < arr.Len(); i++ {
				sID := getNodeIDFromTerm(arr.Elem(i))
				if sID >= 0 {
					sanitizerIDs[sID] = struct{}{}
				}
			}
		}
	}

	nodes := act.ParsedFile.Input.Nodes
	sourceNode := nodes[sourceID]
	sinkNode := nodes[sinkID]

	// Find enclosing function/procedure scope
	procScopeID := findProcedureScopeID(nodes, sourceNode, sinkNode)

	// Perform inter-procedural taint flow analysis
	hasFlow, pathIDs := analyzeTaintFlow(nodes, procScopeID, sourceNode, sinkNode, sanitizerIDs, act.CallGraph, 0)

	return makeTaintFlowResult(hasFlow, pathIDs), nil
}

func getNodeIDFromTerm(term *ast.Term) int {
	if term == nil {
		return -1
	}
	if obj, ok := term.Value.(ast.Object); ok {
		if idTerm := obj.Get(ast.StringTerm("id")); idTerm != nil {
			if num, ok := idTerm.Value.(ast.Number); ok {
				if i, ok := num.Int64(); ok {
					return int(i)
				}
			}
		}
	}
	return -1
}

func findProcedureScopeID(nodes []parser.ASTNode, source, sink parser.ASTNode) int {
	isProcType := func(t string) bool {
		switch t {
		case "function_definition", "function_declaration", "method_declaration",
			"func_literal", "arrow_function", "method_definition", "constructor_declaration":
			return true
		default:
			return false
		}
	}

	sourceProc := -1
	for _, aID := range source.Ancestors {
		if aID >= 0 && aID < len(nodes) && isProcType(nodes[aID].Type) {
			sourceProc = aID
			break
		}
	}

	sinkProc := -1
	for _, aID := range sink.Ancestors {
		if aID >= 0 && aID < len(nodes) && isProcType(nodes[aID].Type) {
			sinkProc = aID
			break
		}
	}

	if sourceProc >= 0 && sourceProc == sinkProc {
		return sourceProc
	}
	if sourceProc >= 0 {
		return sourceProc
	}
	return sinkProc
}

func analyzeTaintFlow(
	nodes []parser.ASTNode,
	procScopeID int,
	source parser.ASTNode,
	sink parser.ASTNode,
	sanitizerIDs map[int]struct{},
	callGraph *ProjectCallGraph,
	depth int,
) (bool, []int) {

	if depth > 5 {
		return false, nil
	}

	// Initial taint tracking maps
	taintedVars := make(map[string]bool)
	taintedNodeIDs := make(map[int]bool)

	taintedNodeIDs[source.ID] = true

	// If source node is inside an assignment (e.g. user_data = req.args.get(...))
	if source.ParentID >= 0 && source.ParentID < len(nodes) {
		parent := nodes[source.ParentID]
		extractAssignedVars(nodes, parent, source.ID, taintedVars)
	}

	// Extract identifiers in source
	extractIdentifiers(nodes, source.ID, func(idName string) {
		taintedVars[idName] = true
	})

	pathIDs := []int{source.ID}

	// Process AST nodes within procedure scope
	for i := 0; i < len(nodes); i++ {
		node := nodes[i]

		if procScopeID >= 0 && node.ID != procScopeID && !hasAncestorID(node, procScopeID) {
			continue
		}

		// Process assignments
		if isAssignmentNode(node.Type) {
			processAssignment(nodes, node, taintedVars, taintedNodeIDs, sanitizerIDs)
		}

		// Inter-procedural parameter propagation: check function calls
		if isCallNode(node.Type) && callGraph != nil {
			calleeName := extractCalleeName(nodes, node)
			if calleeName != "" {
				targetSyms := callGraph.FindFunctions(calleeName)
				for _, sym := range targetSyms {
					argIDs := extractCallArgIDs(nodes, node)
					for argIdx, argID := range argIDs {
						argIsTainted := false
						extractIdentifiers(nodes, argID, func(varName string) {
							if taintedVars[varName] {
								argIsTainted = true
							}
						})
						if taintedNodeIDs[argID] || isChildTainted(nodes, argID, taintedNodeIDs) {
							argIsTainted = true
						}

						if argIsTainted && argIdx < len(sym.ParamNames) {
							paramName := sym.ParamNames[argIdx]
							syntheticSource := parser.ASTNode{
								ID:       sym.NodeID,
								Type:     "identifier",
								Text:     paramName,
								Range:    sym.File.Input.Nodes[sym.NodeID].Range,
								ParentID: sym.NodeID,
							}
							subFlow, subPath := analyzeTaintFlow(sym.File.Input.Nodes, sym.NodeID, syntheticSource, sink, sanitizerIDs, callGraph, depth+1)
							if subFlow {
								pathIDs = append(pathIDs, node.ID)
								pathIDs = append(pathIDs, subPath...)
								return true, pathIDs
							}
						}
					}
				}
			}
		}

		// Check if sink node is reached with tainted data
		if isSinkNodeOrCallee(nodes, node, sink, depth) {
			sinkIsTainted := false
			extractIdentifiers(nodes, node.ID, func(varName string) {
				if taintedVars[varName] {
					sinkIsTainted = true
				}
			})
			if taintedNodeIDs[node.ID] || isChildTainted(nodes, node.ID, taintedNodeIDs) {
				sinkIsTainted = true
			}

			if sinkIsTainted {
				pathIDs = append(pathIDs, node.ID)
				return true, pathIDs
			}
		}
	}

	return false, nil
}

func isSinkNodeOrCallee(nodes []parser.ASTNode, node parser.ASTNode, sink parser.ASTNode, depth int) bool {
	if node.ID == sink.ID {
		return true
	}
	if depth > 0 && isCallNode(node.Type) {
		callee := extractCalleeName(nodes, node)
		if isSinkCallee(callee) {
			return true
		}
	}
	return false
}

func isSinkCallee(name string) bool {
	switch name {
	case "execute", "cursor.execute", "db.execute", "engine.execute",
		"eval", "exec", "os.system", "subprocess.run", "popen", "QueryContext":
		return true
	default:
		return strings.HasSuffix(name, ".execute") || strings.HasSuffix(name, ".Query") || strings.HasSuffix(name, ".QueryContext")
	}
}

func extractAssignedVars(nodes []parser.ASTNode, parent parser.ASTNode, sourceID int, taintedVars map[string]bool) {
	if isAssignmentNode(parent.Type) {
		lhsVars := getLHSVars(nodes, parent)
		for _, v := range lhsVars {
			taintedVars[v] = true
		}
	}
}

func getLHSVars(nodes []parser.ASTNode, assignNode parser.ASTNode) []string {
	var vars []string
	if leftSummary, hasLeft := assignNode.Fields["left"]; hasLeft {
		extractIdentifiers(nodes, leftSummary.ID, func(name string) {
			vars = append(vars, name)
		})
	} else if nameSummary, hasName := assignNode.Fields["name"]; hasName {
		extractIdentifiers(nodes, nameSummary.ID, func(name string) {
			vars = append(vars, name)
		})
	} else if len(assignNode.Children) > 0 {
		// First child is LHS
		extractIdentifiers(nodes, assignNode.Children[0], func(name string) {
			vars = append(vars, name)
		})
	}
	return vars
}

func getRHSNodeIDs(assignNode parser.ASTNode) []int {
	var rhsIDs []int
	if rightSummary, hasRight := assignNode.Fields["right"]; hasRight {
		rhsIDs = append(rhsIDs, rightSummary.ID)
	} else if valSummary, hasVal := assignNode.Fields["value"]; hasVal {
		rhsIDs = append(rhsIDs, valSummary.ID)
	} else if len(assignNode.Children) > 1 {
		// All children after child 0
		rhsIDs = append(rhsIDs, assignNode.Children[1:]...)
	}
	return rhsIDs
}

func hasAncestorID(node parser.ASTNode, ancestorID int) bool {
	for _, a := range node.Ancestors {
		if a == ancestorID {
			return true
		}
	}
	return false
}

func isSanitizerSubtree(nodes []parser.ASTNode, nodeID int, sanitizerIDs map[int]struct{}) bool {
	if _, isSan := sanitizerIDs[nodeID]; isSan {
		return true
	}
	if nodeID >= 0 && nodeID < len(nodes) {
		for _, a := range nodes[nodeID].Ancestors {
			if _, isSan := sanitizerIDs[a]; isSan {
				return true
			}
		}
		for _, cid := range nodes[nodeID].Children {
			if isSanitizerSubtree(nodes, cid, sanitizerIDs) {
				return true
			}
		}
	}
	return false
}

func isAssignmentNode(nodeType string) bool {
	switch nodeType {
	case "assignment", "assignment_expression", "short_var_declaration",
		"variable_declarator", "variable_declaration", "lexical_declaration":
		return true
	default:
		return false
	}
}

func processAssignment(
	nodes []parser.ASTNode,
	assignNode parser.ASTNode,
	taintedVars map[string]bool,
	taintedNodeIDs map[int]bool,
	sanitizerIDs map[int]struct{},
) {
	lhsVars := getLHSVars(nodes, assignNode)
	rhsIDs := getRHSNodeIDs(assignNode)

	// Check if RHS contains a sanitizer
	rhsHasSanitizer := false
	for _, rhsID := range rhsIDs {
		if isSanitizerSubtree(nodes, rhsID, sanitizerIDs) {
			rhsHasSanitizer = true
			break
		}
	}

	if rhsHasSanitizer {
		// Untaint LHS variables
		for _, v := range lhsVars {
			taintedVars[v] = false
		}
		return
	}

	// Check if RHS contains tainted variables or node IDs
	rhsTainted := false
	for _, rhsID := range rhsIDs {
		extractIdentifiers(nodes, rhsID, func(varName string) {
			if taintedVars[varName] {
				rhsTainted = true
			}
		})
		if taintedNodeIDs[rhsID] || isChildTainted(nodes, rhsID, taintedNodeIDs) {
			rhsTainted = true
		}
	}

	if rhsTainted {
		for _, v := range lhsVars {
			taintedVars[v] = true
		}
	}
}

func extractIdentifiers(nodes []parser.ASTNode, rootID int, fn func(name string)) {
	if rootID < 0 || rootID >= len(nodes) {
		return
	}
	root := nodes[rootID]
	if root.Type == "identifier" || root.Type == "field_identifier" || root.Type == "property_identifier" {
		fn(root.Text)
	}

	for _, cid := range root.Children {
		extractIdentifiers(nodes, cid, fn)
	}
}

func isChildTainted(nodes []parser.ASTNode, rootID int, taintedNodeIDs map[int]bool) bool {
	if rootID < 0 || rootID >= len(nodes) {
		return false
	}
	if taintedNodeIDs[rootID] {
		return true
	}
	for _, cid := range nodes[rootID].Children {
		if isChildTainted(nodes, cid, taintedNodeIDs) {
			return true
		}
	}
	return false
}

func makeTaintFlowResult(hasFlow bool, pathIDs []int) *ast.Term {
	val, _ := ast.InterfaceToValue(map[string]interface{}{
		"has_flow": hasFlow,
		"path_ids": pathIDs,
	})
	return ast.NewTerm(val)
}

func getStringFromTerm(term *ast.Term) (string, error) {
	if term == nil {
		return "", fmt.Errorf("term is nil")
	}
	strVal, ok := term.Value.(ast.String)
	if !ok {
		return "", fmt.Errorf("expected string, got %T", term.Value)
	}
	return string(strVal), nil
}

func isCallNode(nodeType string) bool {
	switch nodeType {
	case "call", "call_expression", "method_invocation", "function_call_expression",
		"scoped_call_expression", "member_call_expression", "method_call":
		return true
	default:
		return false
	}
}

func extractCalleeName(nodes []parser.ASTNode, callNode parser.ASTNode) string {
	if funcSummary, hasFunc := callNode.Fields["function"]; hasFunc {
		return funcSummary.Text
	}
	if nameSummary, hasName := callNode.Fields["name"]; hasName {
		return nameSummary.Text
	}
	if methodSummary, hasMethod := callNode.Fields["method"]; hasMethod {
		return methodSummary.Text
	}
	return ""
}

func extractCallArgIDs(nodes []parser.ASTNode, callNode parser.ASTNode) []int {
	var argIDs []int
	var argsNodeID = -1
	if argsSummary, hasArgs := callNode.Fields["arguments"]; hasArgs {
		argsNodeID = argsSummary.ID
	}

	if argsNodeID < 0 {
		for _, cid := range callNode.Children {
			if cid >= 0 && cid < len(nodes) {
				t := nodes[cid].Type
				if t == "argument_list" || t == "arguments" || t == "parenthesized_expression" {
					argsNodeID = cid
					break
				}
			}
		}
	}

	if argsNodeID >= 0 && argsNodeID < len(nodes) {
		argsNode := nodes[argsNodeID]
		for _, cid := range argsNode.Children {
			if cid >= 0 && cid < len(nodes) && nodes[cid].IsNamed {
				argIDs = append(argIDs, cid)
			}
		}
	} else if len(callNode.Children) > 1 {
		for _, cid := range callNode.Children[1:] {
			if cid >= 0 && cid < len(nodes) && nodes[cid].IsNamed {
				argIDs = append(argIDs, cid)
			}
		}
	}

	return argIDs
}
