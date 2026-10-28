package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// ParsedFile represents a parsed source file and holds references to both
// the serialized ScanInput and the raw Tree-sitter tree.
type ParsedFile struct {
	Input ScanInput
	Tree  *tree_sitter.Tree
}

// Close frees any C resources associated with the parsed Tree-sitter tree.
func (p *ParsedFile) Close() {
	if p.Tree != nil {
		p.Tree.Close()
		p.Tree = nil
	}
}

// Parser parses source code files into AST data structures.
type Parser struct{}

// New creates a new Parser instance.
func New() *Parser {
	return &Parser{}
}

// ParseFile reads a file from disk and parses it into a ParsedFile.
func (p *Parser) ParseFile(filePath string) (*ParsedFile, error) {
	filePath = filepath.Clean(filePath)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file %s: %w", filePath, err)
	}

	lang, err := DetectLanguage(filePath)
	if err != nil {
		return nil, err
	}

	return p.ParseSource(filePath, content, lang)
}

// ParseSource parses source code bytes for a given language.
func (p *Parser) ParseSource(filePath string, source []byte, langName string) (*ParsedFile, error) {
	tsLang, err := GetLanguage(langName)
	if err != nil {
		return nil, err
	}

	tsParser := tree_sitter.NewParser()
	defer tsParser.Close()

	if err := tsParser.SetLanguage(tsLang); err != nil {
		return nil, fmt.Errorf("set tree-sitter language %s: %w", langName, err)
	}

	tree := tsParser.Parse(source, nil)
	if tree == nil {
		return nil, fmt.Errorf("failed to parse %s", filePath)
	}

	// Prepare lines for snippet display and context
	lines := splitLines(source)

	fileCtx := FileContext{
		Path:       filePath,
		Language:   langName,
		LinesCount: len(lines),
		Lines:      lines,
		Content:    string(source),
	}

	// Build the AST nodes and tree structure
	builder := newASTBuilder(source)
	rootNode := tree.RootNode()
	treeRoot, nodes := builder.build(rootNode)

	scanInput := ScanInput{
		File:  fileCtx,
		AST:   treeRoot,
		Nodes: nodes,
	}

	return &ParsedFile{
		Input: scanInput,
		Tree:  tree,
	}, nil
}

type astBuilder struct {
	source []byte
	nodes  []ASTNode
	nextID int
}

func newASTBuilder(source []byte) *astBuilder {
	return &astBuilder{
		source: source,
		nodes:  make([]ASTNode, 0, 128),
		nextID: 0,
	}
}

func (b *astBuilder) build(root *tree_sitter.Node) (*ASTTreeNode, []ASTNode) {
	if root == nil {
		return nil, b.nodes
	}

	treeRoot := b.traverse(root, -1, "", nil)
	return treeRoot, b.nodes
}

func (b *astBuilder) traverse(tsNode *tree_sitter.Node, parentID int, fieldName string, ancestors []int) *ASTTreeNode {
	nodeID := b.nextID
	b.nextID++

	startPos := tsNode.StartPosition()
	endPos := tsNode.EndPosition()

	nodeRange := Range{
		Start: Point{
			Line:   int(startPos.Row) + 1,
			Column: int(startPos.Column) + 1,
			Byte:   tsNode.StartByte(),
		},
		End: Point{
			Line:   int(endPos.Row) + 1,
			Column: int(endPos.Column) + 1,
			Byte:   tsNode.EndByte(),
		},
	}

	text := tsNode.Utf8Text(b.source)
	kind := tsNode.Kind()
	isNamed := tsNode.IsNamed()

	treeNode := &ASTTreeNode{
		ID:       nodeID,
		Type:     kind,
		IsNamed:  isNamed,
		Field:    fieldName,
		Range:    nodeRange,
		Text:     text,
		Fields:   make(map[string]*FieldSummary),
		Children: make([]*ASTTreeNode, 0, tsNode.ChildCount()),
	}

	astNode := ASTNode{
		ID:        nodeID,
		ParentID:  parentID,
		Type:      kind,
		IsNamed:   isNamed,
		Field:     fieldName,
		Range:     nodeRange,
		Text:      text,
		Ancestors: ancestors,
		Children:  make([]int, 0, tsNode.ChildCount()),
		Fields:    make(map[string]FieldSummary),
		FieldIDs:  make(map[string][]int),
	}

	// Placeholder to maintain index == nodeID
	b.nodes = append(b.nodes, astNode)

	childAncestors := make([]int, 0, len(ancestors)+1)
	childAncestors = append(childAncestors, nodeID)
	childAncestors = append(childAncestors, ancestors...)

	childCount := tsNode.ChildCount()
	for i := uint(0); i < childCount; i++ {
		child := tsNode.Child(i)
		if child == nil {
			continue
		}

		childField := tsNode.FieldNameForChild(uint32(i))

		// Recurse into child
		childTreeNode := b.traverse(child, nodeID, childField, childAncestors)
		treeNode.Children = append(treeNode.Children, childTreeNode)
		astNode.Children = append(astNode.Children, childTreeNode.ID)

		if childField != "" {
			summary := FieldSummary{
				ID:   childTreeNode.ID,
				Type: childTreeNode.Type,
				Text: childTreeNode.Text,
			}
			treeNode.Fields[childField] = &summary
			astNode.Fields[childField] = summary
			astNode.FieldIDs[childField] = append(astNode.FieldIDs[childField], childTreeNode.ID)
		}
	}

	// Update node in the flattened slice with final children & fields
	b.nodes[nodeID] = astNode

	return treeNode
}

func splitLines(content []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}
