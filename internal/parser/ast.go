package parser

// Point represents a position in a source file (1-indexed for lines and columns).
type Point struct {
	Line   int  `json:"line"`   // 1-indexed line
	Column int  `json:"column"` // 1-indexed column
	Byte   uint `json:"byte"`   // 0-indexed byte offset
}

// Range represents a source code span.
type Range struct {
	Start Point `json:"start"`
	End   Point `json:"end"`
}

// FieldSummary provides quick access to a field's child node type and text.
type FieldSummary struct {
	ID   int    `json:"id"`
	Type string `json:"type"`
	Text string `json:"text"`
}

// ASTNode represents a single node in the flattened AST list.
type ASTNode struct {
	ID        int                     `json:"id"`
	ParentID  int                     `json:"parent_id"` // -1 for root
	Type      string                  `json:"type"`
	IsNamed   bool                    `json:"is_named"`
	Field     string                  `json:"field,omitempty"`
	Range     Range                   `json:"range"`
	Text      string                  `json:"text"`
	Ancestors []int                   `json:"ancestors,omitempty"` // Ancestor node IDs from parent to root
	Children  []int                   `json:"children,omitempty"`  // Child node IDs
	Fields    map[string]FieldSummary `json:"fields,omitempty"`    // Field name -> summary
	FieldIDs  map[string][]int        `json:"field_ids,omitempty"` // Field name -> all child IDs
}

// ASTTreeNode represents a hierarchical syntax tree node.
type ASTTreeNode struct {
	ID       int                      `json:"id"`
	Type     string                   `json:"type"`
	IsNamed  bool                     `json:"is_named"`
	Field    string                   `json:"field,omitempty"`
	Range    Range                    `json:"range"`
	Text     string                   `json:"text"`
	Fields   map[string]*FieldSummary `json:"fields,omitempty"`
	Children []*ASTTreeNode           `json:"children,omitempty"`
}

// FileContext contains metadata about the scanned source file.
type FileContext struct {
	Path       string   `json:"path"`
	Language   string   `json:"language"`
	LinesCount int      `json:"lines_count"`
	Lines      []string `json:"lines,omitempty"`
	Content    string   `json:"content,omitempty"`
}

// ScanInput is the complete data structure passed as `input` to OPA Rego rules.
type ScanInput struct {
	File  FileContext  `json:"file"`
	AST   *ASTTreeNode `json:"ast"`
	Nodes []ASTNode    `json:"nodes"`
}
