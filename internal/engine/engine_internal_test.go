package engine

import (
	"encoding/json"
	"testing"

	"github.com/loganprice/treeguard/internal/parser"
)

type customStringer struct {
	val string
}

func (c customStringer) String() string {
	return c.val
}

func TestIntFromMapTableDriven(t *testing.T) {
	tests := []struct {
		name     string
		inputMap map[string]interface{}
		key      string
		want     int
	}{
		{"float64", map[string]interface{}{"line": float64(42)}, "line", 42},
		{"float32", map[string]interface{}{"line": float32(10)}, "line", 10},
		{"int", map[string]interface{}{"line": int(15)}, "line", 15},
		{"int64", map[string]interface{}{"line": int64(100)}, "line", 100},
		{"int32", map[string]interface{}{"line": int32(20)}, "line", 20},
		{"uint", map[string]interface{}{"line": uint(5)}, "line", 5},
		{"uint64", map[string]interface{}{"line": uint64(50)}, "line", 50},
		{"uint32", map[string]interface{}{"line": uint32(25)}, "line", 25},
		{"json.Number valid", map[string]interface{}{"line": json.Number("77")}, "line", 77},
		{"json.Number invalid", map[string]interface{}{"line": json.Number("invalid")}, "line", 0},
		{"string number", map[string]interface{}{"line": "88"}, "line", 88},
		{"string non-number", map[string]interface{}{"line": "abc"}, "line", 0},
		{"Stringer valid", map[string]interface{}{"line": customStringer{val: "99"}}, "line", 99},
		{"Stringer invalid", map[string]interface{}{"line": customStringer{val: "xyz"}}, "line", 0},
		{"missing key", map[string]interface{}{"other": 1}, "line", 0},
		{"nil value", map[string]interface{}{"line": nil}, "line", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intFromMap(tt.inputMap, tt.key)
			if got != tt.want {
				t.Errorf("intFromMap() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseRangeFromMapTableDriven(t *testing.T) {
	tests := []struct {
		name     string
		inputMap map[string]interface{}
		wantLine int
		wantCol  int
		wantByte uint
	}{
		{
			name: "Full range map",
			inputMap: map[string]interface{}{
				"start": map[string]interface{}{
					"line":   float64(5),
					"column": float64(10),
					"byte":   float64(120),
				},
				"end": map[string]interface{}{
					"line":   float64(5),
					"column": float64(20),
					"byte":   float64(130),
				},
			},
			wantLine: 5,
			wantCol:  10,
			wantByte: 120,
		},
		{
			name:     "Empty range map",
			inputMap: map[string]interface{}{},
			wantLine: 0,
			wantCol:  0,
			wantByte: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := parseRangeFromMap(tt.inputMap)
			if r.Start.Line != tt.wantLine {
				t.Errorf("Start.Line = %d, want %d", r.Start.Line, tt.wantLine)
			}
			if r.Start.Column != tt.wantCol {
				t.Errorf("Start.Column = %d, want %d", r.Start.Column, tt.wantCol)
			}
			if r.Start.Byte != tt.wantByte {
				t.Errorf("Start.Byte = %d, want %d", r.Start.Byte, tt.wantByte)
			}
		})
	}
}

func TestItemToFindingTableDriven(t *testing.T) {
	dummyParsed := &parser.ParsedFile{
		Input: parser.ScanInput{
			File: parser.FileContext{Path: "test.go"},
		},
	}

	tests := []struct {
		name       string
		item       interface{}
		meta       map[string]interface{}
		wantRuleID string
		wantSev    string
	}{
		{
			name:       "Nil item",
			item:       nil,
			meta:       nil,
			wantRuleID: "",
		},
		{
			name: "Item with map metadata",
			item: map[string]interface{}{
				"rule_id":  "map-id",
				"severity": "CRITICAL",
			},
			meta: map[string]interface{}{
				"id":       "meta-id",
				"title":    "Meta Title",
				"severity": "WARNING",
			},
			wantRuleID: "map-id",
			wantSev:    SeverityError,
		},
		{
			name: "Map item with AST node type",
			item: map[string]interface{}{
				"type":     "expression_statement",
				"children": []interface{}{},
				"text":     "foo()",
				"range": map[string]interface{}{
					"start": map[string]interface{}{"line": float64(1)},
				},
			},
			meta: map[string]interface{}{
				"id": "node-rule",
			},
			wantRuleID: "node-rule",
			wantSev:    SeverityWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := itemToFinding(tt.item, tt.meta, dummyParsed)
			if tt.item == nil {
				if f != nil {
					t.Errorf("expected nil finding for nil item")
				}
				return
			}
			if f.RuleID != tt.wantRuleID {
				t.Errorf("RuleID = %q, want %q", f.RuleID, tt.wantRuleID)
			}
			if f.Severity != tt.wantSev {
				t.Errorf("Severity = %q, want %q", f.Severity, tt.wantSev)
			}
		})
	}
}
