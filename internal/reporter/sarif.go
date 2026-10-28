package reporter

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/loganprice/treeguard/internal/engine"
)

// SARIFReport represents OASIS SARIF v2.1.0.
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name,omitempty"`
	ShortDescription     SARIFMessage      `json:"shortDescription,omitempty"`
	DefaultConfiguration SARIFConfig       `json:"defaultConfiguration"`
	Properties           map[string]string `json:"properties,omitempty"`
}

type SARIFConfig struct {
	Level string `json:"level"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
	Fixes     []SARIFFix      `json:"fixes,omitempty"`
}

type SARIFFix struct {
	Description     SARIFMessage          `json:"description,omitempty"`
	ArtifactChanges []SARIFArtifactChange `json:"artifactChanges"`
}

type SARIFArtifactChange struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Replacements     []SARIFReplacement    `json:"replacements"`
}

type SARIFReplacement struct {
	DeletedRegion   SARIFRegion  `json:"deletedRegion"`
	InsertedContent SARIFMessage `json:"insertedContent"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int          `json:"startLine"`
	StartColumn int          `json:"startColumn,omitempty"`
	EndLine     int          `json:"endLine,omitempty"`
	EndColumn   int          `json:"endColumn,omitempty"`
	Snippet     SARIFMessage `json:"snippet,omitempty"`
}

// SARIFReporter formats scan findings as SARIF v2.1.0.
type SARIFReporter struct {
	Pretty bool
}

// NewSARIFReporter creates a new SARIFReporter.
func NewSARIFReporter(pretty bool) *SARIFReporter {
	return &SARIFReporter{Pretty: pretty}
}

// Render writes SARIF v2.1.0 output to the given writer.
func (s *SARIFReporter) Render(w io.Writer, findings []engine.Finding, stats ReportStats) error {
	rulesMap := make(map[string]SARIFRule)
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		sarifLevel := toSARIFLevel(f.Severity)

		if _, exists := rulesMap[f.RuleID]; !exists {
			ruleDesc := f.Title
			if ruleDesc == "" {
				ruleDesc = f.Message
			}
			ruleProps := make(map[string]string)
			if f.CWE != "" {
				ruleProps["cwe"] = f.CWE
			}
			if f.OWASP != "" {
				ruleProps["owasp"] = f.OWASP
			}

			rulesMap[f.RuleID] = SARIFRule{
				ID:   f.RuleID,
				Name: f.RuleID,
				ShortDescription: SARIFMessage{
					Text: ruleDesc,
				},
				DefaultConfiguration: SARIFConfig{
					Level: sarifLevel,
				},
				Properties: ruleProps,
			}
		}

		res := SARIFResult{
			RuleID: f.RuleID,
			Level:  sarifLevel,
			Message: SARIFMessage{
				Text: f.Message,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: f.File,
						},
						Region: SARIFRegion{
							StartLine:   f.Range.Start.Line,
							StartColumn: f.Range.Start.Column,
							EndLine:     f.Range.End.Line,
							EndColumn:   f.Range.End.Column,
							Snippet: SARIFMessage{
								Text: f.Code,
							},
						},
					},
				},
			},
		}

		if f.Fix != nil && f.Fix.Replacement != "" {
			res.Fixes = []SARIFFix{
				{
					Description: SARIFMessage{Text: "Automated remediation"},
					ArtifactChanges: []SARIFArtifactChange{
						{
							ArtifactLocation: SARIFArtifactLocation{URI: f.File},
							Replacements: []SARIFReplacement{
								{
									DeletedRegion: SARIFRegion{
										StartLine:   f.Fix.Range.Start.Line,
										StartColumn: f.Fix.Range.Start.Column,
										EndLine:     f.Fix.Range.End.Line,
										EndColumn:   f.Fix.Range.End.Column,
									},
									InsertedContent: SARIFMessage{Text: f.Fix.Replacement},
								},
							},
						},
					},
				},
			}
		}
		results = append(results, res)
	}

	rulesList := make([]SARIFRule, 0, len(rulesMap))
	for _, r := range rulesMap {
		rulesList = append(rulesList, r)
	}

	report := SARIFReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "TreeGuard",
						Version:        "1.0.0",
						InformationURI: "https://github.com/loganprice/treeguard",
						Rules:          rulesList,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	if s.Pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(report)
}

func toSARIFLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case engine.SeverityError:
		return "error"
	case engine.SeverityWarning:
		return "warning"
	default:
		return "note"
	}
}
