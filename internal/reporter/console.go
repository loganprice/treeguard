package reporter

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"

	"github.com/loganprice/treeguard/internal/engine"
)

// ConsoleReporter formats findings as rich colorized terminal text with code snippets.
type ConsoleReporter struct {
	NoColor bool
}

// NewConsoleReporter creates a new ConsoleReporter.
func NewConsoleReporter(noColor bool) *ConsoleReporter {
	return &ConsoleReporter{NoColor: noColor}
}

// Render writes human-readable colorized findings to the given writer.
func (c *ConsoleReporter) Render(w io.Writer, findings []engine.Finding, stats ReportStats) error {
	if c.NoColor {
		color.NoColor = true
	}

	errorColor := color.New(color.FgRed, color.Bold)
	warnColor := color.New(color.FgYellow, color.Bold)
	infoColor := color.New(color.FgCyan, color.Bold)
	pathColor := color.New(color.Underline, color.Bold)
	dimColor := color.New(color.Faint)
	boldColor := color.New(color.Bold)

	if len(findings) == 0 {
		color.New(color.FgGreen, color.Bold).Fprintln(w, "✓ No security issues found.")
		if stats.SuppressedCount > 0 {
			dimColor.Fprintf(w, "Suppressed %d finding(s) via inline comments.\n", stats.SuppressedCount)
		}
		fmt.Fprintf(w, "\nScanned %d file(s) in %v.\n", stats.FilesScanned, stats.Duration.Round(100*1000))
		return nil
	}

	fmt.Fprintf(w, "\n")

	errorsCount := 0
	warnsCount := 0
	infosCount := 0

	for i, f := range findings {
		switch f.Severity {
		case engine.SeverityError:
			errorColor.Fprintf(w, " [ERROR] ")
			errorsCount++
		case engine.SeverityWarning:
			warnColor.Fprintf(w, " [WARNING] ")
			warnsCount++
		default:
			infoColor.Fprintf(w, " [INFO] ")
			infosCount++
		}

		boldColor.Fprintf(w, "%s\n", f.RuleID)
		pathColor.Fprintf(w, "  %s:%d:%d", f.File, f.Range.Start.Line, f.Range.Start.Column)
		fmt.Fprintln(w)

		if f.Message != "" {
			fmt.Fprintf(w, "  Message: %s\n", f.Message)
		}
		if f.CWE != "" {
			dimColor.Fprintf(w, "  CWE: %s", f.CWE)
			if f.OWASP != "" {
				dimColor.Fprintf(w, " | OWASP: %s", f.OWASP)
			}
			fmt.Fprintln(w)
		}

		if f.Fix != nil && f.Fix.Replacement != "" {
			fixColor := color.New(color.FgCyan, color.Bold)
			fixColor.Fprintf(w, "  🛠  Autofix available: %s\n", f.Fix.Replacement)
		}

		// Print code snippet
		snippet := renderSnippet(f.File, f.Range.Start.Line, f.Range.Start.Column, f.Range.End.Column)
		if snippet != "" {
			fmt.Fprintln(w, snippet)
		}

		if i < len(findings)-1 {
			fmt.Fprintln(w, strings.Repeat("─", 60))
		}
	}

	fmt.Fprintln(w, strings.Repeat("═", 60))
	summaryColor := errorColor
	if errorsCount == 0 && warnsCount > 0 {
		summaryColor = warnColor
	} else if errorsCount == 0 && warnsCount == 0 {
		summaryColor = color.New(color.FgGreen, color.Bold)
	}

	summaryColor.Fprintf(w, "Found %d issue(s): %d errors, %d warnings, %d infos.\n",
		len(findings), errorsCount, warnsCount, infosCount)
	if stats.SuppressedCount > 0 {
		dimColor.Fprintf(w, "Suppressed %d finding(s) via inline comments.\n", stats.SuppressedCount)
	}
	fmt.Fprintf(w, "Scanned %d file(s) in %v.\n\n", stats.FilesScanned, stats.Duration.Round(100*1000))

	return nil
}

func renderSnippet(filePath string, targetLine, startCol, endCol int) string {
	if filePath == "" || targetLine <= 0 {
		return ""
	}

	filePath = filepath.Clean(filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	currentLine := 0
	lines := make(map[int]string)

	contextBefore := 1
	contextAfter := 1
	startContext := targetLine - contextBefore
	if startContext < 1 {
		startContext = 1
	}
	endContext := targetLine + contextAfter

	for scanner.Scan() {
		currentLine++
		if currentLine >= startContext && currentLine <= endContext {
			lines[currentLine] = scanner.Text()
		}
		if currentLine > endContext {
			break
		}
	}

	if _, ok := lines[targetLine]; !ok {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")

	for lineNum := startContext; lineNum <= endContext; lineNum++ {
		lineText, exists := lines[lineNum]
		if !exists {
			continue
		}

		if lineNum == targetLine {
			fmt.Fprintf(&sb, "  > %4d | %s\n", lineNum, lineText)
			if startCol > 0 {
				colIndent := startCol - 1
				if colIndent < 0 {
					colIndent = 0
				}
				underlineLen := endCol - startCol
				if underlineLen <= 0 {
					underlineLen = 1
				}
				fmt.Fprintf(&sb, "    %4s | %s%s\n", "", strings.Repeat(" ", colIndent), strings.Repeat("^", underlineLen))
			}
		} else {
			fmt.Fprintf(&sb, "    %4d | %s\n", lineNum, lineText)
		}
	}

	return sb.String()
}
