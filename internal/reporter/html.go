package reporter

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/loganprice/treeguard/internal/engine"
)

// HTMLReporter renders findings as an interactive standalone HTML security report.
type HTMLReporter struct{}

// NewHTMLReporter creates a new HTMLReporter instance.
func NewHTMLReporter() *HTMLReporter {
	return &HTMLReporter{}
}

type HTMLFindingSnippet struct {
	LineNum  int    `json:"line_num"`
	Text     string `json:"text"`
	IsTarget bool   `json:"is_target"`
}

type HTMLFindingItem struct {
	engine.Finding
	Snippets []HTMLFindingSnippet `json:"snippets,omitempty"`
}

type HTMLReportPayload struct {
	Title        string            `json:"title"`
	GeneratedAt  string            `json:"generated_at"`
	Stats        ReportStats       `json:"stats"`
	Findings     []HTMLFindingItem `json:"findings"`
	SeverityDist map[string]int    `json:"severity_dist"`
}

func (h *HTMLReporter) Render(w io.Writer, findings []engine.Finding, stats ReportStats) error {
	if stats.DurationMs == 0 && stats.Duration > 0 {
		stats.DurationMs = stats.Duration.Milliseconds()
	}

	dist := map[string]int{
		"ERROR":   0,
		"WARNING": 0,
		"INFO":    0,
	}

	items := make([]HTMLFindingItem, 0, len(findings))
	for _, f := range findings {
		sev := engine.NormalizeSeverity(f.Severity)
		dist[sev]++

		snips := extractHTMLSnippets(f.File, f.Range.Start.Line)
		items = append(items, HTMLFindingItem{
			Finding:  f,
			Snippets: snips,
		})
	}

	payload := HTMLReportPayload{
		Title:        "TreeGuard SAST Security Report",
		GeneratedAt:  time.Now().Format("2006-01-02 15:04:05 MST"),
		Stats:        stats,
		Findings:     items,
		SeverityDist: dist,
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal report payload: %w", err)
	}

	htmlContent := strings.Replace(htmlReportTemplate, "/* __REPORT_DATA_PLACEHOLDER__ */", string(jsonBytes), 1)
	_, err = w.Write([]byte(htmlContent))
	return err
}

func extractHTMLSnippets(filePath string, targetLine int) []HTMLFindingSnippet {
	if filePath == "" || targetLine <= 0 {
		return nil
	}

	filePath = filepath.Clean(filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	currentLine := 0
	startContext := targetLine - 2
	if startContext < 1 {
		startContext = 1
	}
	endContext := targetLine + 2

	var snips []HTMLFindingSnippet
	for scanner.Scan() {
		currentLine++
		if currentLine >= startContext && currentLine <= endContext {
			snips = append(snips, HTMLFindingSnippet{
				LineNum:  currentLine,
				Text:     scanner.Text(),
				IsTarget: currentLine == targetLine,
			})
		}
		if currentLine > endContext {
			break
		}
	}
	return snips
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TreeGuard SAST Security Report</title>
  <style>
    :root {
      --bg-main: #0b0f19;
      --bg-card: #161f30;
      --bg-card-hover: #1c283e;
      --border-color: #25334c;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --accent-blue: #38bdf8;
      --severity-error: #f43f5e;
      --severity-warning: #fbbf24;
      --severity-info: #38bdf8;
      --severity-success: #34d399;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-main);
      color: var(--text-main);
      line-height: 1.5;
      padding: 24px;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border-color);
      margin-bottom: 24px;
    }

    .logo-group {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .logo-icon {
      font-size: 28px;
    }

    h1 {
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.5px;
    }

    .meta-badge {
      font-size: 13px;
      color: var(--text-muted);
      background: var(--bg-card);
      padding: 6px 12px;
      border-radius: 6px;
      border: 1px solid var(--border-color);
    }

    /* KPI Cards */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }

    .kpi-card {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px 20px;
    }

    .kpi-card .title {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      margin-bottom: 8px;
    }

    .kpi-card .value {
      font-size: 28px;
      font-weight: 700;
    }

    .kpi-card.error .value { color: var(--severity-error); }
    .kpi-card.warning .value { color: var(--severity-warning); }
    .kpi-card.info .value { color: var(--severity-info); }
    .kpi-card.total .value { color: var(--text-main); }

    /* Controls & Filters */
    .controls-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
    }

    .filter-group {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    .search-input {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 14px;
      width: 280px;
      outline: none;
    }

    .search-input:focus {
      border-color: var(--accent-blue);
    }

    .btn {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      padding: 8px 14px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .btn:hover {
      background-color: var(--bg-card-hover);
      color: var(--text-main);
    }

    .btn.active {
      background-color: var(--accent-blue);
      color: #000;
      border-color: var(--accent-blue);
    }

    .btn.btn-error.active { background-color: var(--severity-error); color: #fff; border-color: var(--severity-error); }
    .btn.btn-warning.active { background-color: var(--severity-warning); color: #000; border-color: var(--severity-warning); }
    .btn.btn-info.active { background-color: var(--severity-info); color: #000; border-color: var(--severity-info); }

    /* Findings List */
    .findings-container {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .finding-card {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow: hidden;
      transition: border-color 0.15s ease;
    }

    .finding-card:hover {
      border-color: #3b4d6c;
    }

    .finding-card.severity-ERROR { border-left: 4px solid var(--severity-error); }
    .finding-card.severity-WARNING { border-left: 4px solid var(--severity-warning); }
    .finding-card.severity-INFO { border-left: 4px solid var(--severity-info); }

    .finding-header {
      padding: 14px 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      user-select: none;
    }

    .finding-title-group {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .badge {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
    }

    .badge-ERROR { background-color: rgba(244, 63, 94, 0.15); color: var(--severity-error); border: 1px solid rgba(244, 63, 94, 0.3); }
    .badge-WARNING { background-color: rgba(251, 191, 36, 0.15); color: var(--severity-warning); border: 1px solid rgba(251, 191, 36, 0.3); }
    .badge-INFO { background-color: rgba(56, 189, 248, 0.15); color: var(--severity-info); border: 1px solid rgba(56, 189, 248, 0.3); }

    .rule-id {
      font-weight: 700;
      font-size: 14px;
      color: var(--text-main);
    }

    .file-location {
      font-family: monospace;
      font-size: 13px;
      color: var(--text-muted);
    }

    .finding-body {
      padding: 16px 18px;
      border-top: 1px solid var(--border-color);
      background-color: rgba(11, 15, 25, 0.4);
    }

    .message {
      font-size: 14px;
      margin-bottom: 12px;
      color: var(--text-main);
    }

    .meta-tags {
      display: flex;
      gap: 8px;
      margin-bottom: 12px;
    }

    .meta-tag {
      font-size: 11px;
      font-family: monospace;
      background-color: #0f172a;
      border: 1px solid var(--border-color);
      color: var(--accent-blue);
      padding: 2px 6px;
      border-radius: 4px;
    }

    .snippet-box {
      background-color: #080c14;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      overflow-x: auto;
    }

    .snippet-line {
      display: flex;
      padding: 2px 0;
    }

    .snippet-line.target {
      background-color: rgba(244, 63, 94, 0.12);
      border-left: 3px solid var(--severity-error);
    }

    .line-num {
      width: 40px;
      color: var(--text-muted);
      text-align: right;
      padding-right: 12px;
      user-select: none;
    }

    .line-text {
      color: #e2e8f0;
      white-space: pre;
    }

    .autofix-box {
      margin-top: 12px;
      background-color: rgba(52, 211, 153, 0.1);
      border: 1px solid rgba(52, 211, 153, 0.3);
      border-radius: 6px;
      padding: 10px 14px;
      font-size: 13px;
      color: var(--severity-success);
    }

    .empty-state {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 40px;
      text-align: center;
    }

    .empty-state h3 {
      color: var(--severity-success);
      font-size: 20px;
      margin-bottom: 8px;
    }

    .hidden { display: none !important; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-group">
        <span class="logo-icon">🛡️</span>
        <div>
          <h1>TreeGuard SAST Report</h1>
          <div style="font-size: 12px; color: var(--text-muted);" id="genAt"></div>
        </div>
      </div>
      <div class="meta-badge" id="statsSummary"></div>
    </header>

    <div class="kpi-grid">
      <div class="kpi-card total">
        <div class="title">Total Findings</div>
        <div class="value" id="kpiTotal">0</div>
      </div>
      <div class="kpi-card error">
        <div class="title">Errors</div>
        <div class="value" id="kpiError">0</div>
      </div>
      <div class="kpi-card warning">
        <div class="title">Warnings</div>
        <div class="value" id="kpiWarning">0</div>
      </div>
      <div class="kpi-card info">
        <div class="title">Info</div>
        <div class="value" id="kpiInfo">0</div>
      </div>
    </div>

    <div class="controls-bar">
      <input type="text" id="searchInput" class="search-input" placeholder="Search rule ID, path, CWE..." oninput="filterFindings()">
      <div class="filter-group">
        <button class="btn active" id="btnAll" onclick="setSeverityFilter('ALL')">All</button>
        <button class="btn btn-error" id="btnERROR" onclick="setSeverityFilter('ERROR')">Errors</button>
        <button class="btn btn-warning" id="btnWARNING" onclick="setSeverityFilter('WARNING')">Warnings</button>
        <button class="btn btn-info" id="btnINFO" onclick="setSeverityFilter('INFO')">Info</button>
      </div>
    </div>

    <div class="findings-container" id="findingsList"></div>
    <div class="empty-state hidden" id="emptyState">
      <h3>✓ No Security Issues Found</h3>
      <p style="color: var(--text-muted);">TreeGuard static analysis completed cleanly with zero findings.</p>
    </div>
  </div>

  <script>
    const reportData = /* __REPORT_DATA_PLACEHOLDER__ */;

    let currentSeverity = 'ALL';

    function init() {
      document.getElementById('genAt').innerText = 'Generated: ' + reportData.generated_at;
      document.getElementById('statsSummary').innerText = 
        'Scanned ' + reportData.stats.files_scanned + ' files | ' + 
        reportData.stats.rules_count + ' rules | ' + 
        reportData.stats.duration_ms + 'ms';

      document.getElementById('kpiTotal').innerText = reportData.findings.length;
      document.getElementById('kpiError').innerText = reportData.severity_dist.ERROR || 0;
      document.getElementById('kpiWarning').innerText = reportData.severity_dist.WARNING || 0;
      document.getElementById('kpiInfo').innerText = reportData.severity_dist.INFO || 0;

      renderFindings(reportData.findings);
    }

    function setSeverityFilter(sev) {
      currentSeverity = sev;
      ['btnAll', 'btnERROR', 'btnWARNING', 'btnINFO'].forEach(id => {
        document.getElementById(id).classList.remove('active');
      });
      if (sev === 'ALL') document.getElementById('btnAll').classList.add('active');
      else document.getElementById('btn' + sev).classList.add('active');

      filterFindings();
    }

    function filterFindings() {
      const query = document.getElementById('searchInput').value.toLowerCase();
      const filtered = reportData.findings.filter(f => {
        const matchesSev = (currentSeverity === 'ALL' || f.severity.toUpperCase() === currentSeverity);
        const matchesQuery = !query || 
          f.rule_id.toLowerCase().includes(query) ||
          f.file.toLowerCase().includes(query) ||
          (f.message && f.message.toLowerCase().includes(query)) ||
          (f.cwe && f.cwe.toLowerCase().includes(query)) ||
          (f.owasp && f.owasp.toLowerCase().includes(query));
        return matchesSev && matchesQuery;
      });

      renderFindings(filtered);
    }

    function renderFindings(findings) {
      const container = document.getElementById('findingsList');
      const emptyState = document.getElementById('emptyState');
      container.innerHTML = '';

      if (findings.length === 0) {
        emptyState.classList.remove('hidden');
        return;
      }
      emptyState.classList.add('hidden');

      findings.forEach((f, index) => {
        const card = document.createElement('div');
        card.className = 'finding-card severity-' + f.severity.toUpperCase();

        let snippetsHTML = '';
        if (f.snippets && f.snippets.length > 0) {
          snippetsHTML = '<div class="snippet-box">' + 
            f.snippets.map(s => 
              '<div class="snippet-line ' + (s.is_target ? 'target' : '') + '">' +
                '<div class="line-num">' + s.line_num + '</div>' +
                '<div class="line-text">' + escapeHTML(s.text) + '</div>' +
              '</div>'
            ).join('') +
            '</div>';
        }

        let autofixHTML = '';
        if (f.fix && f.fix.replacement) {
          autofixHTML = '<div class="autofix-box">🛠 Autofix Suggestion: <code>' + escapeHTML(f.fix.replacement) + '</code></div>';
        }

        let tagsHTML = '';
        if (f.cwe) tagsHTML += '<span class="meta-tag">' + escapeHTML(f.cwe) + '</span>';
        if (f.owasp) tagsHTML += '<span class="meta-tag">' + escapeHTML(f.owasp) + '</span>';

        let linePos = f.range && f.range.start ? (':' + f.range.start.line + ':' + f.range.start.column) : '';

        card.innerHTML = 
          '<div class="finding-header" onclick="toggleCard(' + index + ')">' +
            '<div class="finding-title-group">' +
              '<span class="badge badge-' + f.severity.toUpperCase() + '">' + f.severity + '</span>' +
              '<span class="rule-id">' + escapeHTML(f.rule_id) + '</span>' +
            '</div>' +
            '<div class="file-location">' + escapeHTML(f.file) + linePos + '</div>' +
          '</div>' +
          '<div class="finding-body" id="body-' + index + '">' +
            '<div class="message">' + escapeHTML(f.message) + '</div>' +
            (tagsHTML ? '<div class="meta-tags">' + tagsHTML + '</div>' : '') +
            snippetsHTML +
            autofixHTML +
          '</div>';
        container.appendChild(card);
      });
    }

    function toggleCard(index) {
      const body = document.getElementById('body-' + index);
      body.classList.toggle('hidden');
    }

    function escapeHTML(str) {
      if (!str) return '';
      return str.replace(/[&<>"']/g, function(m) {
        return {
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#039;'
        }[m];
      });
    }

    window.onload = init;
  </script>
</body>
</html>
`
