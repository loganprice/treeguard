const vscode = require('vscode');
const { exec } = require('child_process');
const path = require('path');

let diagnosticCollection;
let statusBarItem;

function activate(context) {
    diagnosticCollection = vscode.languages.createDiagnosticCollection('treeguard');
    context.subscriptions.push(diagnosticCollection);

    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'workbench.action.problems.focus';
    statusBarItem.text = '$(shield) TreeGuard: Ready';
    statusBarItem.tooltip = 'Click to view TreeGuard security findings in Problems panel';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    let scanCmd = vscode.commands.registerCommand('treeguard.scan', runWorkspaceScan);
    let scanActiveCmd = vscode.commands.registerCommand('treeguard.scanActiveFile', runActiveFileScan);

    context.subscriptions.push(scanCmd);
    context.subscriptions.push(scanActiveCmd);

    vscode.workspace.onDidSaveTextDocument(doc => {
        const config = vscode.workspace.getConfiguration('treeguard');
        if (config.get('scanOnSave') && isSupportedLanguage(doc.languageId)) {
            runActiveFileScan();
        }
    });

    vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor && editor.document) {
            const config = vscode.workspace.getConfiguration('treeguard');
            if (config.get('scanOnOpen') && isSupportedLanguage(editor.document.languageId)) {
                runActiveFileScan();
            }
        }
    });
}

function isSupportedLanguage(langId) {
    const supported = ['python', 'go', 'javascript', 'typescript', 'c', 'cpp', 'rust', 'java'];
    return supported.includes(langId);
}

function runWorkspaceScan() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        vscode.window.showWarningMessage('TreeGuard: No open workspace folder found.');
        return;
    }
    const rootPath = workspaceFolders[0].uri.fsPath;
    executeScan(rootPath, rootPath);
}

function runActiveFileScan() {
    const editor = vscode.window.activeTextEditor;
    if (!editor || !editor.document) {
        return;
    }
    const filePath = editor.document.uri.fsPath;
    const workspaceFolders = vscode.workspace.workspaceFolders;
    const cwd = (workspaceFolders && workspaceFolders.length > 0) ? workspaceFolders[0].uri.fsPath : path.dirname(filePath);
    executeScan(filePath, cwd);
}

function executeScan(targetPath, cwd) {
    const config = vscode.workspace.getConfiguration('treeguard');
    const exePath = config.get('executablePath') || 'treeguard';
    const rulesPath = config.get('rulesPath');
    const minSeverity = config.get('severityThreshold') || 'INFO';

    statusBarItem.text = '$(sync~spin) TreeGuard: Scanning...';

    let cmdStr = `"${exePath}" scan --format json --severity ${minSeverity}`;
    if (rulesPath) {
        cmdStr += ` -r "${rulesPath}"`;
    }
    cmdStr += ` "${targetPath}"`;

    exec(cmdStr, { cwd: cwd }, (error, stdout, stderr) => {
        diagnosticCollection.clear();
        if (!stdout) {
            statusBarItem.text = '$(check) TreeGuard: Clean';
            return;
        }

        try {
            const data = JSON.parse(stdout);
            const findings = data.findings || [];
            const diagnosticsMap = new Map();

            findings.forEach(f => {
                const fileUri = vscode.Uri.file(f.file);
                const startLine = Math.max(0, (f.range?.start?.line || 1) - 1);
                const startCol = Math.max(0, (f.range?.start?.column || 1) - 1);
                const endLine = Math.max(startLine, (f.range?.end?.line || startLine + 1) - 1);
                const endCol = Math.max(startCol, f.range?.end?.column || startCol + 10);

                const range = new vscode.Range(startLine, startCol, endLine, endCol);
                let severity = vscode.DiagnosticSeverity.Warning;
                if (f.severity === 'ERROR') severity = vscode.DiagnosticSeverity.Error;
                if (f.severity === 'INFO') severity = vscode.DiagnosticSeverity.Information;

                const message = `[${f.rule_id}] ${f.message}`;
                const diag = new vscode.Diagnostic(range, message, severity);
                diag.source = 'TreeGuard';
                diag.code = f.rule_id;

                if (!diagnosticsMap.has(fileUri.toString())) {
                    diagnosticsMap.set(fileUri.toString(), []);
                }
                diagnosticsMap.get(fileUri.toString()).push(diag);
            });

            diagnosticsMap.forEach((diags, uriStr) => {
                diagnosticCollection.set(vscode.Uri.parse(uriStr), diags);
            });

            if (findings.length > 0) {
                statusBarItem.text = `$(alert) TreeGuard: ${findings.length} Issue(s)`;
            } else {
                statusBarItem.text = '$(check) TreeGuard: Clean';
            }
        } catch (e) {
            statusBarItem.text = '$(warning) TreeGuard: Scan Error';
            console.error('Failed to parse TreeGuard JSON output', e);
        }
    });
}

function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
        diagnosticCollection.dispose();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}

module.exports = {
    activate,
    deactivate
};
