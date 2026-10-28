package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestFindConfig(t *testing.T) {
	tests := []struct {
		name       string
		setupFiles map[string]string
		targetDir  string
		wantPath   string
		wantFound  bool
	}{
		{
			name: "find .treeguard.yaml in root",
			setupFiles: map[string]string{
				".treeguard.yaml": "rules: [rules]",
			},
			targetDir: "",
			wantPath:  ".treeguard.yaml",
			wantFound: true,
		},
		{
			name: "find .treeguard.yml in targetDir",
			setupFiles: map[string]string{
				"sub/.treeguard.yml": "format: json",
			},
			targetDir: "sub",
			wantPath:  filepath.Join("sub", ".treeguard.yml"),
			wantFound: true,
		},
		{
			name:       "no config file found",
			setupFiles: map[string]string{},
			targetDir:  "",
			wantPath:   "",
			wantFound:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "treeguard-config-test-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			origDir, err := os.Getwd()
			if err != nil {
				t.Fatalf("failed to get wd: %v", err)
			}
			if err := os.Chdir(tmpDir); err != nil {
				t.Fatalf("failed to chdir: %v", err)
			}
			defer os.Chdir(origDir)

			for relPath, content := range tt.setupFiles {
				full := filepath.Join(tmpDir, relPath)
				if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
					t.Fatalf("failed to mkdir: %v", err)
				}
				if err := os.WriteFile(full, []byte(content), 0644); err != nil {
					t.Fatalf("failed to write file: %v", err)
				}
			}

			gotPath, gotFound := FindConfig(tt.targetDir)
			if gotFound != tt.wantFound {
				t.Errorf("FindConfig() gotFound = %v, wantFound %v", gotFound, tt.wantFound)
			}
			if tt.wantFound && gotPath != tt.wantPath {
				t.Errorf("FindConfig() gotPath = %v, wantPath %v", gotPath, tt.wantPath)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantConfig  *Config
		wantErr     bool
	}{
		{
			name: "valid full configuration",
			yamlContent: `
rules:
  - rules/python
  - rules/go
ignore:
  - vendor
  - temp
format: json
output: results.json
packs:
  - https://example.com/rules.tar.gz
min_severity: WARNING
language: python
threads: 4
fix: true
max_file_size: 10485760
timeout: 15s
fail_on: high
`,
			wantConfig: &Config{
				Rules:       []string{"rules/python", "rules/go"},
				Ignore:      []string{"vendor", "temp"},
				Format:      "json",
				Output:      "results.json",
				Packs:       []string{"https://example.com/rules.tar.gz"},
				MinSeverity: "WARNING",
				Language:    "python",
				Threads:     4,
				Fix:         true,
				MaxFileSize: 10485760,
				Timeout:     15 * time.Second,
				FailOn:      "high",
			},
			wantErr: false,
		},
		{
			name: "partial configuration",
			yamlContent: `
format: sarif
min_severity: ERROR
`,
			wantConfig: &Config{
				Format:      "sarif",
				MinSeverity: "ERROR",
			},
			wantErr: false,
		},
		{
			name:        "invalid yaml syntax",
			yamlContent: `rules: [unclosed_array`,
			wantConfig:  nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "test-cfg-*.yaml")
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.WriteString(tt.yamlContent); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			tmpFile.Close()

			got, err := LoadConfig(tmpFile.Name())
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && !reflect.DeepEqual(got, tt.wantConfig) {
				t.Errorf("LoadConfig() got = %+v, want %+v", got, tt.wantConfig)
			}
		})
	}
}
