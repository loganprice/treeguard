package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
)

// Default limits for scan engine protection
const (
	DefaultMaxFileSize = int64(5 * 1024 * 1024) // 5 MB
	DefaultTimeout     = 30 * time.Second       // 30 seconds
)

// Config represents the project configuration structure loaded from .treeguard.yaml / .treeguard.yml
type Config struct {
	Rules       []string      `yaml:"rules,omitempty"`
	Ignore      []string      `yaml:"ignore,omitempty"`
	Format      string        `yaml:"format,omitempty"`
	Output      string        `yaml:"output,omitempty"`
	Packs       []string      `yaml:"packs,omitempty"`
	MinSeverity string        `yaml:"min_severity,omitempty"`
	Language    string        `yaml:"language,omitempty"`
	Threads     int           `yaml:"threads,omitempty"`
	Fix         bool          `yaml:"fix,omitempty"`
	ChangedOnly bool          `yaml:"changed_only,omitempty"`
	Baseline    string        `yaml:"baseline,omitempty"`
	MaxFileSize int64         `yaml:"max_file_size,omitempty"`
	Timeout     time.Duration `yaml:"timeout,omitempty"`
	FailOn      string        `yaml:"fail_on,omitempty"`
}

// FindConfig checks for .treeguard.yaml or .treeguard.yml in targetDir or current working directory.
func FindConfig(targetDir string) (string, bool) {
	candidates := []string{".treeguard.yaml", ".treeguard.yml"}

	// Check targetDir if provided and is a directory
	if targetDir != "" {
		fi, err := os.Stat(targetDir)
		if err == nil && fi.IsDir() {
			for _, candidate := range candidates {
				p := filepath.Join(targetDir, candidate)
				if _, err := os.Stat(p); err == nil {
					return p, true
				}
			}
		}
	}

	// Check current directory
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}

	return "", false
}

// LoadConfig reads and parses a YAML configuration file from path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config YAML: %w", err)
	}

	return &cfg, nil
}
