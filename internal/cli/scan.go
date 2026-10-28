package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/loganprice/treeguard/internal/config"
	"github.com/loganprice/treeguard/internal/reporter"
	"github.com/loganprice/treeguard/internal/runner"
)

func newScanCmd(ctx context.Context) *cobra.Command {
	var (
		configPath   string
		rulePaths    []string
		format       string
		outputFile   string
		minSeverity  string
		langFilter   string
		threads      int
		noColor      bool
		autofix      bool
		dryRun       bool
		refreshRules bool
		changedOnly  bool
		baselineRef  string
		maxFileSize  int64
		timeout      time.Duration
		failOn       string
	)

	cmd := &cobra.Command{
		Use:   "scan [flags] <paths...>",
		Short: "Scan source code files or directories for security vulnerabilities",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var cfg *config.Config
			var err error

			if configPath != "" {
				cfg, err = config.LoadConfig(configPath)
				if err != nil {
					return fmt.Errorf("load config file %s: %w", configPath, err)
				}
			} else {
				targetDir := ""
				if len(args) > 0 {
					targetDir = args[0]
				}
				if foundPath, ok := config.FindConfig(targetDir); ok {
					cfg, err = config.LoadConfig(foundPath)
					if err != nil {
						return fmt.Errorf("load config file %s: %w", foundPath, err)
					}
				}
			}

			var ignoreDirs []string
			if cfg != nil {
				if len(cfg.Ignore) > 0 {
					ignoreDirs = cfg.Ignore
				}
				if !cmd.Flags().Changed("rules") {
					if len(cfg.Rules) > 0 {
						rulePaths = append(rulePaths, cfg.Rules...)
					}
					if len(cfg.Packs) > 0 {
						rulePaths = append(rulePaths, cfg.Packs...)
					}
				}
				if !cmd.Flags().Changed("format") && cfg.Format != "" {
					format = cfg.Format
				}
				if !cmd.Flags().Changed("output") && cfg.Output != "" {
					outputFile = cfg.Output
				}
				if !cmd.Flags().Changed("severity") && cfg.MinSeverity != "" {
					minSeverity = cfg.MinSeverity
				}
				if !cmd.Flags().Changed("lang") && cfg.Language != "" {
					langFilter = cfg.Language
				}
				if !cmd.Flags().Changed("threads") && cfg.Threads != 0 {
					threads = cfg.Threads
				}
				if !cmd.Flags().Changed("fix") && cfg.Fix {
					autofix = cfg.Fix
				}
				if !cmd.Flags().Changed("changed-only") && cfg.ChangedOnly {
					changedOnly = cfg.ChangedOnly
				}
				if !cmd.Flags().Changed("baseline") && cfg.Baseline != "" {
					baselineRef = cfg.Baseline
				}
				if !cmd.Flags().Changed("max-file-size") && cfg.MaxFileSize > 0 {
					maxFileSize = cfg.MaxFileSize
				}
				if !cmd.Flags().Changed("timeout") && cfg.Timeout > 0 {
					timeout = cfg.Timeout
				}
				if !cmd.Flags().Changed("fail-on") && cfg.FailOn != "" {
					failOn = cfg.FailOn
				}
			}

			failOnRank, err := parseFailOn(failOn)
			if err != nil {
				return err
			}

			if len(rulePaths) == 0 {
				// Default to ./rules if exists, or /rules (container default)
				if _, err := os.Stat("rules"); err == nil {
					rulePaths = []string{"rules"}
				} else if _, err := os.Stat("/rules"); err == nil {
					rulePaths = []string{"/rules"}
				} else {
					return fmt.Errorf("no rules specified. Use -r / --rules <path>")
				}
			}

			s := runner.NewScanner()
			result, err := s.Run(ctx, runner.ScanOptions{
				TargetPaths:  args,
				RulePaths:    rulePaths,
				Language:     langFilter,
				MinSeverity:  minSeverity,
				Threads:      threads,
				IgnoreDirs:   ignoreDirs,
				Fix:          autofix,
				DryRun:       dryRun,
				RefreshRules: refreshRules,
				ChangedOnly:  changedOnly,
				BaselineRef:  baselineRef,
				MaxFileSize:  maxFileSize,
				Timeout:      timeout,
			})
			if err != nil {
				return err
			}

			var rep reporter.Reporter
			switch strings.ToLower(format) {
			case "json":
				rep = reporter.NewJSONReporter(true)
			case "sarif":
				rep = reporter.NewSARIFReporter(true)
			case "html":
				rep = reporter.NewHTMLReporter()
			default:
				rep = reporter.NewConsoleReporter(noColor)
			}

			outWriter := cmd.OutOrStdout()
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("create output file %s: %w", outputFile, err)
				}
				defer f.Close()
				outWriter = f
			}

			if err := rep.Render(outWriter, result.Findings, result.Stats); err != nil {
				return fmt.Errorf("render findings: %w", err)
			}

			if autofix || dryRun {
				if dryRun {
					fmt.Fprintln(cmd.OutOrStdout(), "\n--- Autofix Preview (Dry Run) ---")
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "\n--- Autofix Results ---")
				}
				for _, diff := range result.FixResult.Diffs {
					fmt.Fprintln(cmd.OutOrStdout(), diff.Diff)
				}
				if dryRun {
					fmt.Fprintf(cmd.OutOrStdout(), "Proposed %d fix(es) across %d file(s).\n", result.FixResult.FixesApplied, result.FixResult.FilesFixed)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "Applied %d fix(es) across %d file(s).\n", result.FixResult.FixesApplied, result.FixResult.FilesFixed)
				}
			}

			if len(result.Findings) > 0 && !autofix {
				if failOnRank >= 0 {
					matching := 0
					for _, f := range result.Findings {
						if findingSeverityRank(f.Severity) >= failOnRank {
							matching++
						}
					}
					if matching > 0 {
						cmd.SilenceUsage = true
						if failOnRank == 0 || strings.ToLower(failOn) == "any" {
							return fmt.Errorf("found %d security issue(s)", matching)
						}
						return fmt.Errorf("found %d security issue(s) matching threshold --fail-on=%s", matching, strings.ToLower(failOn))
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to configuration file (.treeguard.yaml)")
	cmd.Flags().StringSliceVarP(&rulePaths, "rules", "r", nil, "Path to rule file(s) or directory")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text, json, sarif, html")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write output to file")
	cmd.Flags().StringVar(&minSeverity, "severity", "", "Minimum severity filter: INFO, WARNING, ERROR")
	cmd.Flags().StringVarP(&langFilter, "lang", "l", "", "Filter targets by language (python, javascript, go)")
	cmd.Flags().IntVarP(&threads, "threads", "j", 0, "Number of concurrent scanning threads (0 = auto)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable color in console output")
	cmd.Flags().BoolVar(&autofix, "fix", false, "Automatically apply rule remediations to source files")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview proposed autofixes without modifying files")
	cmd.Flags().BoolVar(&refreshRules, "update-rules", false, "Force update remote rule packs before scanning")
	cmd.Flags().BoolVar(&changedOnly, "changed-only", false, "Scan only modified/uncommitted files in local Git repository")
	cmd.Flags().StringVar(&baselineRef, "baseline", "", "Scan files changed relative to Git reference (e.g. main, HEAD~1)")
	cmd.Flags().StringVar(&baselineRef, "diff-ref", "", "Alias for --baseline")
	_ = cmd.Flags().MarkHidden("diff-ref")
	cmd.Flags().Int64Var(&maxFileSize, "max-file-size", config.DefaultMaxFileSize, "Maximum file size in bytes to scan (skip larger files)")
	cmd.Flags().DurationVar(&timeout, "timeout", config.DefaultTimeout, "Per-file evaluation timeout duration (e.g. 30s, 1m)")
	cmd.Flags().StringVar(&failOn, "fail-on", "any", "Exit with error if findings match or exceed severity: critical, high, medium, low, info, any, none")

	return cmd
}

// parseFailOn returns the numeric threshold rank for a fail-on severity string,
// or -1 for never fail, or an error if invalid.
func parseFailOn(val string) (int, error) {
	norm := strings.ToLower(strings.TrimSpace(val))
	switch norm {
	case "", "any", "all":
		return 0, nil
	case "none", "never", "off":
		return -1, nil
	case "info":
		return 1, nil
	case "low":
		return 2, nil
	case "medium", "warn", "warning":
		return 3, nil
	case "high", "error":
		return 4, nil
	case "critical", "crit":
		return 5, nil
	default:
		return 0, fmt.Errorf("invalid --fail-on value: %q. Allowed values: critical, high, medium, low, info, any, none", val)
	}
}

// findingSeverityRank maps finding severity strings to an ordinal rank.
func findingSeverityRank(sev string) int {
	norm := strings.ToLower(strings.TrimSpace(sev))
	switch norm {
	case "critical", "crit":
		return 5
	case "high", "error":
		return 4
	case "medium", "warn", "warning":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 1
	}
}
