package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/loganprice/treeguard/internal/version"
)

// NewRootCmd builds the root treeguard cobra command with all subcommands attached.
func NewRootCmd(ctx context.Context) *cobra.Command {
	info := version.Get()
	rootCmd := &cobra.Command{
		Use:     "treeguard",
		Short:   "TreeGuard: A Semgrep-like SAST scanner powered by Tree-sitter and OPA",
		Version: info.String(),
		Long: `TreeGuard is a high-performance static application security testing (SAST) engine.
It uses Tree-sitter to parse source code across multiple languages into high-fidelity
AST representations and evaluates declarative security rules written in Rego.`,
	}

	rootCmd.SetVersionTemplate("{{.Version}}\n")

	rootCmd.AddCommand(newScanCmd(ctx))
	rootCmd.AddCommand(newTestCmd(ctx))
	rootCmd.AddCommand(newValidateCmd(ctx))
	rootCmd.AddCommand(newDumpASTCmd())
	rootCmd.AddCommand(newQueryCmd(ctx))
	rootCmd.AddCommand(newPackCmd(ctx))
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

// Execute runs the root command with standard OS signal handling.
func Execute() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	rootCmd := NewRootCmd(ctx)
	return rootCmd.ExecuteContext(ctx)
}
