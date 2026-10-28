package cli

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/loganprice/treeguard/internal/validator"
)

func newValidateCmd(ctx context.Context) *cobra.Command {
	var (
		strict bool
		format string
	)

	cmd := &cobra.Command{
		Use:   "validate [flags] <rule-paths...>",
		Short: "Validate and lint Rego rules for syntax, metadata, and policy entrypoints",
		Long: `Validate and lint Rego rule files. Checks OPA syntax compilation, standard package naming
conventions, required metadata fields (id, severity, message), and entrypoint definitions (deny/findings).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			val := validator.New()
			report, err := val.ValidatePaths(ctx, args, validator.ValidationOptions{
				Strict: strict,
			})
			if err != nil {
				return err
			}

			if strings.ToLower(format) == "json" {
				return val.RenderJSON(cmd.OutOrStdout(), report)
			}

			cmd.SilenceUsage = true
			return val.RenderConsole(cmd.OutOrStdout(), report)
		},
	}

	cmd.Flags().BoolVar(&strict, "strict", false, "Upgrade advisory warnings (like missing CWE) to validation errors")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text, json")

	return cmd
}
