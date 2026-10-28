package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/loganprice/treeguard/internal/query"
)

func newQueryCmd(ctx context.Context) *cobra.Command {
	var (
		expr         string
		langOverride string
	)

	cmd := &cobra.Command{
		Use:   "query [flags] -e <expr> <file>",
		Short: "Run an ad-hoc Rego query against a file's AST input",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if expr == "" {
				return fmt.Errorf("query expression required. Use -e <expr>")
			}

			filePath := args[0]
			svc := query.NewService()

			bindings, err := svc.Eval(ctx, filePath, langOverride, expr)
			if err != nil {
				return err
			}

			if len(bindings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No matches (undefined)")
				return nil
			}

			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")

			for _, binding := range bindings {
				if err := encoder.Encode(binding); err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&expr, "eval", "e", "", "Rego expression to evaluate against input")
	cmd.Flags().StringVarP(&langOverride, "lang", "l", "", "Override language detection")
	_ = cmd.MarkFlagRequired("eval")

	return cmd
}
