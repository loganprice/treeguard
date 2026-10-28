package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/loganprice/treeguard/internal/runner"
)

func newTestCmd(ctx context.Context) *cobra.Command {
	var rulePaths []string

	cmd := &cobra.Command{
		Use:   "test [flags] <test-paths...>",
		Short: "Test Rego rules against annotated test fixtures (# ruleid: / # ok:)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(rulePaths) == 0 {
				if _, err := os.Stat("rules"); err == nil {
					rulePaths = []string{"rules"}
				} else if _, err := os.Stat("/rules"); err == nil {
					rulePaths = []string{"/rules"}
				} else {
					return fmt.Errorf("no rules specified. Use -r / --rules <path>")
				}
			}

			t := runner.NewRuleTester()
			res, err := t.RunTests(ctx, rulePaths, args)
			if err != nil {
				return err
			}

			return t.RenderTestResults(cmd.OutOrStdout(), cmd.ErrOrStderr(), res)
		},
	}

	cmd.Flags().StringSliceVarP(&rulePaths, "rules", "r", nil, "Path to rule file(s) or directory")
	return cmd
}
