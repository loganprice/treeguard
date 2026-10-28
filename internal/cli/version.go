package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/loganprice/treeguard/internal/version"
)

func newVersionCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the TreeGuard version and build metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := version.Get()
			if jsonOutput {
				jsonStr, err := info.JSON()
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), jsonStr)
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), info.String())
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output version information in JSON format")

	return cmd
}
