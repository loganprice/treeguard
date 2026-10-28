package cli

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/loganprice/treeguard/internal/query"
)

func newDumpASTCmd() *cobra.Command {
	var (
		langOverride string
		nodesOnly    bool
		pretty       bool
	)

	cmd := &cobra.Command{
		Use:   "dump-ast [flags] <file>",
		Short: "Dump the Tree-sitter AST JSON representation passed to Rego rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			svc := query.NewService()

			data, err := svc.DumpAST(filePath, langOverride, nodesOnly)
			if err != nil {
				return err
			}

			encoder := json.NewEncoder(cmd.OutOrStdout())
			if pretty {
				encoder.SetIndent("", "  ")
			}
			return encoder.Encode(data)
		},
	}

	cmd.Flags().StringVarP(&langOverride, "lang", "l", "", "Override language detection")
	cmd.Flags().BoolVar(&nodesOnly, "nodes-only", false, "Dump only the flattened nodes list")
	cmd.Flags().BoolVarP(&pretty, "pretty", "p", true, "Pretty print output with indents")

	return cmd
}
