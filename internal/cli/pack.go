package cli

import (
	"context"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/loganprice/treeguard/internal/registry"
)

func newPackCmd(ctx context.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "pack",
		Aliases: []string{"registry"},
		Short:   "Manage remote rule packs and registries",
		Long: `TreeGuard Pack & Registry allows downloading, caching, updating, and listing
remote SAST rule packs from HTTP/HTTPS URLs and registry aliases (e.g. pack:owasp-top10).`,
	}

	cmd.AddCommand(newPackPullCmd(ctx))
	cmd.AddCommand(newPackListCmd())
	cmd.AddCommand(newPackUpdateCmd(ctx))
	cmd.AddCommand(newPackCleanCmd())

	return cmd
}

func newPackPullCmd(ctx context.Context) *cobra.Command {
	var expectedSHA256 string

	cmd := &cobra.Command{
		Use:   "pull <pack-or-url>",
		Short: "Pull and cache a remote rule pack or URL locally",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			fmt.Fprintf(cmd.OutOrStdout(), "Pulling rule pack %q...\n", target)

			client := registry.DefaultClient
			path, err := client.ResolveRulePathWithChecksum(ctx, target, expectedSHA256, true)
			if err != nil {
				return fmt.Errorf("failed to pull rule pack %s: %w", target, err)
			}

			color.New(color.FgGreen, color.Bold).Fprintf(cmd.OutOrStdout(), "✓ Successfully pulled rule pack to %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVar(&expectedSHA256, "sha256", "", "Expected SHA-256 checksum of the rule pack archive")
	return cmd
}

func newPackListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List cached rule packs and available registry aliases",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := registry.DefaultClient
			packs, err := client.ListPacks()
			if err != nil {
				return fmt.Errorf("list packs: %w", err)
			}

			fmt.Fprintln(cmd.OutOrStdout(), "\n--- Cached Rule Packs ---")
			if len(packs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No cached rule packs found.")
			} else {
				for _, p := range packs {
					shaInfo := ""
					if len(p.SHA256) >= 12 {
						shaInfo = fmt.Sprintf(" | SHA256: %s...", p.SHA256[:12])
					}
					fmt.Fprintf(cmd.OutOrStdout(), "• %-15s | %d rules%s | URL: %s\n  Path: %s\n",
						p.Name, p.FilesCount, shaInfo, p.URL, p.Path)
				}
			}

			fmt.Fprintln(cmd.OutOrStdout(), "\n--- Default Registry Aliases ---")
			fmt.Fprintf(cmd.OutOrStdout(), "Available aliases: %s\n\n", client.AvailableAliases())

			return nil
		},
	}
}

func newPackUpdateCmd(ctx context.Context) *cobra.Command {
	return &cobra.Command{
		Use:   "update [pack-or-url]",
		Short: "Update cached rule pack(s)",
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) > 0 {
				target = args[0]
				fmt.Fprintf(cmd.OutOrStdout(), "Updating rule pack %q...\n", target)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Updating all cached rule packs...")
			}

			client := registry.DefaultClient
			if err := client.UpdatePack(ctx, target); err != nil {
				return fmt.Errorf("update rule pack: %w", err)
			}

			color.New(color.FgGreen, color.Bold).Fprintf(cmd.OutOrStdout(), "✓ Rule pack update complete.\n")
			return nil
		},
	}
}

func newPackCleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Clear all locally cached rule packs",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := registry.DefaultClient
			if err := client.CleanCache(); err != nil {
				return fmt.Errorf("clean cache: %w", err)
			}

			color.New(color.FgGreen, color.Bold).Fprintf(cmd.OutOrStdout(), "✓ Cleared rule pack cache (%s)\n", client.CacheDir)
			return nil
		},
	}
}
