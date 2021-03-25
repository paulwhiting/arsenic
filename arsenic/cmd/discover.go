package cmd

import (
	"github.com/spf13/cobra"
	"github.com/defektive/arsenic/arsenic/lib/util"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Run scripts in the discovery phase.",
	Long: `Run scripts in the discovery phase.

Scripts should determine what hosts it needs to run against.`,
	Run: func(cmd *cobra.Command, args []string) {
		util.ExecutePhaseScripts("discovery")
	},
}

func init() {
	rootCmd.AddCommand(discoverCmd)
}