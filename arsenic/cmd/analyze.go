package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/defektive/arsenic/arsenic/lib/util"

)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze discovery data and create",
	Long: `Analyze discovery data and create hosts.

This will create a single host for hostnames that resolve to the same IPs`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("plz 2 refactor me, cause i am calling a slow shell script... k thx, bye!")
		create, _ := cmd.Flags().GetBool("create")

		mode := "dry-run"
		if create {
			mode = "create"
		}
		scriptArgs := []string{mode}
		util.ExecScript("as-analyze-hosts", scriptArgs)
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)

	analyzeCmd.Flags().BoolP("create", "c", false, "really create hosts")
}