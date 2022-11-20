package main

import (
	"github.com/gmctechsols/luau/cmd"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{Use: "app"}
	rootCmd.AddCommand(cmd.NewDbCmd())
	rootCmd.AddCommand(cmd.NewClientsCmd())
	rootCmd.Execute()
}
