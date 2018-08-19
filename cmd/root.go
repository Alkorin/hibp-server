package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const addrMapSize = (1<<24 + 1)

var rootCmd = &cobra.Command{}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
