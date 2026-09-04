package cmd

import (
	"context"

	"github.com/spf13/cobra"
)

// ./gwlb-xdp
var RootCmd = &cobra.Command{
	Use:   "gwlb-xdp",
	Short: "https://github.com/lyoung-confluent/gwlb-xdp",

	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute(ctx context.Context) error {
	return RootCmd.ExecuteContext(ctx)
}
