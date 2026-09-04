package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/lyoung-confluent/gwlb-xdp/cmd"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := cmd.Execute(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "gwlb-xdp failed: %v\n", err)
		os.Exit(1)
	}
}
