package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	verbose  bool
	loglevel slog.LevelVar
	timeout  int64
	logger   = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &loglevel}))
	rootCmd  = &cobra.Command{
		Use:     "domain... [--timeout | -t] timeout [--verbose | -v]",
		Short:   "Resolves a domain starting from root name servers, avoiding cached responses",
		Args:    cobra.MinimumNArgs(1),
		Example: "digdeep mydomain.com -t 10",
		RunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				loglevel.Set(slog.LevelDebug)
			} else {
				loglevel.Set(slog.LevelError)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			defer cancel()
			for _, domain := range args {
				ips, err := ResolveDomain(ctx, domain)
				if err != nil {
					return err
				}
				fmt.Printf("%s:\n", domain)
				if len(ips) <= 0 {
					fmt.Printf("no addresses found\n")
				} else {
					for _, ip := range ips {
						fmt.Printf("\t%s\n", ip)
					}
				}
			}
			return nil
		},
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	slog.SetDefault(logger)
	rootCmd.PersistentFlags().Int64VarP(&timeout, "timeout", "t", 10, "timeout in seconds")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}
