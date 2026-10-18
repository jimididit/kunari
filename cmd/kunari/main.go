package main

import (
	"os"

	"github.com/jimididit/kunari/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
