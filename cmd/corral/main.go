package main

import (
	"os"

	"github.com/go-corral/corral/internal/cli"
)

var version = "dev"

func main() {
	os.Exit(cli.Main(os.Args[1:], version))
}
