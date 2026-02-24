package main

import (
	"os"

	"authbear/internal/cli"
)

func main() {
	code := cli.Run(os.Args[1:])
	os.Exit(code)
}
