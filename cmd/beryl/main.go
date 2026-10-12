// Command beryl is the Beryllium CLI and TUI.
package main

import (
	"os"

	"github.com/vvaeli/beryllium/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
