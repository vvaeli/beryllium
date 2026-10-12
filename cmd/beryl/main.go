// Command beryl is the Beryllium CLI and TUI.
package main

import (
	"fmt"

	"github.com/vvaeli/beryllium/internal/version"
)

func main() {
	fmt.Println("beryl", version.String())
}
