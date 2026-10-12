// Command beryl is the Beryllium CLI and TUI.
package main

import (
	"fmt"

	"github.com/wexelsdev/beryllium/internal/version"
)

func main() {
	fmt.Println("beryl", version.String())
}
