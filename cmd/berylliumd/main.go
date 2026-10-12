// Command berylliumd is the privileged Beryllium daemon.
package main

import (
	"fmt"

	"github.com/wexelsdev/beryllium/internal/version"
)

func main() {
	fmt.Println("berylliumd", version.String())
}
