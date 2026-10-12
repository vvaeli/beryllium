// Command berylliumd is the privileged Beryllium daemon.
package main

import (
	"fmt"

	"github.com/vvaeli/beryllium/internal/version"
)

func main() {
	fmt.Println("berylliumd", version.String())
}
