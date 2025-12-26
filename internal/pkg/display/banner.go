// internal/pkg/display/banner.go
package display

import (
	"github.com/fatih/color"
)

// BANNER — Clearly spells "JIN" (J | I | N)
var BANNER = color.New(color.FgCyan).Sprint(
	`
         ___   ___   __      __
        /  /  /  /  /  \    /  /
       /  /  /  /  /    \  /  /
      /  /  /  /  /   \  \/  /
  ___/  /  /  /  /  /  \    /
 |_____/  /__/  /__/    \__/
`) + color.New(color.FgWhite).Sprint(` v2.1.0

  🔍 Just Intelligence Network
  CLI for server & network reconnaissance
  https://github.com/aliftech/jin
`) + color.New(color.FgYellow).Sprint(`
  Usage: jin [command] [flags]
`)
