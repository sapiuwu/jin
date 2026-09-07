package cli

import "github.com/aliftech/jin/internal/version"

const bannerArt = `
         ___   ___   __      __
        /  /  /  /  /  \    /  /
       /  /  /  /  /    \  /  /
      /  /  /  /  /   \  \/  /
  ___/  /  /  /  /  /  \    /
 |_____/  /__/  /__/    \__/
`

const bannerUsage = `
  Usage: jin [command] [flags]
`

// renderBanner returns the startup banner, colored when enabled.
func (a *App) renderBanner() string {
	bannerText := " v" + version.Version + `

  🔍 Just Intelligence Network
  CLI for server & network reconnaissance
  https://github.com/sapiuwu/jin
`
	if !a.color {
		return bannerArt + bannerText + bannerUsage
	}
	return a.cyan(bannerArt) + a.white(bannerText) + a.yellow(bannerUsage)
}
