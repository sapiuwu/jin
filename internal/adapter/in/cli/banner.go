package cli

const bannerArt = `
         ___   ___   __      __
        /  /  /  /  /  \    /  /
       /  /  /  /  /    \  /  /
      /  /  /  /  /   \  \/  /
  ___/  /  /  /  /  /  \    /
 |_____/  /__/  /__/    \__/
`

const bannerText = ` v2.4.1

  🔍 Just Intelligence Network
  CLI for server & network reconnaissance
  https://github.com/sapiuwu/jin
`

const bannerUsage = `
  Usage: jin [command] [flags]
`

// renderBanner returns the startup banner, colored when enabled.
func (a *App) renderBanner() string {
	if !a.color {
		return bannerArt + bannerText + bannerUsage
	}
	return a.cyan(bannerArt) + a.white(bannerText) + a.yellow(bannerUsage)
}
