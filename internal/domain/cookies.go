package domain

// CookieAnalysis reports the Set-Cookie attributes observed on a target's
// response, plus any security concerns (missing Secure/HttpOnly/SameSite).
type CookieAnalysis struct {
	URL      string
	Cookies  []Cookie
	Warnings []string
}

// Cookie captures the security-relevant attributes of a single Set-Cookie.
type Cookie struct {
	Name     string
	Secure   bool
	HttpOnly bool
	SameSite string
	Domain   string
	Path     string
	Expires  string
	HasFlags bool
}
