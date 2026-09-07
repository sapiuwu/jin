package domain

// ExposedResult reports which sensitive files/paths were found to be
// publicly accessible on a target. A "found" entry means the path returned
// a successful (or interesting) HTTP status — a common misconfiguration
// that leaks source, credentials, or metadata.
type ExposedResult struct {
	URL   string
	Files []ExposedFile
}

// ExposedFile describes one probed path.
type ExposedFile struct {
	Path    string
	FullURL string
	Status  int
	Size    int64
	Found   bool
	Note    string
}
