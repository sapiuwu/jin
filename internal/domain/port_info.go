package domain

// PortInfo is the result of a single port probe.
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"` // e.g. "http", "https"
	Status  string `json:"status"`  // "open" or "closed"
}
