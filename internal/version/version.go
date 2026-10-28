package version

import (
	"encoding/json"
	"fmt"
	"runtime"
)

// Build information populated via -ldflags at compile time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info holds detailed build and runtime environment metadata.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the current build and environment metadata.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String formats the build info as a human-readable string.
func (i Info) String() string {
	return fmt.Sprintf("TreeGuard version %s (commit: %s, built at: %s, go: %s, platform: %s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.Platform)
}

// JSON returns the build info formatted as a JSON string.
func (i Info) JSON() (string, error) {
	bytes, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal version info: %w", err)
	}
	return string(bytes), nil
}
