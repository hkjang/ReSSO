package version

import "runtime"

var (
	Version   = "v0.2.0-dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

type Info struct {
	Product   string `json:"product"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

func Current() Info {
	return Info{Product: "ReSSO", Version: Version, Commit: Commit, BuildTime: BuildTime, GoVersion: runtime.Version()}
}
