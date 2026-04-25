package version

import (
	"fmt"
	"runtime"
)

const (
	Major = 2
	Minor = 4
	Patch = 0
)

var (
	Version   = fmt.Sprintf("%d.%d.%d", Major, Minor, Patch)
	GitCommit = ""
	BuildDate = ""
	GoVersion = runtime.Version()
)

func GetVersion() string {
	return Version
}

func GetFullVersion() string {
	v := Version
	if GitCommit != "" {
		v = fmt.Sprintf("%s (commit: %s)", v, GitCommit)
	}
	if BuildDate != "" {
		v = fmt.Sprintf("%s (built: %s)", v, BuildDate)
	}
	return v
}

func GetGoVersion() string {
	return GoVersion
}

func PrintVersion() {
	fmt.Printf("WinLogAnalyzer-Go v%s\n", Version)
	fmt.Printf("Go version: %s\n", GoVersion)
	if GitCommit != "" {
		fmt.Printf("Git commit: %s\n", GitCommit)
	}
	if BuildDate != "" {
		fmt.Printf("Build date: %s\n", BuildDate)
	}
}
