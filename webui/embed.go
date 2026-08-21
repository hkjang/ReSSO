// Package webui embeds the built administration console so that ReSSO
// ships as a single binary with no runtime asset dependencies.
package webui

import "embed"

//go:embed dist/*
var files embed.FS

func Files() embed.FS { return files }
