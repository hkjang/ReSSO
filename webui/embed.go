package webui

import "embed"

//go:embed dist/*
var files embed.FS

func Files() embed.FS { return files }
