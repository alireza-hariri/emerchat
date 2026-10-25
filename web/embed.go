// Package web holds the browser client, embedded into the binary.
package web

import "embed"

//go:embed index.html css js favicon.svg
var FS embed.FS
