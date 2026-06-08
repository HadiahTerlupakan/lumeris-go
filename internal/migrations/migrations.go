// Package migrations meng-embed file SQL migrasi.
package migrations

import (
	"embed"
	"io/fs"
)

//go:embed all:files
var embedded embed.FS

// FS berisi file *.sql migrasi.
var FS fs.FS = mustSub()

func mustSub() fs.FS {
	sub, err := fs.Sub(embedded, "files")
	if err != nil {
		panic(err)
	}
	return sub
}
