package frpc

import (
	"embed"

	"github.com/xxx/yyy/assets"
)

//go:embed static/*
var content embed.FS

func init() {
	assets.Register(content)
}
