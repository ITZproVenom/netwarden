package main

import (
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	application := NewGUIApp()
	if err := wails.Run(&options.App{
		Title:            "NetWarden",
		Width:            1280,
		Height:           800,
		MinWidth:         960,
		MinHeight:        640,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 8, G: 15, B: 26, A: 1},
		OnStartup:        application.startup,
		OnShutdown:       application.shutdown,
		Bind:             []interface{}{application},
	}); err != nil {
		println("NetWarden GUI:", err.Error())
	}
}
