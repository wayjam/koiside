package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/egoist/mygo"

	app "koiside/internal/app"
	"koiside/internal/cli"
	"koiside/internal/mcp"
	"koiside/internal/ui/shell"
	"koiside/locales"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && cli.IsCommand(args[0]) {
		ctx := context.Background()
		if args[0] == "mcp" {
			if err := mcp.ServeStdio(ctx, os.Stdin, os.Stdout, os.Stderr, cli.Deps{}); err != nil {
				log.Fatal(err)
			}
			return
		}
		os.Exit(cli.Run(ctx, args, cli.Deps{}, os.Stdout, os.Stderr))
	}

	if len(args) > 0 && args[0] == "app" {
		args = args[1:]
	}

	services := app.New()
	model := shell.New(services)
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()

	mygo.App.WhenReady(func() {
		win := mygo.NewWindow(mygo.WindowOptions{
			Title:         locales.AppTitle(),
			Width:         960,
			Height:        640,
			MinWidth:      540,
			MinHeight:     460,
			TitleBarStyle: mygo.TitleBarHiddenInset,
			Vibrancy:      mygo.VibrancySidebar,
			Content:       model.Content(),
		})
		model.Attach(win)
		mygo.App.OnLocaleChanged(func(string) {
			win.SetTitle(locales.AppTitle())
			win.Invalidate()
		})
		model.RefreshDevices()
		model.StartDeviceWatch(watchCtx)
		go func() {
			_ = services.Accounts.RestoreDeveloperSession(context.Background())
			_ = services.Accounts.RestoreStoreSession(context.Background())
			mygo.RunOnMain(func() { win.Invalidate() })
		}()
		var openPaths []string
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if strings.TrimSpace(arg) != "" {
				openPaths = append(openPaths, arg)
			}
		}
		if envPath := strings.TrimSpace(os.Getenv("KOISIDE_OPEN_IPA")); envPath != "" {
			openPaths = append(openPaths, envPath)
		}
		if len(openPaths) > 0 {
			model.OpenPaths(openPaths)
		}
		if os.Getenv("KOISIDE_SMOKE") == "1" {
			go func() {
				time.Sleep(400 * time.Millisecond)
				mygo.RunOnMain(func() { win.Close() })
			}()
		}
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
