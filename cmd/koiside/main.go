package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/egoist/mygo"

	app "koiside/internal/app"
	"koiside/internal/ui/shell"
	"koiside/locales"
)

func main() {
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
