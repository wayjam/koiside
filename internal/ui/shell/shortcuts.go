package shell

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"koiside/internal/device"
	"koiside/internal/shortcuts"
	"koiside/locales"
)

func (m *Model) shortcutsPanel(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	m.mu.Lock()
	standalone, lc, embedded := m.sideStoreApp, m.lcApp, m.sideStoreEmbedded
	guests := m.lcApps
	busy, status, failed := m.shortcutBusy, m.shortcutStatus, m.shortcutFailed
	m.mu.Unlock()

	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.ShortcutsTitle()).FontSize(16).Bold()
		ui.Text(c, msg.ShortcutsShareHint()).FontSize(12).TextColor(t.TextMuted)
	})
	insetGroup(c, "iphone-shortcuts-group", func() {
		ui.Column(c).FillWidth().Padding(14, 18).Gap(8).Children(func() {
			ui.Text(c, msg.ShortcutsRefreshTitle()).FontSize(14).Bold()
			ui.Text(c, msg.ShortcutsRefreshHint()).FontSize(12).TextColor(t.TextMuted)
			ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
				addRefresh := func(app *device.InstalledApp, key, appName, title string) {
					if app == nil || app.TeamID == "" {
						return
					}
					if uiBtnWithTip(c, key, title, busy, "").Clicked() {
						bundleID, teamID := app.BundleID, app.TeamID
						m.exportShortcut(title, func(ctx context.Context, out, name string) error {
							return shortcuts.ExportRefresh(ctx, out, name, appName, bundleID, teamID)
						})
					}
				}
				addRefresh(standalone, "shortcut-refresh-sidestore", "SideStore", msg.ShortcutsRefreshSideStore())
				if embedded {
					addRefresh(lc, "shortcut-refresh-livecontainer", "LiveContainer", msg.ShortcutsRefreshLC())
				}
				if uiBtn(c, "shortcut-refresh-guide", msg.ToolsOpenGuide()).Clicked() {
					c.OpenURL("https://livecontainer.github.io/docs/installation/lc_sidestore#auto-refresh-shortcut")
				}
			})
			if (standalone == nil || standalone.TeamID == "") && (!embedded || lc == nil || lc.TeamID == "") {
				ui.Text(c, msg.ShortcutsRefreshNeedsDevice()).FontSize(12).TextColor(t.TextMuted)
			}
		})
		ui.Divider(c)
		ui.Column(c).FillWidth().Padding(14, 18).Gap(8).Children(func() {
			ui.Text(c, msg.ShortcutsLaunchTitle()).FontSize(14).Bold()
			ui.Text(c, msg.ShortcutsLaunchHint()).FontSize(12).TextColor(t.TextMuted)
			if len(guests) > 0 {
				ui.Scroll(c.Key("shortcut-app-list")).FillWidth().MaxHeight(174).Children(func() {
					for i, app := range guests {
						if i > 0 {
							ui.Divider(c)
						}
						name := app.Name
						if name == "" {
							name = strings.TrimSuffix(app.Folder, ".app")
						}
						ui.Row(c.Key("shortcut-app-"+app.Folder)).FillWidth().Gap(10).Padding(5, 0).AlignItems(ui.Center).Children(func() {
							ui.Column(c).Grow(1).MinWidth(0).Gap(2).Children(func() {
								ui.Text(c, name).FontSize(13).Bold().SingleLine()
								monoText(c, app.Folder).FontSize(11).TextColor(t.TextMuted).SingleLine()
							})
							if uiBtnWithTip(c, "shortcut-launch-"+app.Folder, msg.ShortcutsExport(), busy, "").Clicked() {
								launchURL := shortcuts.LaunchURL(app.Folder)
								m.exportShortcut(name, func(ctx context.Context, out, name string) error {
									return shortcuts.ExportLaunch(ctx, out, name, launchURL)
								})
							}
						})
					}
				})
			}
			ui.Text(c, msg.ShortcutsLaunchURLHint()).FontSize(12).TextColor(t.TextMuted)
			ui.TextInput(c.Key("shortcut-launch-url"), &m.shortcutLaunchURL).FillWidth().
				Label(msg.ShortcutsLaunchURL()).Placeholder(msg.ShortcutsLaunchURL())
			ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
				launchURL := strings.TrimSpace(m.shortcutLaunchURL)
				if uiBtnWithTip(c, "shortcut-launch-export", msg.ShortcutsExport(), busy || !shortcuts.ValidLaunchURL(launchURL), "").Clicked() {
					m.exportShortcut(msg.ShortcutsLaunchTitle(), func(ctx context.Context, out, name string) error {
						return shortcuts.ExportLaunch(ctx, out, name, launchURL)
					})
				}
				if uiBtn(c, "shortcut-launch-guide", msg.ToolsOpenGuide()).Clicked() {
					c.OpenURL("https://livecontainer.github.io/docs/guides/add-to-home-screen")
				}
			})
		})
		if busy || status != "" {
			ui.Divider(c)
			ui.Row(c).FillWidth().Padding(10, 18).Gap(8).AlignItems(ui.Center).Children(func() {
				if busy {
					if !c.Preferences().ReduceMotion {
						ui.Spinner(c).Size(16, 16).AccessHidden(true)
					}
					ui.Text(c.Key("shortcut-status"), msg.ShortcutsSaving()).FontSize(12).Role(ui.RoleStatus)
				} else if failed {
					ui.Text(c.Key("shortcut-status"), msg.ShortcutsSaveFailed(status)).Grow(1).FontSize(12).Role(ui.RoleStatus)
				} else {
					ui.Text(c.Key("shortcut-status"), msg.ShortcutsSaved(status)).Grow(1).FontSize(12).Role(ui.RoleStatus)
				}
			})
		}
	})
}

func (m *Model) exportShortcut(defaultName string, export func(context.Context, string, string) error) {
	if m.win == nil {
		return
	}
	m.mu.Lock()
	if m.shortcutBusy {
		m.mu.Unlock()
		return
	}
	m.shortcutBusy, m.shortcutStatus, m.shortcutFailed = true, "", false
	m.mu.Unlock()

	win := m.win
	title := m.msg(nil).ShortcutsExport()
	filename := strings.NewReplacer("/", "-", "\\", "-", ":", "-").Replace(defaultName) + ".shortcut"
	go func() {
		out, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent:      win,
			Title:       title,
			DefaultPath: filename,
			Filters:     []mygo.FileFilter{{Name: "Shortcut", Extensions: []string{"shortcut"}}},
		})
		if err == nil && out != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			name := strings.TrimSuffix(filepath.Base(out), filepath.Ext(out))
			err = export(ctx, out, name)
			cancel()
		}
		m.mu.Lock()
		m.shortcutBusy = false
		if err != nil {
			m.shortcutStatus = err.Error()
			m.shortcutFailed = true
		} else if out != "" {
			m.shortcutStatus = filepath.Base(out)
		}
		m.mu.Unlock()
		mygo.RunOnMain(func() { win.Invalidate() })
	}()
}
