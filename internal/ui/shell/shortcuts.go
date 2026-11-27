package shell

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"koiside/internal/device"
	"koiside/internal/shortcuts"
	"koiside/locales"
)

const (
	helpShortcutRefresh = "shortcut-refresh"
	helpShortcutLaunch  = "shortcut-launch"
)

type shortcutResult struct {
	path string
	err  string
}

func isShortcutGuide(topic string) bool {
	return topic == helpShortcutRefresh || topic == helpShortcutLaunch
}

func (m *Model) shortcutsPanel(c *ui.Context, msg locales.Messages) {
	ui.Text(c, msg.ShortcutsTitle()).FontSize(16).Bold()
	insetGroup(c, "iphone-shortcuts-group", func() {
		for i, item := range []struct {
			topic, label string
			icon         *ui.SVG
		}{
			{helpShortcutRefresh, msg.HelpGuideRefreshShortcut(), phRefresh},
			{helpShortcutLaunch, msg.HelpGuideLaunchShortcut(), phDevice},
		} {
			if i != 0 {
				ui.Divider(c)
			}
			row := ui.ButtonBase(c.Key("help-open-"+item.topic)).FillWidth().Padding(10, 18).
				Cursor(ui.CursorPointer).Label(item.label).Transition(colorTransition)
			if row.Hovered() {
				row.Background(c.Theme().SurfaceHover)
			}
			applyPressPose(row, 0.992)
			row.Children(func() {
				ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, item.icon).Size(19, 19).TextColor(accentInk(c.Theme())).AccessHidden(true)
					ui.Text(c, item.label).Grow(1).MinWidth(0).FontSize(13).Bold()
					ui.Icon(c, phCaretRight).Size(14, 14).TextColor(c.Theme().TextMuted).AccessHidden(true)
				})
			})
			if row.Clicked() {
				m.startHelpGuide(item.topic)
			}
		}
	})
}

func (m *Model) shortcutGuideSteps(c *ui.Context, msg locales.Messages, topic string) (string, []helpGuideStep) {
	result := m.shortcutResultFor(topic)
	title, tryLabel := msg.HelpGuideRefreshShortcut(), msg.HelpGuideTestRefresh()
	body := strings.Split(msg.HelpGuideTryRefresh(), "\n")
	pick := func() { m.shortcutRefreshExport(c, msg) }
	finish := func() {
		ui.Collapsible(c.Key("shortcut-refresh-error"), msg.HelpGuideRefreshHelp(), &m.shortcutTroubleshooting, func() {
			ui.Text(c, msg.HelpGuideRefreshSession()).FontSize(13)
			m.helpRecoveryLink(c, msg)
		}).Cursor(ui.CursorPointer)
		ui.Collapsible(c.Key("shortcut-automation"), msg.HelpGuideSchedule(), &m.shortcutSchedule, func() {
			for _, action := range strings.Split(msg.HelpGuideScheduleSteps(), "\n") {
				ui.Text(c, action).FontSize(13)
			}
		}).Cursor(ui.CursorPointer)
		m.helpLink(c, "shortcut-check-profile", msg.MaintainVerifyProfile(), verifyExpiryURL)
	}
	if topic == helpShortcutLaunch {
		title, tryLabel = msg.HelpGuideLaunchShortcut(), msg.HelpGuidePin()
		body = strings.Split(msg.HelpGuidePinSteps(), "\n")
		pick = func() { m.shortcutLaunchExport(c, msg) }
		finish = func() {
			m.helpLink(c, "shortcut-launch-guide", msg.ToolsOpenGuide(), "https://livecontainer.github.io/docs/guides/add-to-home-screen")
		}
	}
	return title, []helpGuideStep{
		{label: msg.HelpGuideExport(), extra: func() {
			pick()
			m.shortcutExportStatus(c, msg, result)
		}},
		{label: msg.HelpGuideSend(), extra: func() {
			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Padding(10, 12).Radius(9).Background(c.Theme().Selection).Children(func() {
				ui.Icon(c, phPaperPlaneTiltDuotone).Size(21, 21).TextColor(accentInk(c.Theme())).AccessHidden(true)
				ui.Text(c, filepath.Base(result.path)).Grow(1).MinWidth(0).FontSize(13).Bold()
			})
			m.helpFileActions(c, msg, result.path, "shortcut")
			for idx, instruction := range strings.Split(msg.HelpGuideReceiveShortcut(), "\n") {
				ui.Row(c.Key(idx)).FillWidth().Gap(8).AlignItems(ui.Start).Children(func() {
					ui.Icon(c, phCheckCircleFill).Size(14, 14).TextColor(accentInk(c.Theme())).Shrink(0)
					ui.Text(c, instruction).FontSize(13).Grow(1)
				})
			}
		}},
		{label: tryLabel, body: body, extra: finish},
	}
}
func (m *Model) shortcutRefreshExport(c *ui.Context, msg locales.Messages) {
	m.mu.Lock()
	standalone, lc, embedded, busy := m.sideStoreApp, m.lcApp, m.sideStoreEmbedded, m.shortcutBusy
	m.mu.Unlock()
	ui.Text(c, msg.HelpGuideExportRefresh()).FontSize(13)
	ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
		add := func(app *device.InstalledApp, name, button, key string) {
			if app == nil || app.TeamID == "" {
				return
			}
			if uiPrimaryBtnWithTip(c, key, button, busy, "").Clicked() {
				m.exportShortcut(helpShortcutRefresh, msg.ShortcutsRefreshTitle()+" - "+name, func(ctx context.Context, out, title string) error {
					return shortcuts.ExportRefresh(ctx, out, title, name, app.BundleID, app.TeamID)
				})
			}
		}
		add(standalone, "SideStore", msg.HelpGuideExportSideStore(), "shortcut-refresh-sidestore")
		if embedded {
			add(lc, "LiveContainer", msg.HelpGuideExportLive(), "shortcut-refresh-livecontainer")
		}
	})
	if (standalone == nil || standalone.TeamID == "") && (!embedded || lc == nil || lc.TeamID == "") {
		ui.Text(c, msg.ShortcutsRefreshNeedsDevice()).FontSize(13)
		m.helpDeviceCheck(c, msg)
	}
}

func (m *Model) shortcutLaunchExport(c *ui.Context, msg locales.Messages) {
	m.mu.Lock()
	guests, busy := m.lcApps, m.shortcutBusy
	m.mu.Unlock()
	if len(guests) > 0 {
		ui.Text(c, msg.HelpGuideChooseApp()).FontSize(13)
		for _, app := range guests {
			name := app.Name
			if name == "" {
				name = strings.TrimSuffix(app.Folder, ".app")
			}
			ui.Row(c.Key(app.Folder)).FillWidth().Gap(10).Padding(10, 12).Radius(10).Background(c.Theme().Surface).
				Border(1, c.Theme().Border.Alpha(0.6)).AlignItems(ui.Center).Children(func() {
				ui.Box(c).Size(28, 28).Radius(8).Background(c.Theme().Selection).Center().Children(func() {
					ui.Icon(c, phCubeFill).Size(16, 16).TextColor(accentInk(c.Theme())).AccessHidden(true)
				})
				ui.Column(c).Grow(1).MinWidth(0).Gap(2).Children(func() {
					ui.Text(c, name).Bold().FontSize(13)
					monoText(c, app.Folder).FontSize(11).TextColor(c.Theme().TextMuted)
				})
				if uiPrimaryBtnWithTip(c, "shortcut-launch-"+app.Folder, msg.ShortcutsExport(), busy, "").Clicked() {
					m.exportLaunchShortcut(name, shortcuts.LaunchURL(app.Folder))
				}
			})
		}
	} else {
		ui.Row(c).FillWidth().Wrap().Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, msg.HelpGuideNoApps()).Grow(1).MinWidth(190).FontSize(13)
			m.helpRescan(c, msg, "help-detect-guests")
		})
	}
	ui.Text(c, msg.HelpGuideCopyLaunchURL()).FontSize(13)
	ui.Text(c, msg.HelpGuideSendLaunchURL()).FontSize(13)
	ui.TextInput(c.Key("shortcut-launch-url"), &m.shortcutLaunchURL).Font("monospace").FontFeatures("tnum").FillWidth().
		Label(msg.ShortcutsLaunchURL()).Placeholder(msg.ShortcutsLaunchURL())
	launchURL := strings.TrimSpace(m.shortcutLaunchURL)
	valid := shortcuts.ValidLaunchURL(launchURL)
	if launchURL != "" && !valid {
		ui.Text(c, msg.HelpGuideInvalidLaunchURL()).Role(ui.RoleStatus).FontSize(12).TextColor(c.Theme().TextMuted)
	}
	ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
		if uiPrimaryBtnWithTip(c, "shortcut-launch-export", msg.ShortcutsExport(), busy || !valid, "").Clicked() {
			m.exportLaunchShortcut(msg.ShortcutsLaunchTitle(), launchURL)
		}
		if uiBtnWithTip(c, "shortcut-paste", msg.HelpGuidePaste(), busy, "").Clicked() {
			if pasted := strings.TrimSpace(c.ReadClipboard()); pasted != "" {
				m.shortcutLaunchURL = pasted
			}
		}
	})
}

func (m *Model) helpFileActions(c *ui.Context, msg locales.Messages, path, key string) {
	ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
		if uiPrimaryBtn(c, "help-airdrop-"+key, msg.HelpGuideAirDrop()).Clicked() {
			m.helpFileError = ""
			if _, err := os.Stat(path); err != nil {
				m.helpFileError = msg.HelpGuideFileMissing()
			} else if !openAirDrop(path) {
				m.helpFileError = msg.HelpGuideAirDropUnavailable()
			}
		}
		if uiBtn(c, "help-finder-"+key, msg.HelpGuideFinder()).Clicked() {
			m.helpFileError = ""
			if _, err := os.Stat(path); err != nil {
				m.helpFileError = msg.HelpGuideFileMissing()
			} else if m.win != nil {
				mygo.Shell.ShowItemInFolder(path)
			}
		}
	})
	if m.helpFileError != "" {
		ui.Text(c, m.helpFileError).Role(ui.RoleStatus).FontSize(12).TextColor(c.Theme().TextMuted)
	}
}

func (m *Model) shortcutResultFor(topic string) shortcutResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.shortcutResults[topic]
}

func (m *Model) shortcutCanAdvance(topic string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.shortcutBusy && m.shortcutResults[topic].path != ""
}

func (m *Model) shortcutExportStatus(c *ui.Context, msg locales.Messages, res shortcutResult) {
	m.mu.Lock()
	busy := m.shortcutBusy
	m.mu.Unlock()
	text := ""
	switch {
	case busy:
		text = msg.ShortcutsSaving()
	case res.err != "":
		text = msg.ShortcutsSaveFailed(res.err)
	case res.path != "":
		text = msg.ShortcutsSaved(filepath.Base(res.path))
	default:
		text = msg.HelpGuideExportFirst()
	}
	if text != "" {
		ui.Row(c).FillWidth().Gap(7).AlignItems(ui.Center).Children(func() {
			var icon *ui.SVG
			switch {
			case busy:
			case res.err != "":
				icon = phXCircleFill
			case res.path != "":
				icon = phCheckCircleFill
			default:
				icon = phInfo
			}
			if icon != nil {
				badge := ui.Icon(c.Key("shortcut-exported"), icon).Size(16, 16).TextColor(accentInk(c.Theme())).AccessHidden(true)
				if !c.Preferences().ReduceMotion {
					badge.Transition(stepCheckEnterTransition)
				}
			}
			ui.Text(c.Key("shortcut-status"), text).Role(ui.RoleStatus).Grow(1).MinWidth(0).FontSize(13)
		})
	}
}

func (m *Model) exportLaunchShortcut(name, launchURL string) {
	m.exportShortcut(helpShortcutLaunch, name, func(ctx context.Context, out, title string) error {
		return shortcuts.ExportLaunch(ctx, out, title, launchURL)
	})
}

func (m *Model) exportShortcut(topic, defaultName string, export func(context.Context, string, string) error) {
	if m.win == nil {
		return
	}
	m.mu.Lock()
	if m.shortcutBusy {
		m.mu.Unlock()
		return
	}
	m.shortcutBusy = true
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
		if m.shortcutResults == nil {
			m.shortcutResults = make(map[string]shortcutResult)
		}
		if err != nil {
			m.shortcutResults[topic] = shortcutResult{err: err.Error()}
		} else if out != "" {
			m.shortcutResults[topic] = shortcutResult{path: out}
		}
		m.mu.Unlock()
		mygo.RunOnMain(func() { win.Invalidate() })
	}()
}
