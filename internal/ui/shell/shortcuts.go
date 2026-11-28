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
	path           string
	err            string
	button         string
	confirmedUntil time.Time
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
					rowCaret(c, row, 14)
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
		helpDisclosure(c, "shortcut-refresh-error", msg.HelpGuideRefreshHelp(), &m.shortcutTroubleshooting, func() {
			ui.Text(c, msg.HelpGuideRefreshSession()).FontSize(13)
			m.helpRecoveryLink(c, msg)
		})
		helpDisclosure(c, "shortcut-automation", msg.HelpGuideSchedule(), &m.shortcutSchedule, func() {
			for _, action := range strings.Split(msg.HelpGuideScheduleSteps(), "\n") {
				ui.Text(c, action).FontSize(13)
			}
		})
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
	standalone, lc, embedded, busy := m.sideStoreApp, m.lcApp, m.sideStoreEmbedded, m.shortcutExporting != ""
	m.mu.Unlock()
	ui.Text(c, msg.HelpGuideExportRefresh()).FontSize(13)
	ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
		add := func(app *device.InstalledApp, name, button, key string) {
			if app == nil || app.TeamID == "" {
				return
			}
			if m.shortcutExportButton(c, msg, helpShortcutRefresh, key, button, busy).Clicked() {
				m.exportShortcut(helpShortcutRefresh, key, msg.ShortcutsRefreshTitle()+" - "+name, func(ctx context.Context, out, title string) error {
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
	guests, busy := m.lcApps, m.shortcutExporting != ""
	m.mu.Unlock()
	if m.lcContainerPick == nil {
		m.lcContainerPick = map[string]string{}
	}
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
				ui.Column(c).Grow(1).MinWidth(0).Gap(3).Children(func() {
					ui.Text(c, name).Bold().FontSize(13)
					monoText(c, app.Folder).FontSize(11).TextColor(c.Theme().TextMuted)
					if app.InfoKnown {
						ui.Row(c).Wrap().Gap(8).AlignItems(ui.Center).Children(func() {
							sharedColor := ui.Hex("#F59E0B")
							if app.Shared {
								sharedColor = successInk(c.Theme())
							}
							ui.Text(c.Key("lc-shared-"+app.Folder), lcSharedLabel(msg, app.Shared)).
								FontSize(10).Bold().TextColor(sharedColor)
							ui.Text(c.Key("lc-multi-"+app.Folder), lcMultitaskLabel(msg, app.Multitask)).
								FontSize(10).Bold().TextColor(lcMultitaskColor(c.Theme(), app.Multitask))
						})
					} else {
						ui.Text(c.Key("lc-info-"+app.Folder), msg.LcGuestInfoUnknown()).
							FontSize(10).TextColor(c.Theme().TextMuted)
					}
					if len(app.Containers) > 1 {
						labels := make([]string, len(app.Containers))
						for i, container := range app.Containers {
							labels[i] = container.Name
							if labels[i] == "" {
								labels[i] = container.FolderName
							}
						}
						pick := m.lcContainerIndex(app)
						seg := ui.Segmented(c.Key("lc-container-"+app.Folder), &pick, labels...).
							Cursor(ui.CursorPointer).Label(msg.LcGuestContainer())
						if seg.Changed() {
							m.lcContainerPick[app.Folder] = app.Containers[pick].FolderName
						}
					}
				})
				key := "shortcut-launch-" + app.Folder
				if m.shortcutExportButton(c, msg, helpShortcutLaunch, key, msg.ShortcutsExport(), busy).Clicked() {
					m.exportLaunchShortcut(key, name, shortcuts.LaunchURL(m.lcLaunchTarget(app)))
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
		const key = "shortcut-launch-export"
		if m.shortcutExportButton(c, msg, helpShortcutLaunch, key, msg.ShortcutsExport(), busy || !valid).Clicked() {
			m.exportLaunchShortcut(key, msg.ShortcutsLaunchTitle(), launchURL)
		}
		paste, confirmed := shortcutActionButton(c, "shortcut-paste", msg.HelpGuidePaste(), msg.HelpGuidePasted(), phImport, false, busy, false, time.Time{})
		if paste.Clicked() {
			if pasted := strings.TrimSpace(c.ReadClipboard()); pasted != "" {
				m.shortcutLaunchURL = pasted
				confirmShortcutAction(c, confirmed, msg.HelpGuidePasted())
			}
		}
	})
}

func (m *Model) lcLaunchTarget(app device.LiveContainerApp) shortcuts.LaunchTarget {
	target := shortcuts.LaunchTarget{Folder: app.Folder}
	if picked := m.lcContainerPick[app.Folder]; picked != "" && picked != app.DataUUID {
		target.ContainerFolder = picked
	}
	return target
}

func (m *Model) lcContainerIndex(app device.LiveContainerApp) int {
	picked := m.lcContainerPick[app.Folder]
	if picked == "" {
		picked = app.DataUUID
	}
	for i, container := range app.Containers {
		if container.FolderName == picked {
			return i
		}
	}
	return 0
}

func lcSharedLabel(msg locales.Messages, shared bool) string {
	if shared {
		return msg.LcGuestShared()
	}
	return msg.LcGuestNotShared()
}

func lcMultitaskLabel(msg locales.Messages, state int) string {
	switch state {
	case 2:
		return msg.LcGuestMultitaskOn()
	case 1:
		return msg.LcGuestMultitaskOff()
	default:
		return msg.LcGuestMultitaskDefault()
	}
}

func lcMultitaskColor(t *ui.Theme, state int) ui.Color {
	switch state {
	case 2:
		return successInk(t)
	case 1:
		return ui.Hex("#F59E0B")
	default:
		return t.TextMuted
	}
}

func (m *Model) helpFileActions(c *ui.Context, msg locales.Messages, path, key string) {
	ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
		airdrop, sent := shortcutActionButton(c, "help-airdrop-"+key, msg.HelpGuideAirDrop(), msg.HelpGuideAirDropOpened(), phPaperPlaneTiltDuotone, true, false, false, time.Time{})
		if airdrop.Clicked() {
			*sent = time.Time{}
			m.helpFileError = ""
			if _, err := os.Stat(path); err != nil {
				m.helpFileError = msg.HelpGuideFileMissing()
			} else if !openAirDrop(path) {
				m.helpFileError = msg.HelpGuideAirDropUnavailable()
			} else {
				confirmShortcutAction(c, sent, msg.HelpGuideAirDropOpened())
			}
		}
		finder, revealed := shortcutActionButton(c, "help-finder-"+key, msg.HelpGuideFinder(), msg.HelpGuideFinderOpened(), phFolderOpen, false, false, false, time.Time{})
		if finder.Clicked() {
			*revealed = time.Time{}
			m.helpFileError = ""
			if _, err := os.Stat(path); err != nil {
				m.helpFileError = msg.HelpGuideFileMissing()
			} else if m.win != nil {
				mygo.Shell.ShowItemInFolder(path)
				confirmShortcutAction(c, revealed, msg.HelpGuideFinderOpened())
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
	return m.shortcutExporting == "" && m.shortcutResults[topic].path != ""
}

func (m *Model) shortcutExportStatus(c *ui.Context, msg locales.Messages, res shortcutResult) {
	m.mu.Lock()
	busy := m.shortcutExporting != ""
	m.mu.Unlock()
	if busy || res.path != "" {
		return
	}
	text, icon := msg.HelpGuideExportFirst(), phInfo
	if res.err != "" {
		text, icon = msg.ShortcutsSaveFailed(res.err), phXCircleFill
	}
	ui.Row(c).FillWidth().Gap(7).AlignItems(ui.Center).Children(func() {
		ui.Icon(c, icon).Size(16, 16).TextColor(accentInk(c.Theme())).AccessHidden(true)
		ui.Text(c.Key("shortcut-status"), text).Role(ui.RoleStatus).Grow(1).MinWidth(0).FontSize(13)
	})
}

func (m *Model) shortcutExportButton(c *ui.Context, msg locales.Messages, topic, key, label string, disabled bool) ui.Element {
	m.mu.Lock()
	result := m.shortcutResults[topic]
	saving := m.shortcutExporting == key
	m.mu.Unlock()
	var until time.Time
	if result.button == key {
		until = result.confirmedUntil
	}
	if saving {
		label = msg.ShortcutsSaving()
	}
	btn, lastConfirmation := shortcutActionButton(c, key, label, msg.HelpGuideExportDone(), phExport, true, disabled || saving, saving, until)
	if until.After(*lastConfirmation) {
		*lastConfirmation = until
		if until.After(c.Now()) {
			c.Announce(msg.ShortcutsSaved(filepath.Base(result.path)))
		}
	}
	return btn
}

func shortcutActionButton(c *ui.Context, key, label, success string, icon *ui.SVG, primary, disabled, busy bool, until time.Time) (ui.Element, *time.Time) {
	btn := uiBtn
	if primary {
		btn = uiPrimaryBtn
	}
	el := btn(c, key, "").Disabled(disabled).Busy(busy)
	local := ui.Local(el, "confirmation", func() time.Time { return time.Time{} })
	if local.After(until) {
		until = *local
	}
	confirmed := !busy && until.After(c.Now())
	if confirmed {
		c.After(until.Sub(c.Now()))
		label = success
	}
	el.Label(label).Children(func() {
		if confirmed {
			ui.Icon(c.Key("confirmed"), phCheckCircleFill).Size(15, 15).Transition(stepCheckEnterTransition)
		} else if busy && !c.Preferences().ReduceMotion {
			ui.Spinner(c).Size(15, 15).AccessHidden(true)
		} else {
			glyph := ui.Icon(c.Key("action"), icon).Size(15, 15)
			if icon == phPaperPlaneTiltDuotone {
				glyph.Transition(ui.ElementTransition{ExitDuration: 125 * time.Millisecond, Exit: &ui.Motion{X: 3, Y: -3, Rotate: -12}})
			}
		}
		ui.Text(c, label).SingleLine()
	})
	return el, local
}

const shortcutConfirmationDuration = 1500 * time.Millisecond

func confirmShortcutAction(c *ui.Context, until *time.Time, label string) {
	*until = c.Now().Add(shortcutConfirmationDuration)
	c.Announce(label)
	c.Invalidate()
}

func (m *Model) exportLaunchShortcut(key, name, launchURL string) {
	m.exportShortcut(helpShortcutLaunch, key, name, func(ctx context.Context, out, title string) error {
		return shortcuts.ExportLaunch(ctx, out, title, launchURL)
	})
}

func (m *Model) exportShortcut(topic, key, defaultName string, export func(context.Context, string, string) error) {
	if m.win == nil {
		return
	}
	m.mu.Lock()
	if m.shortcutExporting != "" {
		m.mu.Unlock()
		return
	}
	m.shortcutExporting = key
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
		m.shortcutExporting = ""
		if m.shortcutResults == nil {
			m.shortcutResults = make(map[string]shortcutResult)
		}
		if err != nil {
			m.shortcutResults[topic] = shortcutResult{err: err.Error()}
		} else if out != "" {
			m.shortcutResults[topic] = shortcutResult{path: out, button: key, confirmedUntil: time.Now().Add(shortcutConfirmationDuration)}
		}
		m.mu.Unlock()
		mygo.RunOnMain(func() { win.Invalidate() })
	}()
}
