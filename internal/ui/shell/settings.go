package shell

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"koiside/locales"
)

func (m *Model) settingsView(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.SettingsTitle()).FontSize(26).Bold()
		ui.Text(c, msg.SettingsSubtitle()).TextColor(t.TextMuted)
	})

	ui.Text(c, msg.SettingsGeneral()).Bold().FontSize(13).TextColor(t.TextMuted)
	insetGroup(c, "settings-general-group", func() {
		themeIdx := 0
		switch m.appearanceMode() {
		case "light":
			themeIdx = 1
		case "dark":
			themeIdx = 2
		}
		ui.Row(c).FillWidth().Padding(14, 18).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Icon(c, phPalette).Width(18).Height(18).TextColor(accentInk(t))
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, msg.SettingsAppearance()).Bold().FontSize(14)
				ui.Text(c, msg.SettingsAppearanceDesc()).FontSize(12).TextColor(t.TextMuted)
			})
			seg := ui.Segmented(c.Key("appearance-seg"), &themeIdx,
				msg.SettingsThemeSystem(),
				msg.SettingsThemeLight(),
				msg.SettingsThemeDark(),
			).Cursor(ui.CursorPointer).Label(msg.SettingsAppearance())
			if seg.Changed() {
				modes := []string{"system", "light", "dark"}
				m.setAppearance(modes[themeIdx])
				c.Invalidate()
			}
		})

		ui.Divider(c)

		langIdx := 0
		switch m.currentLanguage() {
		case langZhHans:
			langIdx = 1
		case langEn:
			langIdx = 2
		}
		ui.Row(c).FillWidth().Padding(14, 18).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Icon(c, phGlobe).Width(18).Height(18).TextColor(accentInk(t))
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, msg.SettingsLanguage()).Bold().FontSize(14)
				ui.Text(c, msg.SettingsLanguageDesc()).FontSize(12).TextColor(t.TextMuted)
			})
			seg := ui.Segmented(c.Key("language-seg"), &langIdx,
				msg.SettingsLangSystem(),
				msg.SettingsLangZhHans(),
				msg.SettingsLangEn(),
			).Cursor(ui.CursorPointer).Label(msg.SettingsLanguage())
			if seg.Changed() {
				langs := []string{langSystem, langZhHans, langEn}
				m.SetLanguage(langs[langIdx])
				c.Invalidate()
			}
		})

		ui.Divider(c)

		ui.Row(c).FillWidth().Padding(14, 18).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Icon(c, phFolderOpen).Width(18).Height(18).TextColor(accentInk(t))
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, msg.SettingsFileLocations()).Bold().FontSize(14)
				ui.Text(c, msg.SettingsFileLocationsDesc()).FontSize(12).TextColor(t.TextMuted)
				monoText(c, msg.SettingsCacheDir(localDataDir())).FontSize(11).TextColor(t.TextMuted)
			})
		})

		ui.Divider(c)

		ui.Row(c).FillWidth().Padding(14, 18).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Icon(c, phAccount).Width(18).Height(18).TextColor(accentInk(t))
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, msg.AccountTitle()).Bold().FontSize(14)
				devSess := m.services.Accounts.Developer()
				if devSess.SignedIn() {
					ui.Text(c, msg.AccountStatusSignedIn(devSess.Email())).FontSize(12).TextColor(accentInk(t))
				} else {
					ui.Text(c, msg.AccountStatusSignedOut()).FontSize(12).TextColor(t.TextMuted)
				}
			})
			if uiBtn(c, "settings-open-account", msg.NavAccount()).Clicked() {
				m.section = "账号"
			}
		})
	})
	ui.Text(c, msg.SettingsPrivacy()).Bold().FontSize(13).TextColor(t.TextMuted)
	insetGroup(c, "settings-privacy-group", func() {
		ui.Row(c).FillWidth().Padding(14, 18).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Icon(c, phShieldCheck).Width(18).Height(18).TextColor(accentInk(t))
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Text(c, msg.SettingsPrivacy()).Bold().FontSize(14)
					ui.Text(c, msg.SettingsPrivacySummary()).FontSize(11).Bold().TextColor(accentInk(t))
				})
				ui.Text(c, msg.SettingsPrivacyDesc()).FontSize(12).TextColor(t.TextMuted)
			})
		})

		ui.Divider(c)

		m.mu.Lock()
		logsCopy := append([]string(nil), m.logs...)
		exportStatus := m.logExportMsg
		m.mu.Unlock()

		ui.Column(c).FillWidth().Padding(12, 18).Gap(6).Background(t.Background).Transition(heightTransition).Children(func() {
			ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Column(c).Grow(1).Children(func() {
					ui.Collapsible(c.Key("logs-collapsible"), msg.SettingsLogsTitle(), &m.showLogs, func() {
						if len(logsCopy) == 0 {
							ui.Text(c, msg.SettingsLogsEmpty()).FontSize(11).TextColor(t.TextMuted)
						} else {
							start := 0
							if len(logsCopy) > 6 {
								start = len(logsCopy) - 6
							}
							for _, line := range logsCopy[start:] {
								monoText(c, line).FontSize(11).TextColor(t.TextMuted)
							}
						}
					}).Cursor(ui.CursorPointer)
				})
				if len(logsCopy) > 0 {
					if uiBtn(c, "export-logs", msg.SettingsExportLogs()).Clicked() {
						m.exportLogs()
					}
					if uiBtn(c, "clear-logs", msg.SettingsClearLogs()).Clicked() {
						m.mu.Lock()
						m.logs = nil
						m.logExportMsg = ""
						m.mu.Unlock()
					}
				}
			})
			if exportStatus != "" {
				monoText(c.Key("logs-export-status"), exportStatus).FontSize(11).TextColor(accentInk(t))
			}
		})
	})

	ui.Text(c, msg.SettingsSupport()).Bold().FontSize(13).TextColor(t.TextMuted)
	insetGroup(c, "settings-support-group", func() {
		ui.Row(c).FillWidth().Padding(14, 18).AlignItems(ui.Center).Gap(12).Children(func() {
			ui.Icon(c, phQuestion).Width(18).Height(18).TextColor(accentInk(t))
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, msg.SettingsSupport()).Bold().FontSize(14)
				ui.Text(c, msg.SettingsSupportDesc()).FontSize(12).TextColor(t.TextMuted)
			})
			if uiBtn(c, "restart-onboarding", msg.GuideRestart()).Clicked() {
				m.guideStep = 1
				m.section = "引导"
			}
		})
		ui.Divider(c)
		ui.Row(c).FillWidth().Padding(14, 18).Gap(12).AlignItems(ui.Center).
			Background(brandWarmSurface(t)).Children(func() {
			ui.Image(c, brandLogo).Size(36, 36).Fit(ui.Contain)
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, msg.SettingsAbout()).Bold().FontSize(14)
				ui.Text(c, msg.SettingsAboutDesc()).FontSize(12).TextColor(t.TextMuted)
			})
		})
	})
}

// ExportLogsTo writes the current sanitized diagnostic log buffer to path.
func (m *Model) ExportLogsTo(path string) error {
	m.mu.Lock()
	lines := append([]string(nil), m.logs...)
	m.mu.Unlock()
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}
	exportedMsg := m.msg(nil).SettingsLogsExported(path)
	m.mu.Lock()
	m.logExportMsg = exportedMsg
	m.mu.Unlock()
	if m.win != nil {
		m.win.Invalidate()
	}
	return nil
}

func (m *Model) exportLogs() {
	if m.win == nil {
		return
	}
	win := m.win
	title := m.msg(nil).SettingsExportLogs()
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent:      win,
			Title:       title,
			DefaultPath: "koiside-logs.txt",
			Filters:     []mygo.FileFilter{{Name: "Log", Extensions: []string{"txt", "log"}}},
		})
		if err != nil || path == "" {
			return
		}
		_ = m.ExportLogsTo(path)
	}()
}

func localDataDir() string {
	if p, err := mygo.App.Path(mygo.PathUserData); err == nil && strings.TrimSpace(p) != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "koiside")
	}
	return filepath.Join(home, "Library", "Application Support", "KoiSide")
}
