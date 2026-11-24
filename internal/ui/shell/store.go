package shell

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"koiside/internal/appstore"
	"koiside/internal/installer"
	"koiside/locales"
)

var storeRegionPresets = []string{"US", "CN", "JP", "HK", "TW", "GB", "SG"}

func (m *Model) storeView(c *ui.Context, msg locales.Messages, compact bool) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.StoreTitle()).FontSize(26).Bold()
		ui.Text(c, msg.StoreSubtitle()).TextColor(t.TextMuted)
	})

	mgr := m.services.Accounts
	storeSess := mgr.Store()

	m.mu.Lock()
	searching := m.storeSearching
	searchErr := m.storeSearchErr
	results := append([]appstore.Software(nil), m.storeResults...)
	selIdx := m.storeSelected
	narrowDetail := m.storeNarrowDetail
	m.mu.Unlock()

	// Compact Store account status bar
	insetGroup(c, "store-account-banner", func() {
		ui.Row(c).FillWidth().Padding(10, 14).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, phAccount).Width(18).Height(18).TextColor(accentInk(t))
			if storeSess.SignedIn() {
				ui.Column(c).Grow(1).MinWidth(0).Gap(1).Children(func() {
					ui.Text(c.Key("store-active-email"), msg.StoreAccountSignedIn(storeSess.Email())).Bold().FontSize(12).SingleLine()
					country := storeSess.CountryCode()
					if country == "" {
						country = "—"
					}
					monoText(c, msg.StoreAccountRegion(country, storeSess.StoreFront())).FontSize(11).TextColor(t.TextMuted).SingleLine()
				})
				if uiBtn(c, "store-switch-account-link", msg.StoreAccountSwitchBtn()).Clicked() {
					m.section = "账号"
				}
			} else {
				ui.Column(c).Grow(1).MinWidth(0).Gap(1).Children(func() {
					ui.Text(c, msg.StoreAccountNeedTitle()).Bold().FontSize(12).SingleLine()
					ui.Text(c, msg.StoreAccountNeedDesc()).FontSize(11).TextColor(t.TextMuted).SingleLine()
				})
				if uiBtn(c, "store-goto-account", msg.StoreAccountOpenBtn()).Clicked() {
					m.section = "账号"
				}
			}
		})
	})

	// Region selector + search bar (hidden when drilled into compact detail view)
	if !(compact && narrowDetail) {
		if m.storeCountry == "" {
			if cc := storeSess.CountryCode(); cc != "" {
				m.storeCountry = cc
			} else {
				m.storeCountry = "US"
			}
		}

		surfaceCard(c, "store-search-card").Padding(12, 14).Gap(8).Children(func() {
			ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
				input := ui.TextInput(c.Key("store-search-input"), &m.storeQuery).
					Placeholder(msg.StoreSearchPlaceholder()).Grow(1).Label(msg.StoreSearchBtn())
				trySearch := input.Submitted()

				sBtn := uiPrimaryBtn(c, "store-search-btn", msg.StoreSearchBtn())
				if searching || strings.TrimSpace(m.storeQuery) == "" {
					sBtn.Disabled(true)
				}
				if sBtn.Clicked() {
					trySearch = true
				}
				if trySearch && !searching && strings.TrimSpace(m.storeQuery) != "" {
					m.searchAppStore()
				}
			})

			ui.Row(c).FillWidth().Gap(6).Wrap().AlignItems(ui.Center).Children(func() {
				ui.Text(c, msg.StoreCountryLabel()).FontSize(12).TextColor(t.TextMuted)
				for _, cc := range storeRegionPresets {
					cc := cc
					selected := strings.EqualFold(m.storeCountry, cc)
					btn := ui.ButtonBase(c.Key("store-cc-"+cc)).Padding(3, 9).Radius(6).Label(cc).
						Cursor(ui.CursorPointer).Transition(colorTransition)
					if selected {
						btn.Background(t.Selection).Border(1, accentInk(t).Alpha(0.55))
					} else {
						btn.Background(t.Background).Border(1, t.Border)
						if btn.Hovered() {
							btn.Background(t.SurfaceHover)
						}
					}
					applyPressPose(btn, 0.96)
					btn.Children(func() {
						txt := ui.Text(c, cc).FontSize(11)
						if selected {
							txt.Bold().TextColor(accentInk(t))
						}
					})
					if btn.Clicked() {
						m.storeCountry = cc
					}
				}
			})
		})
	}

	if searching {
		ui.Row(c).FillWidth().Padding(14, 16).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Spinner(c).Label(msg.StoreSearching())
			ui.Text(c, msg.StoreSearching()).FontSize(13).TextColor(accentInk(t))
		})
		return
	}
	if searchErr != "" {
		ui.Text(c, friendlyError(msg, searchErr)).FontSize(12).TextColor(ui.Hex("#EF4444"))
	}

	if len(results) == 0 {
		if searchErr == "" {
			surfaceCard(c, "store-empty-card").Padding(24, 22).AlignItems(ui.Center).Gap(8).Children(func() {
				ui.Image(c, phMagnifyingGlassDuotone).Width(42).Height(42).TextColor(t.TextMuted)
				ui.Text(c, msg.StoreSearchEmpty()).FontSize(12).TextColor(t.TextMuted)
			})
		}
		return
	}

	if selIdx < 0 || selIdx >= len(results) {
		selIdx = 0
	}
	selectedApp := results[selIdx]

	if compact {
		if narrowDetail {
			m.storeDetailCard(c, msg, selectedApp, storeSess.SignedIn())
			return
		}
		m.storeResultsList(c, results, selIdx, true, 0)
		return
	}

	winW, winH := c.Size()
	listWidth := float32(264)
	if winW > 0 && winW < mediumWidth {
		listWidth = 224
	}
	listMaxH := float32(360)
	if winH > 0 {
		avail := winH - 270
		if avail < 220 {
			avail = 220
		} else if avail > 540 {
			avail = 540
		}
		listMaxH = avail
	}

	ui.Row(c).FillWidth().Gap(16).AlignItems(ui.Start).Children(func() {
		ui.Column(c).Width(listWidth).Shrink(0).Children(func() {
			m.storeResultsList(c, results, selIdx, false, listMaxH)
		})
		ui.Column(c).Grow(1).MinWidth(0).Children(func() {
			m.storeDetailCard(c, msg, selectedApp, storeSess.SignedIn())
		})
	})
}
func (m *Model) storeResultsList(c *ui.Context, results []appstore.Software, selIdx int, compact bool, maxHeight float32) {
	t := c.Theme()
	insetGroup(c, "store-results-group", func() {
		renderRows := func() {
			for i, sw := range results {
				i, sw := i, sw
				if i > 0 {
					ui.Divider(c)
				}
				selected := i == selIdx
				bg := t.Surface
				if selected {
					bg = t.Selection
				}
				row := ui.ButtonBase(c.Key(fmt.Sprintf("store-res-%d", i))).FillWidth().Padding(10, 12).
					Background(bg).Label(sw.Name).Cursor(ui.CursorPointer).Transition(colorTransition)
				if !selected && row.Hovered() {
					row.Background(t.SurfaceHover)
				}
				applyPressPose(row, 0.992)
				row.Children(func() {
					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Column(c).Grow(1).MinWidth(0).Gap(2).Children(func() {
							ui.Row(c).FillWidth().Gap(6).AlignItems(ui.Center).Children(func() {
								nameTxt := ui.Text(c, sw.Name).Bold().FontSize(13).SingleLine().Grow(1)
								if selected {
									nameTxt.TextColor(accentInk(t))
								}
								if sw.FormattedPrice != "" {
									ui.Row(c).Shrink(0).Padding(1, 6).Radius(5).Background(t.Background).Children(func() {
										ui.Text(c, sw.FormattedPrice).FontSize(10).TextColor(t.TextMuted).SingleLine()
									})
								}
							})
							meta := "v" + sw.Version
							if sw.FileSizeBytes > 0 {
								meta += " · " + formatBytes(sw.FileSizeBytes)
							}
							if sw.BundleID != "" {
								meta += " · " + sw.BundleID
							}
							monoText(c, meta).FontSize(11).TextColor(t.TextMuted).SingleLine()
						})
						if selected {
							ui.Icon(c, phCaretRight).Width(13).Height(13).TextColor(accentInk(t))
						}
					})
				})
				if row.Clicked() {
					m.mu.Lock()
					m.storeSelected = i
					m.storeVersions = nil
					m.storeSelectedVer = ""
					m.storeVersionsErr = ""
					m.storeDownloadErr = ""
					m.storeDownloadMsg = ""
					if compact {
						m.storeNarrowDetail = true
					}
					m.mu.Unlock()
				}
			}
		}

		if maxHeight > 0 {
			ui.Scroll(c.Key("store-results-scroll")).FillWidth().MaxHeight(maxHeight).Children(renderRows)
		} else {
			renderRows()
		}
	})
}

func (m *Model) storeDetailCard(c *ui.Context, msg locales.Messages, sw appstore.Software, signedIn bool) {
	t := c.Theme()

	m.mu.Lock()
	verLoading := m.storeVersionsBusy
	verErr := m.storeVersionsErr
	versions := append([]string(nil), m.storeVersions...)
	selVer := m.storeSelectedVer
	dlBusy := m.storeDownloadBusy
	dlPct := m.storeDownloadPct
	dlErr := m.storeDownloadErr
	dlMsg := m.storeDownloadMsg
	dlPath := m.storeDownloadedIPA
	m.mu.Unlock()
	surfaceCard(c, "store-detail-card").Padding(18, 20).Gap(14).Children(func() {
		// App identity header
		ui.Column(c).FillWidth().Gap(3).Children(func() {
			ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, sw.Name).FontSize(18).Bold().Grow(1)
				if sw.FormattedPrice != "" {
					ui.Row(c).Shrink(0).Padding(2, 8).Radius(6).Background(t.Selection).Children(func() {
						ui.Text(c, sw.FormattedPrice).FontSize(11).Bold().TextColor(accentInk(t)).SingleLine()
					})
				}
			})
			if sw.ArtistName != "" {
				ui.Text(c, sw.ArtistName).FontSize(12).TextColor(t.TextMuted).SingleLine()
			}
			monoText(c, sw.BundleID).FontSize(11).TextColor(t.TextMuted)
		})

		// Compact metadata facts strip (borderless pills to avoid nested-card clutter)
		var facts []string
		if sw.Version != "" {
			facts = append(facts, "v"+sw.Version)
		}
		if sw.FileSizeBytes > 0 {
			facts = append(facts, formatBytes(sw.FileSizeBytes))
		}
		if sw.MinimumOSVersion != "" {
			facts = append(facts, "iOS "+sw.MinimumOSVersion+"+")
		}
		if sw.PrimaryGenreName != "" {
			facts = append(facts, sw.PrimaryGenreName)
		}
		if len(facts) > 0 {
			ui.Row(c).FillWidth().Wrap().Gap(6).Children(func() {
				for idx, fact := range facts {
					ui.Row(c.Key(fmt.Sprintf("store-fact-%d", idx))).Padding(3, 8).Radius(6).
						Background(t.Background).Children(func() {
						monoText(c, fact).FontSize(11).TextColor(t.TextMuted).SingleLine()
					})
				}
			})
		}
		ui.Divider(c)

		// Actions row
		ui.Row(c).FillWidth().Wrap().Gap(8).AlignItems(ui.Center).Children(func() {
			instBtn := uiPrimaryBtn(c, "store-download-install", msg.StoreDownloadInstallBtn())
			if dlBusy || !signedIn || !m.hasConnectedDevice() {
				instBtn.Disabled(true)
			}
			if instBtn.Clicked() {
				m.downloadStoreIPA(sw, selVer, true)
			}

			dlBtn := uiBtn(c, "store-download-only", msg.StoreDownloadBtn())
			if dlBusy || !signedIn {
				dlBtn.Disabled(true)
			}
			if dlBtn.Clicked() {
				m.downloadStoreIPA(sw, selVer, false)
			}

			verBtn := uiBtn(c, "store-fetch-versions", msg.StoreVersionsBtn())
			if verLoading || !signedIn {
				verBtn.Disabled(true)
			}
			if verBtn.Clicked() {
				m.fetchStoreVersions(sw)
			}
		})

		if verLoading {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Spinner(c).Label(msg.StoreVersionsLoading())
				ui.Text(c, msg.StoreVersionsLoading()).FontSize(12).TextColor(t.TextMuted)
			})
		} else if verErr != "" {
			ui.Text(c, friendlyError(msg, verErr)).FontSize(12).TextColor(ui.Hex("#EF4444"))
		} else if len(versions) > 0 {
			ui.Row(c).FillWidth().Wrap().Gap(6).AlignItems(ui.Center).Children(func() {
				latestBtn := ui.ButtonBase(c.Key("store-ver-latest")).Padding(3, 8).Radius(6).
					Label(msg.StoreVersionLatest()).Cursor(ui.CursorPointer).Transition(colorTransition)
				if selVer == "" {
					latestBtn.Background(t.Selection).Border(1, accentInk(t).Alpha(0.55))
				} else {
					latestBtn.Background(t.Background).Border(1, t.Border)
					if latestBtn.Hovered() {
						latestBtn.Background(t.SurfaceHover)
					}
				}
				applyPressPose(latestBtn, 0.96)
				latestBtn.Children(func() { ui.Text(c, msg.StoreVersionLatest()).FontSize(11) })
				if latestBtn.Clicked() {
					m.mu.Lock()
					m.storeSelectedVer = ""
					m.mu.Unlock()
				}

				limit := len(versions)
				if limit > 8 {
					limit = 8
				}
				for _, vid := range versions[:limit] {
					vid := vid
					btn := ui.ButtonBase(c.Key("store-ver-"+vid)).Padding(3, 8).Radius(6).
						Label(vid).Cursor(ui.CursorPointer).Transition(colorTransition)
					if selVer == vid {
						btn.Background(t.Selection).Border(1, accentInk(t).Alpha(0.55))
					} else {
						btn.Background(t.Background).Border(1, t.Border)
						if btn.Hovered() {
							btn.Background(t.SurfaceHover)
						}
					}
					applyPressPose(btn, 0.96)
					btn.Children(func() { monoText(c, vid).FontSize(11) })
					if btn.Clicked() {
						m.mu.Lock()
						m.storeSelectedVer = vid
						m.mu.Unlock()
					}
				}
			})
		}

		if dlBusy {
			smoothProgress(c, "store-download-progress", float64(dlPct)/100.0, msg.StoreDownloading(dlPct)).FillWidth()
			ui.Text(c, msg.StoreDownloading(dlPct)).FontSize(12).TextColor(accentInk(t))
		}
		if dlErr != "" {
			ui.Text(c.Key("store-dl-err"), friendlyError(msg, dlErr)).FontSize(12).TextColor(ui.Hex("#EF4444")).
				Transition(feedbackBannerTransition)
		}
		if dlMsg != "" {
			ui.Row(c.Key("store-dl-done")).FillWidth().Gap(10).AlignItems(ui.Center).Transition(feedbackBannerTransition).Children(func() {
				ui.Text(c, dlMsg).FontSize(12).TextColor(ui.Hex("#10B981")).Grow(1)
				if dlPath != "" {
					if uiBtn(c, "store-open-workbench", msg.StoreInspectBtn()).Clicked() {
						m.OpenPaths([]string{dlPath})
					}
				}
			})
		}

		if desc := strings.TrimSpace(sw.Description); desc != "" {
			if len([]rune(desc)) > 240 {
				desc = string([]rune(desc)[:240]) + "…"
			}
			ui.Divider(c)
			ui.Text(c, desc).FontSize(12).TextColor(t.TextMuted)
		}
	})
}

func (m *Model) searchAppStore() {
	m.mu.Lock()
	if m.storeSearching {
		m.mu.Unlock()
		return
	}
	term := strings.TrimSpace(m.storeQuery)
	country := m.storeCountry
	m.storeSearching = true
	m.storeSearchErr = ""
	m.storeResults = nil
	m.storeSelected = 0
	m.storeNarrowDetail = false
	m.storeVersions = nil
	m.storeSelectedVer = ""
	m.mu.Unlock()

	go func() {
		res, err := m.services.Accounts.StoreClient().SearchApps(context.Background(), term, country, "software", 20)
		m.mu.Lock()
		m.storeSearching = false
		if err != nil {
			m.storeSearchErr = err.Error()
		} else {
			m.storeResults = res
		}
		m.mu.Unlock()
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) fetchStoreVersions(sw appstore.Software) {
	acc, ok := m.services.Accounts.Store().Account()
	if !ok {
		return
	}
	m.mu.Lock()
	if m.storeVersionsBusy {
		m.mu.Unlock()
		return
	}
	m.storeVersionsBusy = true
	m.storeVersionsErr = ""
	m.mu.Unlock()

	go func() {
		vers, cookies, err := m.services.Accounts.StoreClient().ListVersions(context.Background(), acc, sw)
		if len(cookies) > 0 {
			m.services.Accounts.UpdateStoreCookies(acc.Email, cookies)
		}
		m.mu.Lock()
		m.storeVersionsBusy = false
		if err != nil {
			m.storeVersionsErr = err.Error()
		} else {
			m.storeVersions = vers
		}
		m.mu.Unlock()
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) downloadStoreIPA(sw appstore.Software, versionID string, installAfter bool) {
	acc, ok := m.services.Accounts.Store().Account()
	if !ok {
		return
	}
	m.mu.Lock()
	if m.storeDownloadBusy {
		m.mu.Unlock()
		return
	}
	var devCopy = m.devices
	m.storeDownloadBusy = true
	m.storeDownloadPct = 5
	m.storeDownloadErr = ""
	m.storeDownloadMsg = ""
	m.storeDownloadedIPA = ""
	m.mu.Unlock()

	go func() {
		ctx := context.Background()
		client := m.services.Accounts.StoreClient()
		report := func(pct int) {
			m.mu.Lock()
			m.storeDownloadPct = pct
			m.mu.Unlock()
			if m.win != nil {
				mygo.RunOnMain(func() { m.win.Invalidate() })
			}
		}

		if sw.Price <= 0 {
			pRes, _ := client.PurchaseApp(ctx, acc, sw)
			if len(pRes.UpdatedCookies) > 0 {
				acc.Cookies = pRes.UpdatedCookies
				m.services.Accounts.UpdateStoreCookies(acc.Email, pRes.UpdatedCookies)
			}
		}
		report(15)

		dl, cookies, err := client.GetDownloadInfo(ctx, acc, sw, versionID)
		if len(cookies) > 0 {
			m.services.Accounts.UpdateStoreCookies(acc.Email, cookies)
		}
		if err != nil {
			m.finishStoreDownload("", "", err)
			return
		}

		cacheDir := filepath.Join(os.TempDir(), "koiside-downloads")
		if home, hErr := os.UserHomeDir(); hErr == nil {
			cacheDir = filepath.Join(home, "Library", "Application Support", "KoiSide", "downloads")
		}
		safeID := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(sw.BundleID)
		if safeID == "" {
			safeID = fmt.Sprintf("app_%d", sw.ID)
		}
		ver := dl.BundleShortVersionString
		if ver == "" {
			ver = sw.Version
		}
		dest := filepath.Join(cacheDir, fmt.Sprintf("%s_%s.ipa", safeID, ver))

		maxDL := 75
		if !installAfter {
			maxDL = 95
		}
		if err := appstore.DownloadFile(ctx, dl.DownloadURL, dest, appstore.DownloadOptions{
			OnProgress: func(p appstore.DownloadProgress) {
				if p.Total > 0 {
					report(15 + int(p.Downloaded*int64(maxDL-15)/p.Total))
				}
			},
		}); err != nil {
			m.finishStoreDownload("", "", err)
			return
		}

		if err := appstore.InjectSinfAndMetadata(dest, dl.Sinfs, dl.ITunesMetadata); err != nil {
			_ = os.Remove(dest)
			m.finishStoreDownload("", "", err)
			return
		}

		if installAfter && len(devCopy) > 0 {
			if err := installer.InstallStoreIPA(ctx, dest, devCopy[0], nil, func(pct int, _ string) {
				report(75 + pct/4)
			}); err != nil {
				m.finishStoreDownload(dest, "", err)
				return
			}
			m.detectDevices()
			m.finishStoreDownload(dest, m.msg(nil).StoreInstallDone(sw.BundleID), nil)
			return
		}

		m.finishStoreDownload(dest, m.msg(nil).StoreDownloadDone(dest), nil)
	}()
}

func (m *Model) finishStoreDownload(ipaPath, doneMsg string, err error) {
	m.mu.Lock()
	m.storeDownloadBusy = false
	m.storeDownloadedIPA = ipaPath
	if err != nil {
		m.storeDownloadErr = err.Error()
	} else {
		m.storeDownloadPct = 100
		m.storeDownloadMsg = doneMsg
	}
	m.mu.Unlock()
	if err != nil {
		m.addLog("store download/install failed: " + err.Error())
	} else {
		m.addLog("store download/install succeeded: " + ipaPath)
	}
	if m.win != nil {
		mygo.RunOnMain(func() { m.win.Invalidate() })
	}
}
