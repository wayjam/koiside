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

func (m *Model) storeView(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.StoreTitle()).FontSize(26).Bold()
		ui.Text(c, msg.StoreSubtitle()).TextColor(t.TextMuted)
	})

	mgr := m.services.Accounts
	storeSess := mgr.Store()

	// Active Store account banner
	insetGroup(c, "store-account-banner", func() {
		ui.Row(c).FillWidth().Padding(14, 18).Gap(12).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, phAccount).Width(20).Height(20).TextColor(accentInk(t))
			if storeSess.SignedIn() {
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c.Key("store-active-email"), msg.StoreAccountSignedIn(storeSess.Email())).Bold().FontSize(13)
					country := storeSess.CountryCode()
					if country == "" {
						country = "—"
					}
					monoText(c, msg.StoreAccountRegion(country, storeSess.StoreFront())).FontSize(11).TextColor(t.TextMuted)
				})
			} else {
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.StoreAccountNeedTitle()).Bold().FontSize(13)
					ui.Text(c, msg.StoreAccountNeedDesc()).FontSize(11).TextColor(t.TextMuted)
				})
				if uiBtn(c, "store-goto-account", msg.StoreAccountOpenBtn()).Clicked() {
					m.section = "账号"
				}
			}
		})
	})

	// Region selector + search bar
	if m.storeCountry == "" {
		if cc := storeSess.CountryCode(); cc != "" {
			m.storeCountry = cc
		} else {
			m.storeCountry = "US"
		}
	}

	surfaceCard(c, "store-search-card").Padding(14, 16).Gap(10).Children(func() {
		ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
			input := ui.TextInput(c.Key("store-search-input"), &m.storeQuery).
				Placeholder(msg.StoreSearchPlaceholder()).Grow(1).Label(msg.StoreSearchBtn())
			trySearch := input.Submitted()

			m.mu.Lock()
			searching := m.storeSearching
			m.mu.Unlock()

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
				btn := ui.ButtonBase(c.Key("store-cc-"+cc)).Padding(4, 9).Radius(6).Label(cc).Cursor(ui.CursorPointer)
				if selected {
					btn.Background(t.Selection).Border(1, accentInk(t).Alpha(0.55))
				} else {
					btn.Background(t.Background).Border(1, t.Border)
				}
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

	m.mu.Lock()
	searching := m.storeSearching
	searchErr := m.storeSearchErr
	results := append([]appstore.Software(nil), m.storeResults...)
	selIdx := m.storeSelected
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

	if searching {
		ui.Row(c).FillWidth().Padding(14, 16).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Spinner(c).Label(msg.StoreSearching())
			ui.Text(c, msg.StoreSearching()).FontSize(13).TextColor(accentInk(t))
		})
	} else if searchErr != "" {
		ui.Text(c, friendlyError(msg, searchErr)).FontSize(12).TextColor(ui.Hex("#EF4444"))
	}

	if len(results) == 0 && !searching && searchErr == "" {
		surfaceCard(c, "store-empty-card").Padding(20, 22).AlignItems(ui.Center).Gap(8).Children(func() {
			ui.Image(c, phMagnifyingGlassDuotone).Width(42).Height(42).TextColor(t.TextMuted)
			ui.Text(c, msg.StoreSearchEmpty()).FontSize(12).TextColor(t.TextMuted)
		})
		return
	}

	if len(results) > 0 {
		insetGroup(c, "store-results-group", func() {
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
				row := ui.ButtonBase(c.Key(fmt.Sprintf("store-res-%d", i))).FillWidth().Padding(12, 16).
					Background(bg).Label(sw.Name).Cursor(ui.CursorPointer)
				row.Children(func() {
					ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
						ui.Column(c).Grow(1).Gap(2).Children(func() {
							ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
								ui.Text(c, sw.Name).Bold().FontSize(13)
								if sw.FormattedPrice != "" {
									ui.Row(c).Padding(1, 6).Radius(5).Background(t.Background).Children(func() {
										ui.Text(c, sw.FormattedPrice).FontSize(10).TextColor(t.TextMuted)
									})
								}
							})
							meta := fmt.Sprintf("%s · v%s", sw.BundleID, sw.Version)
							if sw.FileSizeBytes > 0 {
								meta += " · " + formatBytes(sw.FileSizeBytes)
							}
							monoText(c, meta).FontSize(11).TextColor(t.TextMuted)
						})
						if selected {
							ui.Icon(c, phCaretRight).Width(14).Height(14).TextColor(accentInk(t))
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
					m.mu.Unlock()
				}
			}
		})
	}

	if selIdx >= 0 && selIdx < len(results) {
		sw := results[selIdx]
		surfaceCard(c, "store-detail-card").Padding(16, 18).Gap(12).Children(func() {
			ui.Column(c).FillWidth().Gap(2).Children(func() {
				ui.Text(c, sw.Name).FontSize(17).Bold()
				monoText(c, fmt.Sprintf("%s · v%s · %s", sw.BundleID, sw.Version, sw.ArtistName)).FontSize(12).TextColor(t.TextMuted)
			})

			ui.Row(c).FillWidth().Wrap().Gap(8).AlignItems(ui.Center).Children(func() {
				verBtn := uiBtn(c, "store-fetch-versions", msg.StoreVersionsBtn())
				if verLoading || !storeSess.SignedIn() {
					verBtn.Disabled(true)
				}
				if verBtn.Clicked() {
					m.fetchStoreVersions(sw)
				}

				dlBtn := uiBtn(c, "store-download-only", msg.StoreDownloadBtn())
				if dlBusy || !storeSess.SignedIn() {
					dlBtn.Disabled(true)
				}
				if dlBtn.Clicked() {
					m.downloadStoreIPA(sw, selVer, false)
				}

				instBtn := uiPrimaryBtn(c, "store-download-install", msg.StoreDownloadInstallBtn())
				if dlBusy || !storeSess.SignedIn() || !m.hasConnectedDevice() {
					instBtn.Disabled(true)
				}
				if instBtn.Clicked() {
					m.downloadStoreIPA(sw, selVer, true)
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
					latestBtn := ui.ButtonBase(c.Key("store-ver-latest")).Padding(3, 8).Radius(6).Label(msg.StoreVersionLatest()).Cursor(ui.CursorPointer)
					if selVer == "" {
						latestBtn.Background(t.Selection).Border(1, accentInk(t).Alpha(0.55))
					} else {
						latestBtn.Background(t.Background).Border(1, t.Border)
					}
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
						btn := ui.ButtonBase(c.Key("store-ver-"+vid)).Padding(3, 8).Radius(6).Label(vid).Cursor(ui.CursorPointer)
						if selVer == vid {
							btn.Background(t.Selection).Border(1, accentInk(t).Alpha(0.55))
						} else {
							btn.Background(t.Background).Border(1, t.Border)
						}
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
				ui.Progress(c, float64(dlPct)/100.0).FillWidth().Label(msg.StoreDownloading(dlPct))
				ui.Text(c, msg.StoreDownloading(dlPct)).FontSize(12).TextColor(accentInk(t))
			}
			if dlErr != "" {
				ui.Text(c, friendlyError(msg, dlErr)).FontSize(12).TextColor(ui.Hex("#EF4444"))
			}
			if dlMsg != "" {
				ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Text(c, dlMsg).FontSize(12).TextColor(ui.Hex("#10B981")).Grow(1)
					if dlPath != "" {
						if uiBtn(c, "store-open-workbench", msg.StoreInspectBtn()).Clicked() {
							m.OpenPaths([]string{dlPath})
						}
					}
				})
			}
		})
	}
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
