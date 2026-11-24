package shell

import (
	"context"
	"fmt"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"koiside/internal/appleauth"
	"koiside/internal/devportal"
	"koiside/locales"
)

type loginVerification uint8

const (
	verifyDeveloper loginVerification = iota + 1
	verifyStore
)

const (
	accountTabDeveloper = 0
	accountTabStore     = 1
)

type accountTabStatus uint8

const (
	accountTabSignedOut accountTabStatus = iota
	accountTabSignedIn
	accountTabSigningIn
	accountTabRestoring
	accountTabVerify
)

// RestoreAccountSessions loads saved accounts without blocking the workspace.
func (m *Model) RestoreAccountSessions(ctx context.Context) {
	mgr, win := m.services.Accounts, m.win
	m.mu.Lock()
	m.developerRestoring, m.storeRestoring = true, true
	m.mu.Unlock()
	if win != nil {
		win.Invalidate()
	}

	restore := func(pending *bool, load func(context.Context) error) {
		_ = load(ctx)
		m.mu.Lock()
		*pending = false
		m.mu.Unlock()
		if win != nil {
			mygo.RunOnMain(func() { win.Invalidate() })
		}
	}
	go restore(&m.storeRestoring, mgr.RestoreStoreSession)
	go restore(&m.developerRestoring, mgr.RestoreDeveloperSession)
}

func (m *Model) accountView(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.AccountTitle()).FontSize(26).Bold()
		ui.Text(c, msg.AccountSubtitle()).TextColor(t.TextMuted)
	})

	mgr := m.services.Accounts
	devSess := mgr.Developer()
	storeSess := mgr.Store()
	m.mu.Lock()
	devBusy, devCode, devRestoring := m.loginBusy, m.twoFactorRespCh != nil, m.developerRestoring
	storeBusy, storeCode, storeRestoring := m.storeLoginBusy, m.store2FARespCh != nil, m.storeRestoring
	m.mu.Unlock()

	m.renderAccountRolesCard(c, msg)
	m.renderAccountTabs(c, msg,
		resolveAccountTabStatus(devSess.SignedIn(), devBusy, devRestoring, devCode),
		resolveAccountTabStatus(storeSess.SignedIn(), storeBusy, storeRestoring, storeCode),
	)

	switch m.accountTab {
	case accountTabStore:
		m.renderStoreAccountTab(c, msg)
	default:
		m.renderDeveloperAccountTab(c, msg)
	}
}

func resolveAccountTabStatus(signedIn, busy, restoring, awaitingCode bool) accountTabStatus {
	switch {
	case awaitingCode:
		return accountTabVerify
	case restoring:
		return accountTabRestoring
	case busy:
		return accountTabSigningIn
	case signedIn:
		return accountTabSignedIn
	default:
		return accountTabSignedOut
	}
}

func accountTabStatusVisual(t *ui.Theme, msg locales.Messages, st accountTabStatus, active bool) (label string, dotColor, textColor, badgeBg ui.Color) {
	switch st {
	case accountTabSignedIn:
		dotColor = ui.Hex("#10B981")
		if t.Dark {
			textColor = ui.Hex("#34D399")
			badgeBg = ui.Hex("#10B981").Alpha(0.16)
		} else {
			textColor = ui.Hex("#065F46")
			badgeBg = ui.Hex("#10B981").Alpha(0.14)
		}
		return msg.AccountTabStatusSignedIn(), dotColor, textColor, badgeBg
	case accountTabVerify:
		dotColor = ui.Hex("#F59E0B")
		if t.Dark {
			textColor = ui.Hex("#FBBF24")
			badgeBg = ui.Hex("#F59E0B").Alpha(0.16)
		} else {
			textColor = ui.Hex("#92400E")
			badgeBg = ui.Hex("#F59E0B").Alpha(0.16)
		}
		return msg.AccountTabStatusVerify(), dotColor, textColor, badgeBg
	case accountTabRestoring:
		ink := accentInk(t)
		return msg.AccountTabStatusRestoring(), ink, ink, t.Selection
	case accountTabSigningIn:
		ink := accentInk(t)
		return msg.AccountTabStatusSigningIn(), ink, ink, t.Selection
	default:
		dotColor = t.TextMuted.Alpha(0.45)
		textColor = t.TextMuted
		if active && !t.Dark {
			textColor = ui.Hex("#475569")
		}
		return msg.AccountTabStatusSignedOut(), dotColor, textColor, ui.Transparent
	}
}

func (m *Model) renderAccountRolesCard(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	winW, _ := c.Size()
	stackRoles := winW > 0 && winW < mediumWidth

	roleItem := func(key string, icon *ui.SVG, title, desc string) {
		ui.Row(c.Key(key)).Grow(1).MinWidth(0).Gap(12).AlignItems(ui.Start).Children(func() {
			ui.Row(c).Width(32).Height(32).Radius(8).Background(t.Selection).Shrink(0).Center().Children(func() {
				ui.Icon(c, icon).Width(16).Height(16).TextColor(accentInk(t))
			})
			ui.Column(c).Grow(1).MinWidth(0).Gap(3).Children(func() {
				ui.Text(c, title).Bold().FontSize(13)
				ui.Text(c, desc).FontSize(12).TextColor(t.TextMuted)
			})
		})
	}

	surfaceCard(c, "account-roles-card").Padding(14, 18).Children(func() {
		if stackRoles {
			ui.Column(c).FillWidth().Gap(12).Children(func() {
				roleItem("account-role-dev", phKey, msg.AccountRoleDevTitle(), msg.AccountRoleDevDesc())
				ui.Divider(c)
				roleItem("account-role-store", phImport, msg.AccountRoleStoreTitle(), msg.AccountRoleStoreDesc())
			})
		} else {
			ui.Row(c).FillWidth().Gap(16).AlignItems(ui.Stretch).Children(func() {
				roleItem("account-role-dev", phKey, msg.AccountRoleDevTitle(), msg.AccountRoleDevDesc())
				ui.Divider(c)
				roleItem("account-role-store", phImport, msg.AccountRoleStoreTitle(), msg.AccountRoleStoreDesc())
			})
		}
	})
}

func (m *Model) renderAccountTabs(c *ui.Context, msg locales.Messages, devStatus, storeStatus accountTabStatus) {
	t := c.Theme()
	winW, _ := c.Size()
	fillEqually := winW > 0 && winW < mediumWidth

	items := []struct {
		key    string
		title  string
		status accountTabStatus
	}{
		{key: "account-tab-dev", title: msg.AccountTabDeveloper(), status: devStatus},
		{key: "account-tab-store", title: msg.AccountTabStore(), status: storeStatus},
	}

	ui.Row(c.Key("account-tabs-row")).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
		parts := ui.SegmentedBase(c.Key("account-sub-tab"), &m.accountTab, len(items))
		parts.Track.AlignItems(ui.Stretch).Padding(t.Space(0.5)).Gap(t.Space(0.5)).
			Radius(t.Radius).Background(t.Surface).Border(1, t.Border).
			Label(msg.AccountTitle()).Children(func() {
			for i, item := range items {
				active := i == m.accountTab
				statusLabel, dotColor, textColor, badgeBg := accountTabStatusVisual(t, msg, item.status, active)
				seg := parts.Segment(i).Padding(6, 12).Radius(max(4, t.Radius-2)).Gap(8).
					Label(item.title).Description(statusLabel).
					Cursor(ui.CursorPointer).Transition(colorTransition)
				if active {
					shadowAlpha := float32(0.12)
					if t.Dark {
						shadowAlpha = 0.28
					}
					seg.Background(t.SurfacePressed).Shadow(0, 1, 2, 0, ui.RGBA(0, 0, 0, shadowAlpha))
				} else if seg.Hovered() {
					seg.Background(t.SurfaceHover)
				}
				applyPressPose(seg, 0.988)
				seg.Children(func() {
					dot := ui.Row(c.Key(item.key + "-dot")).Width(7).Height(7).Radius(3.5).Shrink(0)
					dot.Background(dot.AnimateColor("tab-dot", dotColor, motionStatusColorAnim))
					title := ui.Text(c, item.title).FontSize(13).SingleLine()
					if active {
						title.Bold().TextColor(t.Text)
					} else {
						title.TextColor(t.TextMuted)
					}
					badge := ui.Row(c.Key(item.key + "-status")).Padding(1, 7).Radius(999).Shrink(0)
					if badgeBg != ui.Transparent {
						badge.Background(badgeBg)
					}
					badge.Children(func() {
						stTxt := ui.Text(c, statusLabel).FontSize(11).TextColor(textColor).SingleLine()
						if item.status != accountTabSignedOut {
							stTxt.Bold()
						}
					})
				})
			}
		})
		if fillEqually {
			parts.Track.FillEqually()
		}
	})
}

func (m *Model) renderDeveloperAccountTab(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	mgr := m.services.Accounts
	devSess := mgr.Developer()
	m.mu.Lock()
	busy, awaitingCode := m.loginBusy, m.twoFactorRespCh != nil
	restoring := m.developerRestoring
	loginErr := m.loginErr
	m.mu.Unlock()

	if busy || awaitingCode || restoring {
		surfaceCard(c, "account-signin-card").Padding(18, 20).Gap(12).Children(func() {
			ui.Text(c, msg.AccountSignInTitle()).Bold().FontSize(16)
			if awaitingCode {
				m.loginVerificationRow(c, msg, "developer-verification", msg.Account2FATitle(), verifyDeveloper)
			} else if restoring {
				loginLoading(c, "developer-signin-status", msg.AccountRestoringSession())
			} else {
				loginLoading(c, "developer-signin-status", msg.AccountSigningIn())
			}
		})
	} else if devSess.SignedIn() {
		insetGroup(c, "account-signedin-group", func() {
			ui.Row(c).FillWidth().Padding(16, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Row(c).Width(40).Height(40).Radius(20).Background(t.Selection).Center().Children(func() {
					ui.Icon(c, phAccountFill).Width(24).Height(24).TextColor(accentInk(t))
				})
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c.Key("account-status-title"), msg.AccountStatusSignedIn(devSess.Email())).Role(ui.RoleStatus).Bold().FontSize(15)
					if name := devSess.FullName(); name != "" {
						ui.Text(c, name).FontSize(12).TextColor(t.TextMuted)
					}
					if team, ok := devSess.ActiveTeam(); ok {
						kind := msg.AccountTeamPaid()
						if team.IsFreePersonal() {
							kind = msg.AccountTeamFree()
						}
						monoText(c.Key("account-team-status"), fmt.Sprintf("%s · %s (%s)", msg.AccountTeamLabel(), team.Name, kind)).Role(ui.RoleStatus).FontSize(11).TextColor(accentInk(t))
					}
				})
				if uiBtn(c, "account-sign-out", msg.AccountSignOutBtn()).Clicked() {
					mgr.SignOutDeveloper()
					m.mu.Lock()
					m.portalCerts = nil
					m.portalCertErr = ""
					m.portalQuotaKnown = false
					m.mu.Unlock()
					m.addLog("developer account signed out")
				}
			})
		})

		insetGroup(c, "account-certs-group", func() {
			ui.Row(c).FillWidth().Padding(14, 18).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phKey).Width(18).Height(18).TextColor(accentInk(t))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.AccountCertsTitle()).Bold().FontSize(14)
					m.mu.Lock()
					quotaKnown := m.portalQuotaKnown
					avail := m.portalAppIDsAvail
					maxQ := m.portalAppIDsMax
					appIDs := append([]devportal.AppID(nil), m.portalAppIDs...)
					certsLoadedPre := m.portalCertsLoaded
					m.mu.Unlock()
					isFreeTeam := false
					if team, ok := devSess.ActiveTeam(); ok {
						isFreeTeam = team.IsFreePersonal()
					}
					if quotaKnown && isFreeTeam {
						ui.Text(c.Key("account-appid-quota"), msg.AccountAppIDQuotaFree(int(avail), int(maxQ))).Role(ui.RoleStatus).FontSize(11).TextColor(accentInk(t))
					} else if certsLoadedPre {
						monoText(c.Key("account-appid-quota"), msg.AccountAppIDQuotaPaid(len(appIDs))).Role(ui.RoleStatus).FontSize(11).TextColor(accentInk(t))
					}
				})
				refreshBtn := uiBtn(c, "account-load-certs", msg.AccountLoadCertsBtn())
				if m.certsLoading {
					refreshBtn.Disabled(true)
				}
				if refreshBtn.Clicked() {
					m.loadPortalCertsAndQuota()
				}
			})
			m.mu.Lock()
			certs := append([]devportal.DevelopmentCertificate(nil), m.portalCerts...)
			appIDs := append([]devportal.AppID(nil), m.portalAppIDs...)
			certErr := m.portalCertErr
			certsLoaded := m.portalCertsLoaded
			deletingID := m.appIDDeleting
			m.mu.Unlock()

			isFreeTeam := false
			if team, ok := devSess.ActiveTeam(); ok {
				isFreeTeam = team.IsFreePersonal()
			}

			if certErr != "" {
				ui.Divider(c)
				ui.Row(c).FillWidth().Padding(10, 18).Children(func() {
					ui.Text(c, friendlyError(msg, certErr)).FontSize(12).TextColor(ui.Hex("#EF4444"))
				})
			} else if !certsLoaded {
				ui.Row(c).FillWidth().Padding(12, 18).Children(func() {
					ui.Text(c, msg.AccountCertEmpty()).FontSize(12).TextColor(t.TextMuted)
				})
			} else {
				for idx, cert := range certs {
					cert := cert
					hasLocal := devportal.HasLocalRSAKeyForCert(devSess.Email(), cert, mgr.Storage())
					ui.Divider(c)
					ui.Row(c.Key(fmt.Sprintf("cert-row-%d", idx))).FillWidth().Padding(10, 18).Gap(10).AlignItems(ui.Center).Children(func() {
						ui.Column(c).Grow(1).Gap(3).Children(func() {
							ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
								ui.Text(c, valueOrUnknown(msg, cert.Name)).Bold().FontSize(12)
								if hasLocal {
									ui.Row(c).Padding(2, 7).Radius(6).Background(t.Selection).Children(func() {
										ui.Text(c, msg.AccountLocalKeyBadge()).FontSize(10).Bold().TextColor(accentInk(t))
									})
								}
							})
							meta := fmt.Sprintf("Serial: %s · Machine: %s", valueOrUnknown(msg, cert.SerialNumber), valueOrUnknown(msg, cert.MachineName))
							if !cert.Expiration.IsZero() {
								meta += " · " + msg.AccountCertExpires(cert.Expiration.Local().Format("2006-01-02"))
							}
							monoText(c, meta).FontSize(11).TextColor(t.TextMuted)
						})
						if cert.SerialNumber != "" {
							if uiBtn(c, fmt.Sprintf("revoke-cert-%d", idx), msg.AccountRevokeCertBtn()).Clicked() {
								cp := cert
								m.mu.Lock()
								m.pendingRevokeCert = &cp
								m.mu.Unlock()
							}
						}
					})
				}

				if len(appIDs) > 0 {
					ui.Divider(c)
					ui.Column(c).FillWidth().Padding(12, 18).Gap(6).Children(func() {
						ui.Text(c, msg.AccountAppIDsTitle()).Bold().FontSize(13)
						if isFreeTeam {
							ui.Text(c, msg.AccountAppIDFreeDeleteHint()).FontSize(11).TextColor(t.TextMuted)
						}
					})
					for idx, aid := range appIDs {
						aid := aid
						ui.Divider(c)
						ui.Row(c.Key(fmt.Sprintf("appid-row-%d", idx))).FillWidth().Padding(9, 18).Gap(10).AlignItems(ui.Center).Children(func() {
							ui.Column(c).Grow(1).Gap(2).Children(func() {
								ui.Text(c, valueOrUnknown(msg, aid.Name)).Bold().FontSize(12)
								sub := aid.Identifier
								if !aid.ExpirationDate.IsZero() {
									sub += " · " + msg.AccountAppIDExpires(aid.ExpirationDate.Local().Format("2006-01-02 15:04"))
								}
								monoText(c, sub).FontSize(11).TextColor(t.TextMuted)
							})
							if !isFreeTeam && aid.AppIDID != "" {
								delBtn := uiBtn(c, fmt.Sprintf("delete-appid-%d", idx), msg.AccountAppIDDeleteBtn())
								if deletingID == aid.AppIDID {
									delBtn.Disabled(true)
								}
								if delBtn.Clicked() {
									m.deletePortalAppID(aid.AppIDID)
								}
							}
						})
					}
				}
			}
		})
	} else {
		surfaceCard(c, "account-signin-card").Padding(18, 20).Gap(12).Children(func() {
			ui.Text(c, msg.AccountSignInTitle()).Bold().FontSize(16)
			ui.Text(c, msg.AccountEmailLabel()).FontSize(12).TextColor(t.TextMuted)
			ui.TextInput(c.Key("acc-email-input"), &m.loginEmail).
				Placeholder(msg.AccountEmailPlaceholder()).FillWidth().Label(msg.AccountEmailLabel())

			ui.Text(c, msg.AccountPasswordLabel()).FontSize(12).TextColor(t.TextMuted)
			ui.TextInput(c.Key("acc-password-input"), &m.loginPassword).
				Password().Placeholder(msg.AccountPasswordPlaceholder()).FillWidth().Label(msg.AccountPasswordLabel())

			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Switch(c.Key("acc-remember-switch"), &m.loginRemember).Cursor(ui.CursorPointer).Label(msg.AccountRememberPassword())
				ui.Column(c).Grow(1).Gap(1).Children(func() {
					ui.Text(c, msg.AccountRememberPassword()).FontSize(12).Bold()
					ui.Text(c, msg.AccountRememberHint()).FontSize(11).TextColor(t.TextMuted)
				})
			})

			if loginErr != "" {
				ui.Text(c.Key("acc-login-err"), friendlyError(msg, loginErr)).Role(ui.RoleStatus).FontSize(12).TextColor(ui.Hex("#EF4444"))
			}

			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
				btn := uiPrimaryBtn(c, "acc-sign-in-btn", msg.AccountSignInBtn())
				if strings.TrimSpace(m.loginEmail) == "" || m.loginPassword == "" {
					btn.Disabled(true)
				}
				if btn.Clicked() {
					m.startLogin(m.loginEmail, m.loginPassword, m.loginRemember, false)
				}
			})
		})

		if saved := mgr.SavedAccounts(); len(saved) > 0 {
			ui.Text(c, msg.AccountSavedAccountsTitle()).Bold().FontSize(13).TextColor(t.TextMuted)
			insetGroup(c, "account-saved-group", func() {
				for idx, em := range saved {
					em := em
					if idx > 0 {
						ui.Divider(c)
					}
					ui.Row(c.Key(fmt.Sprintf("saved-acc-%d", idx))).FillWidth().Padding(12, 18).Gap(10).AlignItems(ui.Center).Children(func() {
						ui.Icon(c, phAccount).Width(18).Height(18).TextColor(accentInk(t))
						monoText(c, em).FontSize(13).Grow(1)
						if uiBtn(c, fmt.Sprintf("saved-login-%d", idx), msg.AccountUseSavedBtn()).Clicked() {
							m.startLogin(em, "", false, true)
						}
						if uiBtn(c, fmt.Sprintf("saved-forget-%d", idx), msg.AccountForgetSavedBtn()).Clicked() {
							_ = mgr.ForgetSavedAccount(em)
						}
					})
				}
			})
		}
	}

	// Anisette v3 configuration (independent of login state)
	if m.anisetteInput == "" {
		m.anisetteInput = mgr.AnisetteURL()
	}
	insetGroup(c, "account-anisette-group", func() {
		ui.Column(c).FillWidth().Padding(16, 18).Gap(10).Children(func() {
			ui.Text(c, msg.AccountAnisetteTitle()).Bold().FontSize(14)
			ui.Text(c, msg.AccountAnisetteDesc()).FontSize(12).TextColor(t.TextMuted)
			ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
				ui.TextInput(c.Key("acc-anisette-url"), &m.anisetteInput).
					Placeholder(msg.AccountAnisetteURLPlaceholder()).Grow(1).Label(msg.AccountAnisetteTitle())
				if uiBtn(c, "acc-anisette-save", msg.AccountAnisetteSaveBtn()).Clicked() {
					mgr.SetAnisetteURL(m.anisetteInput)
					m.anisetteInput = mgr.AnisetteURL()
					m.addLog("anisette server updated")
				}
				if uiBtn(c, "acc-anisette-reset", msg.AccountAnisetteResetBtn()).Clicked() {
					_ = mgr.ResetAnisetteState(context.Background())
					m.anisetteNotice = msg.AccountAnisetteResetDone()
					m.addLog("anisette provisioning state reset")
				}
			})
			if m.anisetteNotice != "" {
				ui.Text(c, m.anisetteNotice).FontSize(11).TextColor(accentInk(t))
			}
			ui.Divider(c)
			ui.Text(c, msg.AccountStoreBoundaryNote()).FontSize(11).TextColor(t.TextMuted)
		})
	})
}

func loginLoading(c *ui.Context, key, label string) {
	ink := accentInk(c.Theme())
	ui.Row(c.Key(key)).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
		if !c.Preferences().ReduceMotion {
			ui.Spinner(c).Size(16, 16).TextColor(ink).AccessHidden(true)
		}
		ui.Text(c, label).Role(ui.RoleStatus).FontSize(12).TextColor(ink).Grow(1).MinWidth(0)
	})
}

func (m *Model) loginVerificationRow(c *ui.Context, msg locales.Messages, key, label string, kind loginVerification) {
	ui.Row(c.Key(key)).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Icon(c, phKey).Size(16, 16).Shrink(0).TextColor(accentInk(c.Theme()))
		ui.Text(c, label).Role(ui.RoleStatus).FontSize(12).Grow(1).MinWidth(0)
		if uiBtn(c, key+"-enter-code", msg.Account2FAOpen()).Description(label).Shrink(0).Clicked() {
			m.mu.Lock()
			m.loginVerification = kind
			m.mu.Unlock()
		}
	})
}

func (m *Model) backgroundLoginStatus(c *ui.Context, msg locales.Messages) {
	onDevTab := m.section == "账号" && m.accountTab == accountTabDeveloper
	onStoreTab := m.section == "账号" && m.accountTab == accountTabStore
	m.mu.Lock()
	developerBusy := m.loginBusy && !onDevTab
	developerCode := m.twoFactorRespCh != nil && !onDevTab
	developerRestoring := m.developerRestoring && !onDevTab
	storeBusy := m.storeLoginBusy && !onStoreTab
	storeCode := m.store2FARespCh != nil && !onStoreTab
	storeRestoring := m.storeRestoring && !onStoreTab && m.section != "商店"
	m.mu.Unlock()
	if !developerCode && !storeCode && !developerBusy && !storeBusy && !developerRestoring && !storeRestoring {
		return
	}

	t := c.Theme()
	ui.Column(c.Key("background-login-status")).FillWidth().Shrink(0).Padding(8, 16).Gap(6).
		Background(t.Surface).BorderWidth(1, 0, 0, 0).BorderColor(t.Border).Children(func() {
			if developerCode {
				m.loginVerificationRow(c, msg, "developer-verification", msg.Account2FATitle(), verifyDeveloper)
			} else if developerRestoring {
				loginLoading(c, "developer-background-login", msg.AccountRestoringSession())
			} else if developerBusy {
				loginLoading(c, "developer-background-login", msg.AccountSigningIn())
			}
			if storeCode {
				m.loginVerificationRow(c, msg, "store-verification", msg.Store2FATitle(), verifyStore)
			} else if storeRestoring {
				loginLoading(c, "store-background-login", msg.StoreAccountRestoringSession())
			} else if storeBusy {
				loginLoading(c, "store-background-login", msg.StoreAccountSigningIn())
			}
		})
}

func (m *Model) accountReturnOverlay(c *ui.Context, msg locales.Messages, compact bool) {
	m.mu.Lock()
	ret := m.returnTarget
	awaitingCode := m.twoFactorRespCh != nil || m.store2FARespCh != nil
	m.mu.Unlock()
	if m.section != "账号" || ret == nil || awaitingCode {
		return
	}

	t := c.Theme()
	devSess := m.services.Accounts.Developer()
	signedIn := devSess != nil && devSess.SignedIn()

	sourceLabel := msg.AccountReturnSourceTask()
	switch ret.sourceKey {
	case "device":
		sourceLabel = msg.AccountReturnSourceDevice()
	case "guide":
		sourceLabel = msg.AccountReturnSourceGuide()
	}

	ui.Overlay(c, func() {
		card := ui.Column(c.Key("account-return-overlay")).Absolute().Bottom(18).Right(20).
			Padding(14, 16).Gap(10).Radius(14).Background(t.Surface).
			Border(1, accentInk(t).Alpha(0.55)).
			Shadow(0, 8, 24, 0, ui.RGBA(15, 23, 42, 0.22))
		if compact {
			card.Left(16).Right(16)
		} else {
			card.Width(360)
		}
		card.Children(func() {
			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Start).Children(func() {
				if signedIn {
					ui.Icon(c, phCheckCircleFill).Width(20).Height(20).TextColor(ui.Hex("#10B981"))
					ui.Text(c.Key("account-return-status"), msg.AccountReturnBannerReady(devSess.Email())).Role(ui.RoleStatus).FontSize(12).Bold().Grow(1)
				} else {
					ui.Icon(c, phInfo).Width(20).Height(20).TextColor(accentInk(t))
					ui.Text(c.Key("account-return-status"), msg.AccountReturnBannerWaiting(sourceLabel)).Role(ui.RoleStatus).FontSize(12).Grow(1)
				}
			})
			ui.Row(c).FillWidth().Gap(8).Justify(ui.End).Children(func() {
				if uiBtn(c, "account-return-dismiss", msg.AccountDismissBtn()).Clicked() {
					m.mu.Lock()
					m.returnTarget = nil
					m.mu.Unlock()
				}
				var retBtn ui.Element
				if signedIn {
					retBtn = uiPrimaryBtn(c, "account-return-back", msg.AccountReturnBtn())
				} else {
					retBtn = uiBtn(c, "account-return-back", msg.AccountReturnBtn())
				}
				if retBtn.Clicked() {
					m.mu.Lock()
					target := m.returnTarget
					m.returnTarget = nil
					m.mu.Unlock()
					if target != nil {
						if target.section == "文件" || target.section == "差异" || target.section == "交接" || target.section == "维护" {
							m.goTaskSection(target.section, target.taskStage)
						} else if target.section != "" {
							m.section = target.section
						}
					}
				}
			})
		})
	})
}

func (m *Model) revokeCertConfirmModal(c *ui.Context, msg locales.Messages) {
	m.mu.Lock()
	cert := m.pendingRevokeCert
	m.mu.Unlock()
	if cert == nil {
		return
	}
	t := c.Theme()
	devSess := m.services.Accounts.Developer()
	hasLocal := devSess.SignedIn() && devportal.HasLocalRSAKeyForCert(devSess.Email(), *cert, m.services.Accounts.Storage())
	open := true
	ui.Modal(c.Key("revoke-cert-confirm-modal"), &open, func() {
		ui.Column(c).Width(420).Gap(12).Children(func() {
			ui.Text(c, msg.AccountRevokeConfirmTitle()).Bold().FontSize(16)
			ui.Text(c, msg.AccountRevokeConfirmDesc(cert.SerialNumber, valueOrUnknown(msg, cert.MachineName))).FontSize(12)
			if hasLocal {
				ui.Row(c).FillWidth().Padding(10, 12).Gap(8).Radius(8).
					Background(t.SurfaceHover).Border(1, ui.Hex("#F59E0B")).AlignItems(ui.Start).Children(func() {
					ui.Icon(c, phWarningFill).Width(16).Height(16).TextColor(ui.Hex("#F59E0B"))
					ui.Text(c, msg.AccountRevokeConfirmLocalKeyWarn()).FontSize(11).Grow(1)
				})
			}
			ui.Row(c).FillWidth().Gap(8).Justify(ui.End).Children(func() {
				if uiBtn(c, "revoke-confirm-cancel", msg.LibraryCancel()).Clicked() {
					m.mu.Lock()
					m.pendingRevokeCert = nil
					m.mu.Unlock()
				}
				if uiPrimaryBtn(c, "revoke-confirm-ok", msg.AccountRevokeConfirmBtn()).Clicked() {
					serial := cert.SerialNumber
					m.mu.Lock()
					m.pendingRevokeCert = nil
					m.mu.Unlock()
					m.revokePortalCert(serial)
				}
			})
		})
	})
	if !open {
		m.mu.Lock()
		m.pendingRevokeCert = nil
		m.mu.Unlock()
	}
}
func (m *Model) accountModals(c *ui.Context, msg locales.Messages) {
	t := c.Theme()

	m.mu.Lock()
	tfa := m.twoFactorPrompt
	tfaCh := m.twoFactorRespCh
	verification := m.loginVerification
	maxCerts := m.maxCertsList
	maxCertsCh := m.maxCertsRespCh
	m.mu.Unlock()

	if verification == verifyDeveloper && tfa != nil && tfaCh != nil {
		open := true
		ui.Modal(c.Key("two-factor-modal"), &open, func() {
			ui.Column(c).Width(360).Gap(12).Children(func() {
				ui.Text(c, msg.Account2FATitle()).Bold().FontSize(16)
				if tfa.SMS && tfa.SelectedNumberID != nil {
					digits := "****"
					for _, n := range tfa.Numbers {
						if n.ID == *tfa.SelectedNumberID {
							digits = n.LastTwoDigits
						}
					}
					ui.Text(c, msg.Account2FASMSDesc(digits)).FontSize(12).TextColor(t.TextMuted)
				} else {
					ui.Text(c, msg.Account2FADesc()).FontSize(12).TextColor(t.TextMuted)
				}
				if tfa.LastError != "" {
					ui.Text(c, friendlyError(msg, tfa.LastError)).FontSize(11).TextColor(ui.Hex("#EF4444"))
				}
				ui.TextInput(c.Key("tfa-code-input"), &m.twoFactorCode).
					Placeholder(msg.Account2FACodePlaceholder()).FillWidth().AutoFocus().Label(msg.Account2FATitle())
				ui.Row(c).FillWidth().Gap(8).Justify(ui.End).Children(func() {
					if uiBtn(c, "tfa-cancel", msg.LibraryCancel()).Clicked() {
						m.submit2FAResponse(appleauth.TwoFactorResponse{Action: appleauth.ActionAbort})
					}
					if uiBtn(c, "tfa-resend", msg.Account2FAResend()).Clicked() {
						m.submit2FAResponse(appleauth.TwoFactorResponse{Action: appleauth.ActionResendCode})
					}
					submit := uiPrimaryBtn(c, "tfa-submit", msg.Account2FASubmit())
					if len(strings.TrimSpace(m.twoFactorCode)) == 0 {
						submit.Disabled(true)
					}
					if submit.Clicked() {
						m.submit2FAResponse(appleauth.TwoFactorResponse{
							Action: appleauth.ActionSubmitCode,
							Code:   strings.TrimSpace(m.twoFactorCode),
						})
					}
				})
				if len(tfa.Numbers) > 0 {
					ui.Divider(c)
					for idx, num := range tfa.Numbers {
						num := num
						if uiBtn(c, fmt.Sprintf("tfa-sms-%d", idx), msg.Account2FASendSMS(num.NumberWithDialCode)).Clicked() {
							m.submit2FAResponse(appleauth.TwoFactorResponse{
								Action:   appleauth.ActionSendSMS,
								NumberID: num.ID,
							})
						}
					}
				}
			})
		})
		if !open {
			m.submit2FAResponse(appleauth.TwoFactorResponse{Action: appleauth.ActionAbort})
		}
		return
	}

	if len(maxCerts) > 0 && maxCertsCh != nil {
		open := true
		ui.Modal(c.Key("max-certs-modal"), &open, func() {
			ui.Column(c).Width(420).Gap(12).Children(func() {
				ui.Text(c, msg.AccountMaxCertsTitle()).Bold().FontSize(16)
				ui.Text(c, msg.AccountMaxCertsDesc()).FontSize(12).TextColor(t.TextMuted)
				for idx, cert := range maxCerts {
					cert := cert
					checked := m.maxCertsSelected[cert.SerialNumber]
					label := fmt.Sprintf("%s (%s)", valueOrUnknown(msg, cert.MachineName), cert.SerialNumber)
					ui.Row(c.Key(fmt.Sprintf("max-cert-row-%d", idx))).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Checkbox(c.Key("mc-chk-"+cert.SerialNumber), &checked, label).Cursor(ui.CursorPointer)
					})
					m.maxCertsSelected[cert.SerialNumber] = checked
				}
				ui.Row(c).FillWidth().Gap(8).Justify(ui.End).Children(func() {
					if uiBtn(c, "max-certs-cancel", msg.LibraryCancel()).Clicked() {
						m.submitMaxCertsResponse(nil)
					}
					if uiPrimaryBtn(c, "max-certs-confirm", msg.AccountMaxCertsRevokeContinue()).Clicked() {
						var serials []string
						for serial, on := range m.maxCertsSelected {
							if on {
								serials = append(serials, serial)
							}
						}
						m.submitMaxCertsResponse(serials)
					}
				})
			})
		})
		if !open {
			m.submitMaxCertsResponse(nil)
		}
	}

	m.mu.Lock()
	store2FAEmail := m.store2FAEmail
	store2FACh := m.store2FARespCh
	m.mu.Unlock()
	if verification == verifyStore && store2FAEmail != "" && store2FACh != nil {
		open := true
		ui.Modal(c.Key("store-two-factor-modal"), &open, func() {
			ui.Column(c).Width(360).Gap(12).Children(func() {
				ui.Text(c, msg.Store2FATitle()).Bold().FontSize(16)
				ui.Text(c, msg.Store2FADesc(store2FAEmail)).FontSize(12).TextColor(t.TextMuted)
				ui.TextInput(c.Key("store-tfa-code-input"), &m.store2FACode).
					Placeholder(msg.Account2FACodePlaceholder()).FillWidth().AutoFocus().Label(msg.Store2FATitle())
				ui.Row(c).FillWidth().Gap(8).Justify(ui.End).Children(func() {
					if uiBtn(c, "store-tfa-cancel", msg.LibraryCancel()).Clicked() {
						m.submitStore2FACode("")
					}
					submit := uiPrimaryBtn(c, "store-tfa-submit", msg.Account2FASubmit())
					if strings.TrimSpace(m.store2FACode) == "" {
						submit.Disabled(true)
					}
					if submit.Clicked() {
						m.submitStore2FACode(strings.TrimSpace(m.store2FACode))
					}
				})
			})
		})
		if !open {
			m.submitStore2FACode("")
		}
	}
}

func (m *Model) submit2FAResponse(resp appleauth.TwoFactorResponse) {
	m.mu.Lock()
	ch := m.twoFactorRespCh
	m.twoFactorPrompt = nil
	m.twoFactorRespCh = nil
	m.twoFactorCode = ""
	if m.loginVerification == verifyDeveloper {
		m.loginVerification = 0
	}
	m.mu.Unlock()
	if ch != nil {
		select {
		case ch <- resp:
		default:
		}
	}
}

func (m *Model) submitMaxCertsResponse(serials []string) {
	m.mu.Lock()
	ch := m.maxCertsRespCh
	m.maxCertsList = nil
	m.maxCertsRespCh = nil
	m.maxCertsSelected = map[string]bool{}
	m.mu.Unlock()
	if ch != nil {
		select {
		case ch <- serials:
		default:
		}
	}
}

func (m *Model) prompt2FA(ctx context.Context, prompt appleauth.TwoFactorPrompt) (appleauth.TwoFactorResponse, error) {
	ch := make(chan appleauth.TwoFactorResponse, 1)
	m.mu.Lock()
	p := prompt
	m.twoFactorPrompt = &p
	m.twoFactorRespCh = ch
	m.twoFactorCode = ""
	m.mu.Unlock()
	if m.win != nil {
		mygo.RunOnMain(func() { m.win.Invalidate() })
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		m.submit2FAResponse(appleauth.TwoFactorResponse{Action: appleauth.ActionAbort})
		return appleauth.TwoFactorResponse{Action: appleauth.ActionAbort}, ctx.Err()
	}
}

func (m *Model) promptMaxCerts(certs []devportal.DevelopmentCertificate) ([]string, error) {
	ch := make(chan []string, 1)
	m.mu.Lock()
	m.maxCertsList = append([]devportal.DevelopmentCertificate(nil), certs...)
	m.maxCertsRespCh = ch
	m.maxCertsSelected = map[string]bool{}
	m.mu.Unlock()
	if m.win != nil {
		mygo.RunOnMain(func() { m.win.Invalidate() })
	}
	serials := <-ch
	return serials, nil
}

func (m *Model) startLogin(email, password string, remember, useSaved bool) {
	m.mu.Lock()
	if m.loginBusy || m.developerRestoring {
		m.mu.Unlock()
		return
	}
	m.loginBusy = true
	m.loginErr = ""
	m.mu.Unlock()
	if m.win != nil {
		m.win.Invalidate()
	}

	go func() {
		ctx := context.Background()
		var err error
		if useSaved {
			err = m.services.Accounts.SignInSavedDeveloper(ctx, email, m.prompt2FA)
		} else {
			err = m.services.Accounts.SignInDeveloper(ctx, email, password, remember, m.prompt2FA)
		}
		m.mu.Lock()
		m.loginBusy = false
		if err != nil {
			m.loginErr = err.Error()
		} else {
			m.loginErr = ""
			m.loginPassword = ""
		}
		m.mu.Unlock()
		if err != nil {
			m.addLog("developer sign-in failed: " + err.Error())
		} else {
			m.addLog("developer signed in: " + email)
			m.loadPortalCertsAndQuota()
		}
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) loadPortalCertsAndQuota() {
	m.mu.Lock()
	if m.certsLoading {
		m.mu.Unlock()
		return
	}
	m.certsLoading = true
	m.portalCertErr = ""
	m.mu.Unlock()

	go func() {
		ctx := context.Background()
		portal, err := m.services.Accounts.DeveloperPortal()
		var certs []devportal.DevelopmentCertificate
		var ids devportal.ListAppIDsResult
		if err == nil {
			if team, ok := m.services.Accounts.Developer().ActiveTeam(); ok {
				certs, err = portal.ListAllDevelopmentCerts(ctx, team.TeamID, true)
				if err == nil {
					ids, err = portal.ListAppIDs(ctx, team.TeamID)
				}
			}
		}
		m.mu.Lock()
		m.certsLoading = false
		if err != nil {
			m.portalCertErr = err.Error()
		} else {
			m.portalCerts = certs
			m.portalCertsLoaded = true
			m.portalQuotaKnown = ids.HasAvailable
			m.portalAppIDsAvail = ids.AvailableQuantity
			m.portalAppIDsMax = ids.MaxQuantity
			m.portalAppIDs = ids.AppIDs
		}
		m.mu.Unlock()
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) deletePortalAppID(appIDID string) {
	m.mu.Lock()
	m.appIDDeleting = appIDID
	m.portalCertErr = ""
	m.mu.Unlock()
	go func() {
		ctx := context.Background()
		portal, err := m.services.Accounts.DeveloperPortal()
		if err == nil {
			if team, ok := m.services.Accounts.Developer().ActiveTeam(); ok {
				err = portal.DeleteAppID(ctx, team.TeamID, appIDID)
			}
		}
		m.mu.Lock()
		m.appIDDeleting = ""
		if err != nil {
			m.portalCertErr = err.Error()
		}
		m.mu.Unlock()
		if err == nil {
			m.addLog("deleted app ID: " + appIDID)
			m.loadPortalCertsAndQuota()
		}
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) revokePortalCert(serial string) {
	go func() {
		ctx := context.Background()
		portal, err := m.services.Accounts.DeveloperPortal()
		if err == nil {
			if team, ok := m.services.Accounts.Developer().ActiveTeam(); ok {
				err = portal.RevokeDevelopmentCert(ctx, team.TeamID, serial)
			}
		}
		if err != nil {
			m.mu.Lock()
			m.portalCertErr = err.Error()
			m.mu.Unlock()
		} else {
			m.addLog("revoked dev certificate: " + serial)
			m.loadPortalCertsAndQuota()
		}
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}

func (m *Model) renderStoreAccountTab(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	mgr := m.services.Accounts
	m.mu.Lock()
	busy, awaitingCode := m.storeLoginBusy, m.store2FARespCh != nil
	restoring := m.storeRestoring
	sErr := m.storeLoginErr
	m.mu.Unlock()
	if busy || awaitingCode || restoring {
		surfaceCard(c, "store-signin-card").Padding(18, 20).Gap(12).Children(func() {
			ui.Text(c, msg.StoreAccountSignInTitle()).Bold().FontSize(16)
			if awaitingCode {
				m.loginVerificationRow(c, msg, "store-verification", msg.Store2FATitle(), verifyStore)
			} else if restoring {
				loginLoading(c, "store-signin-status", msg.StoreAccountRestoringSession())
			} else {
				loginLoading(c, "store-signin-status", msg.StoreAccountSigningIn())
			}
		})
		return
	}

	storeSess := mgr.Store()
	savedStore := mgr.SavedStoreAccounts()

	if storeSess.SignedIn() {
		insetGroup(c, "store-account-signedin", func() {
			ui.Row(c).FillWidth().Padding(16, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Row(c).Width(40).Height(40).Radius(20).Background(t.Selection).Center().Children(func() {
					ui.Icon(c, phAccountFill).Width(24).Height(24).TextColor(accentInk(t))
				})
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c.Key("store-status-title"), msg.StoreAccountSignedIn(storeSess.Email())).Role(ui.RoleStatus).Bold().FontSize(15)
					country := storeSess.CountryCode()
					if country == "" {
						country = "—"
					}
					monoText(c, msg.StoreAccountRegion(country, storeSess.StoreFront())).FontSize(11).TextColor(accentInk(t))
				})
				if uiBtn(c, "store-account-signout", msg.StoreAccountSignOutBtn()).Clicked() {
					mgr.SignOutStore()
					m.addLog("store account signed out")
				}
			})
		})
	}

	if len(savedStore) > 0 {
		ui.Text(c, msg.StoreAccountSavedTitle()).Bold().FontSize(13).TextColor(t.TextMuted)
		insetGroup(c, "store-saved-accounts", func() {
			for idx, item := range savedStore {
				item := item
				if idx > 0 {
					ui.Divider(c)
				}
				isActive := storeSess.SignedIn() && strings.EqualFold(storeSess.Email(), item.Email)
				ui.Row(c.Key(fmt.Sprintf("store-saved-%d", idx))).FillWidth().Padding(10, 18).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, phAccount).Width(18).Height(18).TextColor(accentInk(t))
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						monoText(c, item.Email).FontSize(12).Bold()
						cc := item.CountryCode
						if cc == "" {
							cc = item.StoreFront
						}
						monoText(c, msg.StoreAccountRegion(cc, item.StoreFront)).FontSize(11).TextColor(t.TextMuted)
					})
					if isActive {
						ui.Row(c).Padding(2, 8).Radius(6).Background(t.Selection).Children(func() {
							ui.Text(c, msg.StoreAccountActiveBadge()).FontSize(11).Bold().TextColor(accentInk(t))
						})
					} else if uiBtn(c, fmt.Sprintf("store-switch-%d", idx), msg.StoreAccountSwitchBtn()).Clicked() {
						_ = mgr.SwitchStoreAccount(item.Email)
					}
					if uiBtn(c, fmt.Sprintf("store-forget-%d", idx), msg.StoreAccountForgetBtn()).Clicked() {
						_ = mgr.ForgetStoreAccount(item.Email)
					}
				})
			}
		})
	}

	surfaceCard(c, "store-signin-card").Padding(18, 20).Gap(12).Children(func() {
		ui.Text(c, msg.StoreAccountSignInTitle()).Bold().FontSize(16)
		ui.Text(c, msg.AccountEmailLabel()).FontSize(12).TextColor(t.TextMuted)
		ui.TextInput(c.Key("store-email-input"), &m.storeLoginEmail).
			Placeholder(msg.AccountEmailPlaceholder()).FillWidth().Label(msg.AccountEmailLabel())
		ui.Text(c, msg.AccountPasswordLabel()).FontSize(12).TextColor(t.TextMuted)
		ui.TextInput(c.Key("store-password-input"), &m.storeLoginPass).
			Password().Placeholder(msg.AccountPasswordPlaceholder()).FillWidth().Label(msg.AccountPasswordLabel())
		if sErr != "" {
			ui.Text(c.Key("store-login-err"), friendlyError(msg, sErr)).Role(ui.RoleStatus).FontSize(12).TextColor(ui.Hex("#EF4444"))
		}

		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
			btn := uiPrimaryBtn(c, "store-signin-btn", msg.StoreAccountSignInBtn())
			if strings.TrimSpace(m.storeLoginEmail) == "" || m.storeLoginPass == "" {
				btn.Disabled(true)
			}
			if btn.Clicked() {
				m.startStoreLogin(m.storeLoginEmail, m.storeLoginPass)
			}
		})
	})
}

func (m *Model) submitStore2FACode(code string) {
	m.mu.Lock()
	ch := m.store2FARespCh
	m.store2FAEmail = ""
	m.store2FARespCh = nil
	m.store2FACode = ""
	if m.loginVerification == verifyStore {
		m.loginVerification = 0
	}
	m.mu.Unlock()
	if ch != nil {
		select {
		case ch <- code:
		default:
		}
	}
}

func (m *Model) promptStore2FA(ctx context.Context, email string) (string, error) {
	ch := make(chan string, 1)
	m.mu.Lock()
	m.store2FAEmail = email
	m.store2FARespCh = ch
	m.store2FACode = ""
	m.mu.Unlock()
	if m.win != nil {
		mygo.RunOnMain(func() { m.win.Invalidate() })
	}
	select {
	case code := <-ch:
		if strings.TrimSpace(code) == "" {
			return "", context.Canceled
		}
		return code, nil
	case <-ctx.Done():
		m.submitStore2FACode("")
		return "", ctx.Err()
	}
}

func (m *Model) startStoreLogin(email, password string) {
	m.mu.Lock()
	if m.storeLoginBusy || m.storeRestoring {
		m.mu.Unlock()
		return
	}
	m.storeLoginBusy = true
	m.storeLoginErr = ""
	m.mu.Unlock()
	if m.win != nil {
		m.win.Invalidate()
	}

	go func() {
		err := m.services.Accounts.SignInStore(context.Background(), email, password, m.promptStore2FA)
		m.mu.Lock()
		m.storeLoginBusy = false
		if err != nil {
			m.storeLoginErr = err.Error()
		} else {
			m.storeLoginErr = ""
			m.storeLoginPass = ""
		}
		m.mu.Unlock()
		if err != nil {
			m.addLog("store sign-in failed: " + err.Error())
		} else {
			m.addLog("store signed in: " + email)
		}
		if m.win != nil {
			mygo.RunOnMain(func() { m.win.Invalidate() })
		}
	}()
}
