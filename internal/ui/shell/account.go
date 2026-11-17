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

func (m *Model) accountView(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.AccountTitle()).FontSize(26).Bold()
		ui.Text(c, msg.AccountSubtitle()).TextColor(t.TextMuted)
	})

	mgr := m.services.Accounts
	devSess := mgr.Developer()

	if devSess.SignedIn() {
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

			m.mu.Lock()
			busy := m.loginBusy
			loginErr := m.loginErr
			m.mu.Unlock()
			if loginErr != "" {
				ui.Text(c.Key("acc-login-err"), friendlyError(msg, loginErr)).FontSize(12).TextColor(ui.Hex("#EF4444"))
			}

			ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
				btn := uiPrimaryBtn(c, "acc-sign-in-btn", msg.AccountSignInBtn())
				if busy || strings.TrimSpace(m.loginEmail) == "" || m.loginPassword == "" {
					btn.Disabled(true)
				}
				if btn.Clicked() {
					m.startLogin(m.loginEmail, m.loginPassword, m.loginRemember, false)
				}
				if busy {
					ui.Spinner(c).Label(msg.AccountSigningIn())
					ui.Text(c, msg.AccountSigningIn()).FontSize(12).TextColor(accentInk(t))
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

	m.storeAccountSection(c, msg)
}

func (m *Model) accountReturnOverlay(c *ui.Context, msg locales.Messages, compact bool) {
	m.mu.Lock()
	ret := m.returnTarget
	tfaOpen := m.twoFactorPrompt != nil
	m.mu.Unlock()
	if m.section != "账号" || ret == nil || tfaOpen {
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
	maxCerts := m.maxCertsList
	maxCertsCh := m.maxCertsRespCh
	m.mu.Unlock()

	if tfa != nil && tfaCh != nil {
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
					ui.Text(c, tfa.LastError).FontSize(11).TextColor(ui.Hex("#EF4444"))
				}
				ui.TextInput(c.Key("tfa-code-input"), &m.twoFactorCode).
					Placeholder(msg.Account2FACodePlaceholder()).FillWidth().Label(msg.Account2FATitle())
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
	if store2FAEmail != "" && store2FACh != nil {
		open := true
		ui.Modal(c.Key("store-two-factor-modal"), &open, func() {
			ui.Column(c).Width(360).Gap(12).Children(func() {
				ui.Text(c, msg.Store2FATitle()).Bold().FontSize(16)
				ui.Text(c, msg.Store2FADesc(store2FAEmail)).FontSize(12).TextColor(t.TextMuted)
				ui.TextInput(c.Key("store-tfa-code-input"), &m.store2FACode).
					Placeholder(msg.Account2FACodePlaceholder()).FillWidth().Label(msg.Store2FATitle())
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
	if m.loginBusy {
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

func (m *Model) storeAccountSection(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	mgr := m.services.Accounts
	storeSess := mgr.Store()
	savedStore := mgr.SavedStoreAccounts()

	ui.Column(c).FillWidth().Gap(4).Margin(8, 0, 0, 0).Children(func() {
		ui.Text(c, msg.StoreAccountSectionTitle()).Bold().FontSize(16)
		ui.Text(c, msg.StoreAccountSectionDesc()).FontSize(12).TextColor(t.TextMuted)
	})

	if storeSess.SignedIn() {
		insetGroup(c, "store-account-signedin", func() {
			ui.Row(c).FillWidth().Padding(14, 18).Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phAccountFill).Width(24).Height(24).TextColor(accentInk(t))
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, msg.StoreAccountSignedIn(storeSess.Email())).Bold().FontSize(14)
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

	surfaceCard(c, "store-signin-card").Padding(16, 18).Gap(10).Children(func() {
		ui.Text(c, msg.StoreAccountSignInTitle()).Bold().FontSize(14)
		ui.TextInput(c.Key("store-email-input"), &m.storeLoginEmail).
			Placeholder(msg.AccountEmailPlaceholder()).FillWidth().Label(msg.AccountEmailLabel())
		ui.TextInput(c.Key("store-password-input"), &m.storeLoginPass).
			Password().Placeholder(msg.AccountPasswordPlaceholder()).FillWidth().Label(msg.AccountPasswordLabel())

		m.mu.Lock()
		busy := m.storeLoginBusy
		sErr := m.storeLoginErr
		m.mu.Unlock()
		if sErr != "" {
			ui.Text(c.Key("store-login-err"), friendlyError(msg, sErr)).FontSize(12).TextColor(ui.Hex("#EF4444"))
		}

		ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
			btn := uiPrimaryBtn(c, "store-signin-btn", msg.StoreAccountSignInBtn())
			if busy || strings.TrimSpace(m.storeLoginEmail) == "" || m.storeLoginPass == "" {
				btn.Disabled(true)
			}
			if btn.Clicked() {
				m.startStoreLogin(m.storeLoginEmail, m.storeLoginPass)
			}
			if busy {
				ui.Spinner(c).Label(msg.StoreAccountSigningIn())
				ui.Text(c, msg.StoreAccountSigningIn()).FontSize(12).TextColor(accentInk(t))
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
	if m.storeLoginBusy {
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
