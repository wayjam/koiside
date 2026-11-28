package shell

import (
	"path/filepath"
	"strconv"

	"github.com/egoist/mygo/ui"

	"koiside/locales"
)

const (
	localDevVPNURL  = "https://apps.apple.com/app/localdevvpn/id6755608044"
	liveSetupURL    = "https://livecontainer.github.io/docs/installation/lc_sidestore"
	verifyExpiryURL = "https://livecontainer.github.io/docs/guides/refresh-verification"
)

type helpGuideStep struct {
	label string
	body  []string
	extra func()
}

func (m *Model) startHelpGuide(topic string) {
	m.helpTopic = topic
	m.helpStep = 0
	m.shortcutSchedule = false
	m.shortcutTroubleshooting = false
	m.helpFileError = ""
}

func (m *Model) helpGuideModal(c *ui.Context, msg locales.Messages) {
	topic := m.helpTopic
	if topic == "" {
		return
	}
	title, steps := m.helpGuideSteps(c, msg, topic)
	width, height := c.Size()
	panelWidth := min(580, width-64)
	bodyHeight := min(340, height-212)
	step := m.helpStep
	t := c.Theme()
	canAdvance := step != 0 || !isShortcutGuide(topic) || m.shortcutCanAdvance(topic)
	open := true
	ui.Modal(c.Key("help-guide-modal"), &open, func() {
		panel := ui.Column(c.Key(topic)).Width(panelWidth).Gap(14)
		type stepMotion struct {
			step int
			dx   float32
		}
		motion := ui.Local(panel, "step-motion", func() stepMotion { return stepMotion{step: step} })
		if step > motion.step {
			motion.dx = 8
		} else if step < motion.step {
			motion.dx = -8
		}
		motion.step = step
		panel.Children(func() {
			ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Center).Children(func() {
				ui.Box(c).Size(42, 42).Shrink(0).Radius(12).Background(t.Selection).Center().Children(func() {
					ui.Icon(c, helpGuideIcon(topic)).Size(23, 23).TextColor(accentInk(t)).AccessHidden(true)
				})
				ui.Column(c).Grow(1).MinWidth(0).Gap(2).Children(func() {
					ui.Text(c, title).Role(ui.RoleHeading).Bold().FontSize(19)
					ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
						ui.Box(c).Size(6, 6).Radius(3).Background(accentInk(t)).Shrink(0)
						ui.Text(c, steps[step].label).Bold().FontSize(12).TextColor(accentInk(t))
						ui.Text(c, "·").FontSize(12).TextColor(t.TextMuted)
						ui.Text(c, msg.GuideStepOf(step+1, len(steps))).Role(ui.RoleStatus).FontSize(12).TextColor(t.TextMuted)
					})
				})
			})
			helpProgress(c, step, steps)
			body := ui.Scroll(c.Key("help-guide-step-" + strconv.Itoa(step))).FillWidth().MaxHeight(bodyHeight)
			if !c.Preferences().ReduceMotion {
				transition := helpStepTransition
				if motion.dx != 0 {
					transition.Enter = &ui.Motion{X: motion.dx, Opacity: 0.8}
					panel.ChildExit(ui.Motion{X: -motion.dx, Opacity: 0})
				}
				body.Transition(transition)
			}
			body.Children(func() {
				ui.Column(c).FillWidth().MinHeight(min(134, bodyHeight)).Padding(2, 3, 4, 0).Gap(10).Children(func() {
					if len(steps[step].body) > 0 {
						ui.Column(c).FillWidth().Padding(10, 12).Gap(8).Radius(10).
							Background(t.Surface).Border(1, t.Border.Alpha(0.6)).Children(func() {
							for idx, paragraph := range steps[step].body {
								ui.Row(c.Key(idx)).FillWidth().Gap(8).AlignItems(ui.Start).Children(func() {
									ui.Box(c).Size(18, 18).Radius(9).Background(t.Selection).Shrink(0).Center().Children(func() {
										ui.Text(c, strconv.Itoa(idx+1)).Bold().FontSize(10).TextColor(accentInk(t))
									})
									ui.Text(c, paragraph).FontSize(13).Grow(1)
								})
							}
						})
					}
					if steps[step].extra != nil {
						steps[step].extra()
					}
				})
			})
			ui.Row(c).FillWidth().Wrap().AlignItems(ui.Center).Gap(8).Children(func() {
				if uiBtn(c, "help-guide-close", msg.HelpGuideClose()).Clicked() {
					open = false
				}
				ui.Box(c).Grow(1)
				if uiBtnWithTip(c, "help-guide-previous", msg.HelpGuidePrevious(), step == 0, "").Clicked() {
					m.helpFileError = ""
					m.helpStep--
				}
				if step+1 < len(steps) {
					btnText := msg.HelpGuideNext() + " →"
					if uiPrimaryBtnWithTip(c, "help-guide-next", btnText, !canAdvance, "").Clicked() {
						m.helpFileError = ""
						m.helpStep++
					}
				} else if uiPrimaryBtn(c, "help-guide-finish", msg.HelpGuideFinish()).Clicked() {
					open = false
				}
			})
		})
	})
	if !open {
		m.helpTopic = ""
	}
}

func helpProgress(c *ui.Context, step int, steps []helpGuideStep) {
	t := c.Theme()
	ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
		for i, item := range steps {
			bg, ink, marker := t.SurfaceHover, t.TextMuted, t.Border
			chipBg, chipFg := t.Surface, t.TextMuted
			if i < step {
				bg, ink = t.Selection, accentInk(t)
				chipBg, chipFg = t.Surface, successInk(t)
			} else if i == step {
				bg, ink, marker = t.Selection, t.Text, t.Accent
				chipBg, chipFg = t.Accent, t.AccentText
			}
			ui.Row(c.Key(i)).Grow(1).MinWidth(0).MinHeight(44).Padding(6, 10).Gap(8).Radius(10).
				Background(bg).Border(1, marker).Transition(colorTransition).AlignItems(ui.Center).Children(func() {
				ui.Box(c).Size(22, 22).Radius(11).Background(chipBg).Center().Children(func() {
					if i < step {
						icon := ui.Icon(c.Key("past"), phCheckCircleFill).Size(16, 16).TextColor(chipFg).AccessHidden(true)
						if !c.Preferences().ReduceMotion {
							icon.Transition(stepCheckEnterTransition)
						}
					} else {
						ui.Text(c, strconv.Itoa(i+1)).Bold().FontSize(11).TextColor(chipFg).AccessHidden(true)
					}
				})
				ui.Text(c, item.label).Grow(1).MinWidth(0).Bold().FontSize(12).TextColor(ink)
			})
			if i+1 < len(steps) {
				line := ui.Box(c.Key("help-step-link-"+strconv.Itoa(i))).Size(16, 2).Shrink(0).
					Radius(1).Background(t.Border).AccessHidden(true)
				target := float32(0)
				if i < step {
					target = 1
				}
				fill := line.AnimateTo("fill", target, motionFeedbackAnim)
				line.Children(func() {
					ui.Box(c).Width(16 * fill).Height(2).Radius(1).Background(accentInk(t))
				})
			}
		}
	})
}

func helpDisclosure(c *ui.Context, key, label string, open *bool, content func()) {
	t := c.Theme()
	ui.Column(c.Key(key)).Shrink(0).Children(func() {
		disclosure := ui.CollapsibleBase(c.Key("toggle"), open)
		trigger := disclosure.Trigger.Label(label).AlignSelf(ui.Start).AlignItems(ui.Center).
			Padding(4, 8).Gap(6).Radius(t.Radius).Cursor(ui.CursorPointer).Transition(colorTransition)
		if trigger.Hovered() {
			trigger.Background(t.SurfaceHover)
		}
		trigger.Children(func() {
			pose := ui.Pose{}
			if *open {
				pose.Rotate = 90
			}
			ui.Icon(c, phCaretRight).Size(14, 14).TextColor(t.TextMuted).AnimatePose(pose, ui.Snappy)
			ui.Text(c, label).FontSize(13)
		})
		panel := disclosure.Panel(content)
		if panel != (ui.Element{}) {
			progress := disclosure.Progress()
			panel.Padding(4, 0).PaddingStart(28).Gap(8).Opacity(progress).Translate(0, -4*(1-progress))
		}
	})
}

func helpGuideIcon(topic string) *ui.SVG {
	switch topic {
	case "connect":
		return phDeviceDuotone
	case "missing":
		return phMagnifyingGlassDuotone
	case "refresh", helpShortcutRefresh:
		return phRefresh
	case "vpn":
		return phShieldCheck
	case "livecontainer", helpShortcutLaunch:
		return phCubeFill
	default:
		return phCompassFill
	}
}

func (m *Model) helpGuideSteps(c *ui.Context, msg locales.Messages, topic string) (string, []helpGuideStep) {
	switch topic {
	case helpShortcutRefresh, helpShortcutLaunch:
		return m.shortcutGuideSteps(c, msg, topic)
	case "connect":
		return msg.HelpTopicConnectTitle(), []helpGuideStep{
			{label: msg.GuideStep1Title(), body: []string{msg.HelpGuideConnectCable()}},
			{label: msg.HelpGuideTrust(), body: []string{msg.HelpGuideConnectTrust()}},
			{label: msg.HelpGuideCheckDevice(), body: []string{msg.HelpGuideConnectCheck()}, extra: func() { m.helpDeviceCheck(c, msg) }},
		}
	case "setup":
		return msg.HelpTopicSetupTitle(), []helpGuideStep{
			{label: msg.HelpGuideInstall(), body: []string{msg.HelpGuideSetupInstall()}, extra: func() {
				ui.Row(c).FillWidth().Wrap().Gap(8).Children(func() {
					m.helpDeviceLink(c, msg, 0)
					m.helpRecoveryLink(c, msg)
				})
			}},
			{label: msg.HelpGuideTrust(), body: []string{msg.PostInstallStepDevMode(), msg.PostInstallStepTrust()}},
			{label: msg.HelpGuideTestRefresh(), body: []string{msg.PostInstallStepRefresh(), msg.PostInstallStepLCSS()}, extra: func() {
				m.helpLink(c, "help-setup-vpn", msg.ToolInstallLocalDevVPNBtn(), localDevVPNURL)
			}},
		}
	case "missing":
		return msg.HelpTopicMissingFileTitle(), []helpGuideStep{
			{label: msg.HelpGuideCheckTransfer(), body: []string{msg.HelpGuideMissingCheck()}, extra: func() {
				ui.Text(c, m.transferStatusText(msg)).Role(ui.RoleStatus).FontSize(12).TextColor(accentInk(c.Theme()))
				m.mu.Lock()
				path := m.exportedPath
				m.mu.Unlock()
				if path != "" {
					ui.Text(c, filepath.Base(path)).FontSize(12)
					m.helpFileActions(c, msg, path, "ipa")
				}
				m.helpDeviceLink(c, msg, 2)
			}},
			{label: msg.HelpGuideFindFile(), body: []string{msg.HelpGuideMissingFind()}},
			{label: msg.HelpGuideImport(), body: []string{msg.HelpGuideMissingImport()}},
		}
	case "refresh":
		return msg.HelpTopicRefreshTitle(), []helpGuideStep{
			{label: msg.HelpGuideCheckLaunch(), body: []string{msg.MaintainRecoverySubtitle(), msg.MaintainRecoveryExpiredDesc()}, extra: func() {
				m.helpRecoveryLink(c, msg)
			}},
			{label: msg.HelpGuideTestRefresh(), body: []string{msg.MaintainRecoveryOpenableDesc(), msg.HelpGuideRefreshSession()}, extra: func() {
				if uiBtn(c, "help-open-refresh-shortcut", msg.HelpGuideRefreshShortcut()).Clicked() {
					m.startHelpGuide(helpShortcutRefresh)
				}
			}},
			{label: msg.HelpGuideVerify(), body: []string{msg.MaintainExpiryNote()}, extra: func() {
				m.helpLink(c, "help-verify-expiry", msg.MaintainVerifyProfile(), verifyExpiryURL)
			}},
		}
	case "vpn":
		return "LocalDevVPN", []helpGuideStep{
			{label: msg.HelpGuideInstall(), body: []string{msg.ToolLocalDevVPNLimitation()}, extra: func() {
				m.helpLink(c, "help-vpn-install", msg.ToolInstallLocalDevVPNBtn(), localDevVPNURL)
			}},
			{label: msg.HelpGuideCheckDevice(), body: []string{msg.HelpGuideVPNConnect()}},
			{label: msg.HelpGuideVerify(), body: []string{msg.HelpGuideVPNCheck()}},
		}
	default: // livecontainer
		return "LiveContainer", []helpGuideStep{
			{label: msg.HelpGuideInstall(), body: []string{msg.HelpGuideLiveInstall()}, extra: func() {
				m.helpDeviceLink(c, msg, 0)
				m.helpLink(c, "help-live-guide", msg.ToolsOpenGuide(), liveSetupURL)
			}},
			{label: msg.HelpGuideImport(), body: []string{msg.HelpGuideLiveImport()}},
			{label: msg.HelpGuideCheckLaunch(), body: []string{msg.LcAdvancedMultiDesc()}, extra: func() {
				if uiBtn(c, "help-open-launch-shortcut", msg.HelpGuideLaunchShortcut()).Clicked() {
					m.startHelpGuide(helpShortcutLaunch)
				}
			}},
		}
	}
}

func (m *Model) helpDeviceCheck(c *ui.Context, msg locales.Messages) {
	ui.Row(c).FillWidth().Wrap().Gap(8).AlignItems(ui.Center).Children(func() {
		m.helpRescan(c, msg, "help-detect-device")
		m.helpDeviceLink(c, msg, 0)
	})
	ui.Text(c, m.deviceStatusText(msg)).Role(ui.RoleStatus).FontSize(13).Bold()
}

func (m *Model) helpRescan(c *ui.Context, msg locales.Messages, key string) {
	m.mu.Lock()
	busy := m.deviceProbing
	m.mu.Unlock()
	label := msg.GuideRetry()
	if busy {
		label = msg.HelpGuideScanning()
	}
	if uiBtnWithTip(c, key, label, busy, "").Clicked() {
		m.detectDevices()
	}
}

func (m *Model) helpDeviceLink(c *ui.Context, msg locales.Messages, tab int) {
	label := msg.ToolsManageOnDeviceBtn()
	if tab == 2 {
		label = msg.DeviceTabDocs()
	}
	if uiBtn(c, "help-open-device", label).Clicked() {
		m.helpTopic = ""
		m.deviceTab = tab
		m.section = "设备"
	}
}

func (m *Model) helpRecoveryLink(c *ui.Context, msg locales.Messages) {
	if uiBtn(c, "help-open-recovery", msg.MaintainRecoveryTitle()).Clicked() {
		m.helpTopic = ""
		m.recoveryMode = true
		m.goTaskSection("维护", 5)
	}
}

func (m *Model) helpLink(c *ui.Context, key, label, url string) {
	if uiBtn(c, key, label).Clicked() {
		c.OpenURL(url)
	}
}
