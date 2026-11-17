package shell

import (
	"github.com/egoist/mygo/ui"

	"koiside/locales"
)

type toolGuide struct {
	name   string
	state  string
	next   string
	source string
}

func toolBadgeStyle(name string) (*ui.SVG, ui.Color) {
	switch name {
	case "SideStore":
		return phLightningFill, ui.Hex("#1769D2")
	case "LocalDevVPN":
		return phShieldFill, ui.Hex("#0284C7")
	default:
		return phCubeFill, ui.Hex("#0D9488")
	}
}

func (m *Model) guides(msg locales.Messages) []toolGuide {
	sideState := msg.ToolSideStoreState()
	vpnState := msg.ToolVPNState()
	lcState := msg.ToolLCState()
	m.mu.Lock()
	queried := m.appsQueried
	side := m.sideStoreApp
	sideEmbedded := m.sideStoreEmbedded
	vpn := m.vpnApp
	lc := m.lcApp
	m.mu.Unlock()
	if queried {
		if side != nil {
			sideState = msg.DeviceToolDetected(valueOrUnknown(msg, side.Version))
		} else if sideEmbedded {
			sideState = msg.DeviceToolEmbeddedInLC()
		} else {
			sideState = msg.DeviceToolNotDetected()
		}
		if vpn != nil {
			vpnState = msg.DeviceToolDetected(valueOrUnknown(msg, vpn.Version))
		} else {
			vpnState = msg.DeviceToolNotDetected()
		}
		if lc != nil {
			lcState = msg.DeviceToolDetected(valueOrUnknown(msg, lc.Version))
		} else {
			lcState = msg.DeviceToolNotDetected()
		}
	}
	return []toolGuide{
		{name: "SideStore", state: sideState, next: msg.ToolSideStoreNext(), source: "https://docs.sidestore.io/docs/installation/install"},
		{name: "LocalDevVPN", state: vpnState, next: msg.ToolVPNNext(), source: "https://apps.apple.com/app/localdevvpn/id6755608044"},
		{name: "LiveContainer", state: lcState, next: msg.ToolLCNext(), source: "https://livecontainer.github.io/docs/installation/lc_sidestore"},
	}
}

func (m *Model) tools(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
		ui.Column(c).Grow(1).Gap(4).Children(func() {
			ui.Text(c, msg.HelpHubTitle()).FontSize(26).Bold()
			ui.Text(c, msg.HelpHubSubtitle()).TextColor(t.TextMuted)
		})
		if m.lastTaskSection != "" {
			if uiBtn(c, "help-back-to-task", msg.BackToTask()).Clicked() {
				m.section = m.lastTaskSection
			}
		}
	})

	insetGroup(c, "help-topics-group", func() {
		topicRow := func(id string, icon *ui.SVG, title, desc string, action func()) {
			bg := t.Surface
			if m.helpTopic == id {
				bg = t.Selection
			}
			row := ui.ButtonBase(c.Key("help-topic-"+id)).FillWidth().Padding(14, 18).
				Background(bg).Label(title).Cursor(ui.CursorPointer).Transition(colorTransition)
			if m.helpTopic != id && row.Hovered() {
				row.Background(t.SurfaceHover)
			}
			row.Children(func() {
				ui.Row(c).FillWidth().Gap(12).AlignItems(ui.Center).Children(func() {
					ui.Icon(c, icon).Width(20).Height(20).TextColor(accentInk(t))
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						ui.Text(c, title).Bold().FontSize(14)
						ui.Text(c, desc).FontSize(12).TextColor(t.TextMuted)
					})
					ui.Icon(c, phCaretRight).Width(15).Height(15).TextColor(t.TextMuted)
				})
			})
			if row.Clicked() {
				action()
			}
		}

		topicRow("connect", phUSB, msg.HelpTopicConnectTitle(), msg.HelpTopicConnectDesc(), func() {
			m.section = "设备"
		})
		ui.Divider(c)
		topicRow("setup", phCompass, msg.HelpTopicSetupTitle(), msg.HelpTopicSetupDesc(), func() {
			m.guideStep = 1
			m.section = "引导"
		})
		ui.Divider(c)
		topicRow("missing", phFolderOpen, msg.HelpTopicMissingFileTitle(), msg.HelpTopicMissingFileDesc(), func() {
			m.goTaskSection("交接", 4)
		})
		ui.Divider(c)
		topicRow("refresh", phRefresh, msg.HelpTopicRefreshTitle(), msg.HelpTopicRefreshDesc(), func() {
			m.recoveryMode = false
			m.goTaskSection("维护", 5)
		})
	})

	ui.Column(c).FillWidth().Gap(3).Children(func() {
		ui.Text(c, msg.ToolsTitle()).FontSize(16).Bold()
		ui.Text(c, msg.ToolsDetectedNote()).FontSize(12).TextColor(t.TextMuted)
	})

	allGuides := m.guides(msg)
	insetGroup(c, "tools-list-group", func() {
		for idx, guide := range allGuides {
			guide := guide
			glyph, iconBg := toolBadgeStyle(guide.name)
			ui.Row(c.Key("tool-card-"+guide.name)).FillWidth().Padding(16, 18).Gap(14).AlignItems(ui.Center).Children(func() {
				ui.Row(c).Width(40).Height(40).Radius(10).Background(iconBg).
					InsetShadow(0, 1, 0, 0, ui.RGBA(255, 255, 255, 0.22)).
					Center().Children(func() {
					ui.Icon(c, glyph).Width(20).Height(20).TextColor(ui.Hex("#FFFFFF"))
				})
				ui.Column(c).Grow(1).Gap(3).Children(func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, guide.name).Bold().FontSize(15)
						ui.Text(c, msg.ToolsStatusPrefix(guide.state)).FontSize(12).TextColor(t.TextMuted)
					})
					ui.Text(c, guide.next).FontSize(12).TextColor(t.TextMuted)
					if guide.name == "LocalDevVPN" {
						ui.Text(c, msg.ToolLocalDevVPNLimitation()).FontSize(11).TextColor(t.TextMuted)
					}
				})
				ui.Row(c).Gap(8).Children(func() {
					switch guide.name {
					case "LocalDevVPN":
						if uiBtn(c, "tools-open-localdevvpn", msg.ToolInstallLocalDevVPNBtn()).Clicked() {
							c.OpenURL(guide.source)
						}
					default:
						if uiBtn(c, "tools-manage-device-"+guide.name, msg.ToolsManageOnDeviceBtn()).Clicked() {
							m.section = "设备"
						}
					}
					if uiBtn(c, "tool-"+guide.name, msg.ToolsOpenGuide()).Clicked() {
						c.OpenURL(guide.source)
					}
				})
			})
			if idx < len(allGuides)-1 {
				ui.Divider(c)
			}
		}
		m.toolInstallStatusRow(c, msg)
	})
}

func (m *Model) guide(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	step := m.guideStep
	if step < 1 || step > 3 {
		step = 1
	}

	stepIndicatorBar(c, step, []string{
		msg.GuideStep1Tab(),
		msg.GuideStep2Tab(),
		msg.GuideStep3Tab(),
	}, func(n int) { m.guideStep = n })

	ui.Text(c, msg.GuideStepOf(step, 3)).FontSize(12).TextColor(t.TextMuted)

	switch step {
	case 1:
		ui.Text(c, msg.GuideStep1Title()).FontSize(26).Bold()
		ui.Text(c, msg.GuideStep1Desc()).TextColor(t.TextMuted)

		surfaceCard(c, "guide-device-card").Padding(24, 24).Gap(14).AlignItems(ui.Center).Children(func() {
			ui.Image(c, phDeviceDuotone).Width(58).Height(58).TextColor(accentInk(t))
			if m.hasConnectedDevice() {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Row(c).Width(8).Height(8).Radius(4).Background(ui.Hex("#10B981"))
					ui.Text(c, msg.GuideStep1Connected()).Bold().FontSize(15)
				})
			} else {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					ui.Spinner(c).Label(msg.GuideStep1Waiting())
					ui.Text(c, msg.GuideStep1Waiting()).Bold().FontSize(15)
				})
			}
			ui.Text(c.Key("guide-device"), m.deviceStatusText(msg)).FontSize(13).TextColor(t.TextMuted)
			ui.Text(c, msg.GuideStep1CableHint()).FontSize(12).TextColor(t.TextMuted)
			if uiBtn(c, "guide-retry", msg.GuideRetry()).Clicked() {
				m.detectDevices()
			}
		})

		ui.Row(c).Gap(10).Children(func() {
			if uiBtn(c, "detect-later", msg.GuideConnectLater()).Clicked() {
				m.section = "准备"
			}
			if uiBtn(c, "skip-guide", msg.GuideSkip()).Clicked() {
				m.section = "准备"
			}
			if uiPrimaryBtn(c, "guide-next-1", msg.GuideContinue()).Clicked() {
				m.guideStep = 2
			}
		})

	case 2:
		ui.Text(c, msg.GuideStep2Title()).FontSize(26).Bold()
		ui.Text(c, msg.GuideStep2Desc()).TextColor(t.TextMuted)

		surfaceCard(c, "guide-ipa-card").Padding(24, 24).Gap(12).AlignItems(ui.Center).Children(func() {
			ui.Image(c, phPackageDuotone).Width(58).Height(58).TextColor(accentInk(t))
			files := m.archives()
			if len(files) > 0 {
				ui.Text(c, msg.GuideStep2Ready(len(files))).FontSize(14).Bold()
			} else {
				ui.Text(c, msg.GuideStep2Empty()).FontSize(13).TextColor(t.TextMuted)
			}
			if uiBtn(c, "guide-import-ipa", msg.ImportIPA()).Clicked() {
				m.pickIPA()
			}
		})

		ui.Row(c).Gap(10).Children(func() {
			if uiBtn(c, "guide-back-2", msg.NavBack()).Clicked() {
				m.guideStep = 1
			}
			if uiBtn(c, "skip-guide", msg.GuideSkip()).Clicked() {
				m.section = "准备"
			}
			if uiPrimaryBtn(c, "guide-next-2", msg.GuideContinue()).Clicked() {
				m.guideStep = 3
			}
		})

	case 3:
		ui.Text(c, msg.GuideStep3Title()).FontSize(26).Bold()
		ui.Text(c, msg.GuideStep3Desc()).TextColor(t.TextMuted)

		surfaceCard(c, "guide-transfer-card").Padding(20, 24).Gap(10).Children(func() {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Image(c, phPaperPlaneTiltDuotone).Width(28).Height(28).TextColor(accentInk(t))
				ui.Text(c, msg.PostInstallChecklistTitle()).Bold().FontSize(15)
			})
			ui.Text(c, msg.PostInstallStepDevMode()).FontSize(13)
			ui.Text(c, msg.PostInstallStepTrust()).FontSize(13)
			ui.Text(c, msg.PostInstallStepRefresh()).FontSize(13)
			ui.Text(c, msg.PostInstallStepLCSS()).FontSize(13)
			ui.Divider(c)
			ui.Text(c, msg.TransferNextSteps()).Bold().FontSize(14)
			ui.Text(c, msg.TransferNextStep1()).FontSize(12)
			ui.Text(c, msg.TransferNextStep2()).FontSize(12)
			ui.Text(c, msg.TransferNextStep3()).FontSize(12)
			ui.Text(c, msg.GuideStep3Note()).FontSize(12).TextColor(t.TextMuted)
			if m.services.Accounts != nil && !m.services.Accounts.Developer().SignedIn() {
				if uiBtn(c, "guide-signin-apple", msg.RoutePrecheckSignInBtn()).Clicked() {
					m.navigateToAccountForLogin("guide", "引导", 3)
				}
			}
		})
		ui.Row(c).Gap(10).Children(func() {
			if uiBtn(c, "guide-back-3", msg.NavBack()).Clicked() {
				m.guideStep = 2
			}
			if uiBtn(c, "skip-guide", msg.GuideSkip()).Clicked() {
				m.section = "准备"
			}
			if uiPrimaryBtn(c, "guide-finish", msg.GuideFinish()).Clicked() {
				m.guideStep = 1
				m.section = "准备"
			}
		})
	}

	ui.Text(c, msg.GuideSkipNote()).FontSize(12).TextColor(t.TextMuted)
}
