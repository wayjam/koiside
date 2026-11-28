// Package shell is the phase-one native window.
// It calls application services and owns no IPA or device protocol.
package shell

import (
	"context"
	"fmt"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	app "koiside/internal/app"
	"koiside/internal/appleauth"
	"koiside/internal/appstore"
	"koiside/internal/device"
	"koiside/internal/devportal"
	"koiside/internal/installer"
	"koiside/locales"
)

const (
	accentLight  = "#1769D2"
	accentDark   = "#64A8FF"
	narrowWidth  = 720
	mediumWidth  = 920
	sidebarFullW = 216
	sidebarIconW = 64
)

// Model is the window state. Tests drive it without opening a window.
type Model struct {
	services app.Services
	win      *mygo.Window

	sidebar         float32
	section         string
	lastTaskSection string
	taskStage       int // 1: Check, 2: Route, 3: Prepare, 4: Handoff/Verify, 5: Maintain
	selected        int

	sourceKind    string // "github", "self", "local"
	installRoute  string // "sidestore", "livecontainer", "advanced"
	lcPlacement   string // "inside", "outside"
	prepareMode   string // "choice", "edit"
	editIntent    string // "update", "copy"
	recoveryMode  bool
	userConfirmed bool
	maintainApp   string

	query             string
	editName          string
	editBundleID      string
	editLocalizedName string
	removePaths       map[string]bool
	showAdvanced      bool
	showLCAdvanced    bool
	showEncDetails    bool
	showLogs          bool
	sidebarCollapsed  bool
	narrowDetail      bool
	appearance        string
	language          string
	guideStep         int
	settingsSection   string

	helpTopic               string
	helpStep                int
	helpFileError           string
	shortcutLaunchURL       string
	shortcutSchedule        bool
	shortcutTroubleshooting bool

	appQuery    string
	appFilter   int // 0: all, 1: sideloaded
	deviceTab   int // 0: environment, 1: apps, 2: documents
	accountTab  int // 0: Apple Developer (signing), 1: App Store (downloads & regions)
	docTreeOpen map[string]bool

	dropped       []string
	chosen        []string
	saved         string
	dialogNote    string
	logExportMsg  string
	openPathModal bool
	openPathInput string
	openPathErr   string
	openPathShake uint64
	inspecting    bool
	inspectName   string
	inspectCancel context.CancelFunc

	exporting    bool
	exportMsg    string
	exportErr    string
	exportedPath string
	exportCancel context.CancelFunc

	files              []archiveState
	devices            []device.Device
	deviceInfo         device.Info
	deviceInfoErr      string
	deviceErr          string
	deviceApps         []device.InstalledApp
	appsQueried        bool
	sideStoreApp       *device.InstalledApp
	sideStoreEmbedded  bool
	vpnApp             *device.InstalledApp
	lcApp              *device.InstalledApp
	lcApps             []device.LiveContainerApp
	latestSideStoreLog *device.SideStoreLogSummary
	sideStoreDocs      []string
	sideStoreTree      []device.DocEntry
	docsBundleID       string
	docDeleting        string
	docDeleteMsg       string
	docDeleteErr       string
	usbVerified        bool
	devModeKnown       bool
	devModeEnabled     bool
	devModeMsg         string
	devModeErr         string
	deviceProbing      bool
	sessionErr         error
	transfer           string
	transferState      string
	transferErr        string
	transferring       bool
	transferrer        Transferrer

	loginEmail         string
	loginPassword      string
	loginRemember      bool
	loginBusy          bool
	developerRestoring bool
	loginErr           string
	anisetteInput      string
	anisetteNotice     string
	anisettePreset     string
	twoFactorPrompt    *appleauth.TwoFactorPrompt
	twoFactorRespCh    chan appleauth.TwoFactorResponse
	twoFactorCode      string
	loginVerification  loginVerification
	maxCertsList       []devportal.DevelopmentCertificate
	maxCertsRespCh     chan []string
	maxCertsSelected   map[string]bool
	portalCerts        []devportal.DevelopmentCertificate
	portalCertsLoaded  bool
	portalCertErr      string
	portalQuotaKnown   bool
	portalAppIDsAvail  int64
	portalAppIDsMax    int64
	portalAppIDs       []devportal.AppID
	appIDDeleting      string
	certsLoading       bool
	returnTarget       *accountReturnContext
	pendingToolInstall installer.ToolTarget
	pendingRevokeCert  *devportal.DevelopmentCertificate
	toolInstalling     bool
	toolInstallPct     int
	toolInstallMsg     string
	toolInstallErr     string
	toolInstallDone    bool
	shortcutExporting  string
	shortcutResults    map[string]shortcutResult
	pairingBusy        bool
	pairingMsg         string
	pairingErr         string
	directInstallOn    bool
	directPct          int
	directStage        string
	directErr          string
	directDoneMsg      string
	skipExtensionsFor  string
	lcContainerPick    map[string]string
	skipToolExtensions bool

	storeLoginEmail    string
	storeLoginPass     string
	storeLoginBusy     bool
	storeRestoring     bool
	storeLoginErr      string
	store2FAEmail      string
	store2FACode       string
	store2FARespCh     chan string
	storeQuery         string
	storeCountry       string
	storeSearching     bool
	storeSearchErr     string
	storeResults       []appstore.Software
	storeSelected      int
	storeNarrowDetail  bool
	storeVersionsBusy  bool
	storeVersionsErr   string
	storeVersions      []string
	storeSelectedVer   string
	storeDownloadBusy  bool
	storeDownloadPct   int
	storeDownloadErr   string
	storeDownloadMsg   string
	storeDownloadedIPA string

	logs []string
	mu   sync.Mutex
}

type accountReturnContext struct {
	section   string
	taskStage int
	sourceKey string // "task", "device", "guide"
}

// New returns the phase-one window state.
func New(services app.Services) *Model {
	return &Model{
		services:         services,
		sidebar:          216,
		section:          "准备",
		lastTaskSection:  "文件",
		taskStage:        1,
		sourceKind:       "local",
		installRoute:     "sidestore",
		lcPlacement:      "inside",
		prepareMode:      "choice",
		guideStep:        1,
		settingsSection:  "general",
		showLogs:         true,
		removePaths:      map[string]bool{},
		docTreeOpen:      map[string]bool{"/Documents": true},
		maxCertsSelected: map[string]bool{},
	}
}

// Content is the native view. Pass it to NewWindow. Attach the created
// window before the user can open a file dialog.
func (m *Model) Content() mygo.Content { return ui.View(m.view) }

// Attach binds the window used by file dialogs and background refresh.
func (m *Model) Attach(win *mygo.Window) { m.win = win }

// Open is the test entry. A nil window skips system dialogs.
func Open(win *mygo.Window, services app.Services) *Model {
	m := New(services)
	m.Attach(win)
	return m
}

func (m *Model) addLog(entry string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	line := fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), entry)
	m.logs = append(m.logs, line)
	if len(m.logs) > 80 {
		m.logs = m.logs[len(m.logs)-80:]
	}
	fmt.Fprintln(os.Stderr, line)
}

func (m *Model) openHelp(topic string) {
	if m.isTaskSection(m.section) {
		m.lastTaskSection = m.section
	}
	if topic != "" {
		m.startHelpGuide(topic)
		return
	}
	m.section = "工具"
}

func (m *Model) isTaskSection(sec string) bool {
	return sec == "文件" || sec == "差异" || sec == "交接" || sec == "维护"
}

func (m *Model) goTaskSection(sec string, stage int) {
	m.section = sec
	m.lastTaskSection = sec
	if stage > 0 {
		m.taskStage = stage
	}
}

func (m *Model) view(c *ui.Context) {
	dark := c.Theme().Dark
	switch m.appearanceMode() {
	case "light":
		dark = false
	case "dark":
		dark = true
	}
	applyShellTheme(c, dark)
	if c.Vibrancy() {
		c.Root().Background(ui.Transparent)
	}
	msg := m.msg(c)
	m.shortcuts(c)
	if m.section == "检查" {
		m.risk(c, msg)
		return
	}

	winW, _ := c.Size()
	compact := winW > 0 && winW < narrowWidth

	attachWorkspaceDrop := func(el ui.Element) {
		el.Transition(dropZoneTransition)
		if el.FileDragOver() {
			el.Border(2, accentInk(c.Theme())).Background(c.Theme().Selection).
				InsetShadow(0, 0, 0, 2, accentInk(c.Theme()).Alpha(0.25))
		}
		if files := el.DroppedFiles(); len(files) > 0 {
			m.dropped = append([]string(nil), files...)
			m.addLog(fmt.Sprintf("dropped %d file(s)", len(files)))
			for _, f := range files {
				m.inspect(f)
			}
			m.goTaskSection("文件", 1)
		}
	}

	if compact {
		body := ui.Column(c).Fill().Background(c.Theme().Background)
		attachWorkspaceDrop(body)
		body.Children(func() {
			m.compactTopBar(c, msg)
			ui.Scroll(c.Key("workspace-scroll")).Grow(1).FillWidth().Padding(16, 18).Children(func() {
				m.workspace(c, msg, true)
			})
			m.backgroundLoginStatus(c, msg)
		})
		m.accountReturnOverlay(c, msg, true)
		m.openPathDialog(c, msg)
		m.helpGuideModal(c, msg)
		m.toolInstallConfirmModal(c, msg)
		m.revokeCertConfirmModal(c, msg)
		m.accountModals(c, msg)
		return
	}

	sideTarget := float32(sidebarFullW)
	if m.sidebarCollapsed {
		sideTarget = sidebarIconW
	}
	ui.Row(c).Fill().Children(func() {
		sbCol := ui.Column(c.Key("sidebar-col")).Shrink(0).FillHeight().Clip()
		sideW := sbCol.AnimateTo("sidebar-w", sideTarget, ui.Snappy)
		sbCol.Width(sideW).Children(func() {
			m.sidebarView(c, msg)
		})
		right := ui.Column(c).Grow(1).MinWidth(0).FillHeight().Background(c.Theme().Background)
		attachWorkspaceDrop(right)
		right.Children(func() {
			if m.section == "准备" || m.section == "" {
				ambientGlow(c, dark)
			}
			padY, padX := float32(24), float32(30)
			if winW > 0 && winW < mediumWidth {
				padY, padX = 20, 22
			}
			ui.Scroll(c.Key("workspace-scroll")).Grow(1).FillWidth().Padding(padY, padX).Children(func() {
				m.workspace(c, msg, false)
			})
			m.backgroundLoginStatus(c, msg)
		})
	})
	m.accountReturnOverlay(c, msg, false)
	m.openPathDialog(c, msg)
	m.helpGuideModal(c, msg)
	m.toolInstallConfirmModal(c, msg)
	m.revokeCertConfirmModal(c, msg)
	m.accountModals(c, msg)
}

func (m *Model) navigateToAccountForLogin(sourceKey, backSection string, backStage int) {
	m.mu.Lock()
	m.returnTarget = &accountReturnContext{
		section:   backSection,
		taskStage: backStage,
		sourceKey: sourceKey,
	}
	m.mu.Unlock()
	m.accountTab = accountTabDeveloper
	m.section = "账号"
	if m.win != nil {
		m.win.Invalidate()
	}
}

func (m *Model) shortcuts(c *ui.Context) {
	if c.Shortcut(ui.Cmd|ui.Shift, ui.KeyO) {
		m.openPathErr = ""
		m.openPathModal = true
	} else if c.Shortcut(ui.Cmd, ui.KeyO) {
		m.pickIPA()
	}
}

// OpenPaths inspects one or more IPA files directly from disk without opening a file dialog.
func (m *Model) OpenPaths(paths []string) {
	var valid []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" {
			valid = append(valid, p)
		}
	}
	if len(valid) == 0 {
		return
	}
	if m.win == nil {
		for _, p := range valid {
			m.inspect(p)
		}
		m.goTaskSection("文件", 1)
		return
	}
	m.inspectPathsAsync(valid)
}

func (m *Model) openPathDialog(c *ui.Context, msg locales.Messages) {
	if !m.openPathModal {
		return
	}
	t := c.Theme()
	ui.Modal(c.Key("open-path-modal"), &m.openPathModal, func() {
		ui.Column(c).Width(420).Gap(12).Children(func() {
			ui.Text(c, msg.OpenPathTitle()).Bold().FontSize(16)
			ui.Text(c, msg.OpenPathDesc()).FontSize(12).TextColor(t.TextMuted)
			if m.openPathErr != "" {
				ui.Text(c.Key("open-path-err"), m.openPathErr).Role(ui.RoleStatus).FontSize(11).
					TextColor(ui.Hex("#EF4444")).Transition(feedbackBannerTransition)
			}
			input := ui.TextInput(c.Key("open-path-input"), &m.openPathInput).
				Placeholder(msg.OpenPathPlaceholder()).FillWidth().AutoFocus().Label(msg.OpenPathTitle())
			applyErrorShakeTrigger(input, "open-path-shake", m.openPathShake)
			trySubmit := input.Submitted()
			ui.Row(c).FillWidth().Gap(8).Justify(ui.End).Children(func() {
				if uiBtn(c, "open-path-cancel", msg.LibraryCancel()).Clicked() {
					m.openPathModal = false
					m.openPathErr = ""
				}
				confirm := uiPrimaryBtn(c, "open-path-confirm", msg.OpenPathConfirm())
				if strings.TrimSpace(m.openPathInput) == "" {
					confirm.Disabled(true)
				}
				if confirm.Clicked() {
					trySubmit = true
				}
			})
			if trySubmit {
				p := strings.TrimSpace(m.openPathInput)
				if p != "" {
					info, err := os.Stat(p)
					if err != nil || info.IsDir() {
						m.openPathErr = msg.OpenPathNotFound()
						m.openPathShake++
					} else {
						m.openPathModal = false
						m.openPathErr = ""
						m.openPathInput = ""
						m.OpenPaths([]string{p})
					}
				}
			}
		})
	})
}

func (m *Model) compactTopBar(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	bar := c.TitleBar()
	topPad := float32(10)
	if bar.Bottom > 0 {
		topPad = bar.Bottom + 6
	}
	ui.Column(c).FillWidth().Background(t.Surface).BorderWidth(0, 0, 1, 0).BorderColor(t.Border).
		Padding(topPad, 14, 10, 14).Gap(8).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(8).DragWindow().Children(func() {
			brandLogoBadge(c, 28)
			ui.Text(c, msg.AppTitle()).Bold().FontSize(15).Grow(1)
			if (m.isTaskSection(m.section) && m.narrowDetail) || (m.section == "商店" && m.storeNarrowDetail) {
				if uiBtn(c, "compact-back", "‹ "+msg.NavBack()).Clicked() {
					m.narrowDetail = false
					m.storeNarrowDetail = false
				}
			}
		})
		ui.ScrollHorizontal(c.Key("compact-nav-scroll")).FillWidth().Children(func() {
			ui.Row(c).Gap(6).Children(func() {
				navItems := []struct {
					id    string
					label string
				}{
					{"准备", msg.NavHome()},
					{"文件", msg.NavTask()},
					{"商店", msg.NavStore()},
					{"设备", msg.NavDevice()},
					{"账号", msg.NavAccount()},
					{"工具", msg.NavHelpTools()},
					{"设置", msg.NavSettings()},
				}
				for _, item := range navItems {
					active := m.section == item.id ||
						(item.id == "文件" && m.isTaskSection(m.section)) ||
						(item.id == "工具" && m.section == "引导")
					btn := ui.ButtonBase(c.Key("compact-nav-"+item.id)).Padding(6, 12).Radius(8).
						Label(item.label).Cursor(ui.CursorPointer).Transition(colorTransition)
					if active {
						btn.Background(ui.Transparent).Border(1, ui.Transparent)
					} else {
						btn.Background(t.Background).Border(1, t.Border)
						if btn.Hovered() {
							btn.Background(t.SurfaceHover)
						}
					}
					applyPressPose(btn, 0.975)
					btn.Children(func() {
						if active {
							ui.Box(c.Key("compact-nav-pill")).Absolute().Fill().Radius(8).
								Background(t.Selection).Border(1, accentInk(t)).PassThrough().ZIndex(-1).
								Transition(navIndicatorTransition("compact-nav"))
						}
						fg := t.Text
						if active {
							fg = accentInk(t)
						}
						ui.Text(c, item.label).FontSize(12).Bold().TextColor(fg).SingleLine().ZIndex(1)
					})
					if btn.Clicked() {
						if item.id == "文件" && m.lastTaskSection != "" {
							m.section = m.lastTaskSection
						} else {
							m.section = item.id
						}
						m.narrowDetail = false
						m.storeNarrowDetail = false
					}
				}
			})
		})
	})
}

func (m *Model) sidebarView(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	col := ui.Column(c).Fill().BorderEndWidth(1).BorderColor(t.Border)
	if c.Vibrancy() {
		if t.Dark {
			col.Background(ui.Hex("#111419").Alpha(0.65))
		} else {
			col.Background(ui.RGBA(255, 255, 255, 0.70))
		}
	} else {
		if t.Dark {
			col.Background(t.Surface)
		} else {
			col.Background(ui.Hex("#F8FAFC"))
		}
	}
	col.Children(func() {
		sidebarLogoGlow(c, t.Dark)
		bar := c.TitleBar()
		topPad := float32(16)
		if bar.Bottom > 0 {
			topPad = bar.Bottom + 10
		}
		if m.sidebarCollapsed {
			ui.Column(c.Key("sidebar-header-col")).Padding(topPad, 10, 10, 10).Gap(8).AlignItems(ui.Center).DragWindow().Children(func() {
				brandLogoBadge(c, 32)
				tog := ui.ButtonBase(c.Key("sidebar-collapse-btn")).Padding(4, 8).Radius(6).
					Label(msg.SidebarExpand()).Cursor(ui.CursorPointer).Transition(colorTransition)
				if tog.Hovered() {
					tog.Background(t.SurfaceHover)
				}
				applyPressPose(tog, 0.95)
				tog.Children(func() {
					ui.Icon(c, phCaretRight).Width(14).Height(14).TextColor(t.TextMuted)
				})
				if tog.Clicked() {
					m.sidebarCollapsed = false
				}
			})
		} else {
			ui.Row(c.Key("sidebar-header-row")).Padding(topPad, 12, 12, 14).Gap(10).AlignItems(ui.Center).DragWindow().Children(func() {
				brandLogoBadge(c, 32)
				ui.Text(c, msg.AppTitle()).Bold().FontSize(15).Grow(1)
				tog := ui.ButtonBase(c.Key("sidebar-collapse-btn")).Padding(4, 6).Radius(6).
					Label(msg.SidebarCollapse()).Cursor(ui.CursorPointer).Transition(colorTransition)
				if tog.Hovered() {
					tog.Background(t.SurfaceHover)
				}
				applyPressPose(tog, 0.95)
				tog.Children(func() {
					ui.Icon(c, phCaretLeft).Width(14).Height(14).TextColor(t.TextMuted)
				})
				if tog.Clicked() {
					m.sidebarCollapsed = true
				}
			})
		}
		navSection := m.section
		if m.isTaskSection(navSection) {
			navSection = "文件"
		} else if navSection == "引导" {
			navSection = "工具"
		}
		navIcon := func(id string, regular, filled *ui.SVG) *ui.SVG {
			if navSection == id || (id == "准备" && navSection == "") {
				return filled
			}
			return regular
		}
		if m.sidebarCollapsed {
			ui.Column(c).Padding(6, 10).Gap(4).Grow(1).FillWidth().AlignItems(ui.Center).Children(func() {
				items := []struct {
					id      string
					regular *ui.SVG
					filled  *ui.SVG
					label   string
				}{
					{"准备", phHouse, phHouseFill, msg.NavHome()},
					{"文件", phStack, phStackFill, msg.NavTask()},
					{"商店", phImport, phImport, msg.NavStore()},
					{"设备", phDevice, phDeviceFill, msg.NavDevice()},
					{"账号", phAccount, phAccountFill, msg.NavAccount()},
					{"工具", phCompass, phCompassFill, msg.NavHelpTools()},
					{"设置", phGear, phGearFill, msg.NavSettings()},
				}
				for _, it := range items {
					active := navSection == it.id || (it.id == "准备" && navSection == "")
					btn := ui.ButtonBase(c.Key("sb-icon-" + it.id)).Width(42).Height(36).Radius(8).
						Center().Label(it.label).Cursor(ui.CursorPointer).Transition(colorTransition)
					if !active && btn.Hovered() {
						btn.Background(t.SurfaceHover)
					}
					applyPressPose(btn, 0.96)
					btn.Children(func() {
						if active {
							ui.Box(c.Key("sb-collapsed-pill")).Absolute().Fill().Radius(8).
								Background(t.Selection).PassThrough().ZIndex(-1).
								Transition(navIndicatorTransition("sidebar-collapsed"))
						}
						icColor := t.TextMuted
						if active {
							icColor = accentInk(t)
						}
						ui.Icon(c, navIcon(it.id, it.regular, it.filled)).Width(18).Height(18).TextColor(icColor).ZIndex(1)
					})
					if btn.Clicked() {
						if it.id == "文件" && m.isTaskSection(m.lastTaskSection) {
							m.section = m.lastTaskSection
						} else {
							m.section = it.id
						}
					}
				}
			})
		} else {
			chosenNav := navSection
			sb := ui.Sidebar(c, &chosenNav, func() {
				sbItems := []struct {
					id      string
					regular *ui.SVG
					filled  *ui.SVG
					label   string
				}{
					{"准备", phHouse, phHouseFill, msg.NavHome()},
					{"文件", phStack, phStackFill, msg.NavTask()},
					{"商店", phImport, phImport, msg.NavStore()},
					{"设备", phDevice, phDeviceFill, msg.NavDevice()},
					{"账号", phAccount, phAccountFill, msg.NavAccount()},
					{"工具", phCompass, phCompassFill, msg.NavHelpTools()},
					{"设置", phGear, phGearFill, msg.NavSettings()},
				}
				for _, it := range sbItems {
					active := navSection == it.id || (it.id == "准备" && navSection == "")
					row := ui.SidebarItem(c, it.id, navIcon(it.id, it.regular, it.filled), it.label).
						Padding(8, 12).Gap(10).FontSize(14).Cursor(ui.CursorPointer).Transition(colorTransition)
					applyPressPose(row, 0.988)
					if active {
						row.Children(func() {
							ui.Box(c.Key("sb-active-bar")).Absolute().Left(2).Top(7).Bottom(7).Width(3).Radius(1.5).
								Background(accentInk(t)).PassThrough().
								Transition(navIndicatorTransition("sidebar"))
						})
					}
				}
			}).Padding(6, 12).Gap(4).Grow(1).FillWidth()
			if sb.Changed() {
				if chosenNav == "文件" && m.isTaskSection(m.lastTaskSection) {
					m.section = m.lastTaskSection
				} else {
					m.section = chosenNav
				}
			}
			sb.Background(ui.Transparent)
		}
		ui.Column(c).FillWidth().Padding(10, 12, 12, 12).BorderWidth(1, 0, 0, 0).BorderColor(t.Border).Children(func() {
			pinText := msg.SidebarDeviceSingle()
			connected := m.hasConnectedDevice()
			hasErr := m.deviceErr != ""
			m.mu.Lock()
			probing := m.deviceProbing
			m.mu.Unlock()
			dotColor := t.TextMuted
			if connected {
				devName := msg.DeviceCardTitle()
				if m.deviceInfo.Name != "" {
					devName = m.deviceInfo.Name
				}
				conn := "USB"
				if len(m.devices) > 0 && m.devices[0].ConnectionType != "" {
					conn = m.devices[0].ConnectionType
				}
				pinText = msg.SidebarDeviceConnected(devName, conn)
				dotColor = ui.Hex("#10B981")
			} else if hasErr {
				dotColor = ui.Hex("#EF4444")
			}
			if probing {
				pinText = msg.HelpGuideScanning()
				dotColor = accentInk(t)
			}
			if m.sidebarCollapsed {
				pinBtn := ui.ButtonBase(c.Key("sidebar-device-pin")).Width(42).Height(34).Radius(8).
					Center().Label(pinText).Background(t.Selection).Cursor(ui.CursorPointer).Transition(colorTransition)
				applyPressPose(pinBtn, 0.96)
				pinBtn.Children(func() {
					statusDot(c, "sidebar-dev-dot-collapsed", 8, dotColor, connected, probing)
				})
				if pinBtn.Clicked() {
					m.section = "设备"
				}
			} else {
				pinBtn := ui.ButtonBase(c.Key("sidebar-device-pin")).FillWidth().Padding(9, 12).Radius(9).
					Label(pinText).Background(t.Selection).Cursor(ui.CursorPointer).Transition(colorTransition)
				applyPressPose(pinBtn, 0.985)
				pinBtn.Children(func() {
					ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
						statusDot(c, "sidebar-dev-dot", 7, dotColor, connected, probing)
						ui.Text(c, pinText).FontSize(12).Bold().TextColor(t.Text).SingleLine().Grow(1)
					})
				})
				if pinBtn.Clicked() {
					m.section = "设备"
				}
			}
		})
	})
}

func (m *Model) workspace(c *ui.Context, msg locales.Messages, compact bool) {
	gap := float32(16)
	if compact {
		gap = 14
	}
	secKey := m.section
	if secKey == "" {
		secKey = "准备"
	}
	ui.Column(c.Key("workspace-" + secKey)).FillWidth().Gap(gap).Transition(workspaceEnterTransition).Children(func() {
		switch m.section {
		case "工具":
			m.tools(c, msg)
		case "引导":
			m.guide(c, msg)
		case "差异":
			m.diffView(c, msg, compact)
		case "交接":
			m.transferView(c, msg, compact)
		case "维护":
			m.maintainView(c, msg, compact)
		case "文件":
			m.filesView(c, msg, compact)
		case "商店":
			m.storeView(c, msg, compact)
		case "设备":
			m.deviceView(c, msg)
		case "账号":
			m.accountView(c, msg)
		case "设置":
			m.settingsView(c, msg)
		default:
			m.home(c, msg)
		}
	})
}

func (m *Model) home(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	ui.Column(c).FillWidth().Gap(4).Children(func() {
		ui.Text(c, msg.HomeHeroTitle()).FontSize(28).Bold().Balance()
		ui.Text(c, msg.HomeHeroSubtitle()).FontSize(13).TextColor(t.TextMuted)
	})

	m.deviceCard(c, msg)

	ui.Column(c).FillWidth().Gap(6).AlignItems(ui.Center).Children(func() {
		if primaryActionButton(c, "import", msg.HomeStartNew(), phImport).Clicked() {
			m.pickIPA()
		}
		ui.Text(c, msg.HomeImportDragHint()).FontSize(11).TextColor(t.TextMuted)
	})

	// Continue active task card if any IPA is loaded
	if file, ok := m.selectedArchive(); ok {
		baseName := filepath.Base(file.path)
		name := file.report.DisplayName
		if name == "" {
			name = baseName
		}
		stageLabel := m.currentStageSummary(msg)
		ui.Row(c).FillWidth().Margin(2, 0, 0, 0).AlignItems(ui.Center).Children(func() {
			ui.Text(c, msg.HomeContinueTask()).Bold().FontSize(14).TextColor(t.TextMuted).Grow(1)
			if len(m.archives()) == 1 {
				if uiBtn(c, "files", msg.SeeAll()).Clicked() {
					m.goTaskSection("文件", 1)
				}
			}
		})
		insetGroup(c, "home-continue-group", func() {
			row := groupRow(c, "home-continue-row", name+" · "+stageLabel, func() {
				appIconBadgeHero(c, file, 36)
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, name).Bold().FontSize(14)
					ui.Text(c, stageLabel).FontSize(12).TextColor(accentInk(t))
				})
			}, func() {
				ui.Text(c, msg.GuideContinue()).FontSize(12).Bold().TextColor(accentInk(t))
				ui.Icon(c, phCaretRight).Width(14).Height(14).TextColor(accentInk(t))
			})
			if row.Clicked() {
				if m.isTaskSection(m.lastTaskSection) {
					m.section = m.lastTaskSection
				} else {
					m.section = "文件"
				}
				m.narrowDetail = true
			}
		})
	}

	m.recentFiles(c, msg)

	// Sideloaded apps maintenance entry when device apps are queried
	if sideloaded := m.sideloadedApps(); len(sideloaded) > 0 {
		ui.Row(c).FillWidth().Margin(4, 0, 0, 0).AlignItems(ui.Center).Children(func() {
			ui.Text(c, msg.HomeSideloadedMaintain()).Bold().FontSize(14).TextColor(t.TextMuted).Grow(1)
		})
		insetGroup(c, "home-maintain-group", func() {
			limit := len(sideloaded)
			if limit > 3 {
				limit = 3
			}
			for idx, a := range sideloaded[:limit] {
				idx, a := idx, a
				row := groupRow(c, fmt.Sprintf("home-maint-%d", idx), valueOrUnknown(msg, a.Name)+" ("+a.BundleID+")", func() {
					ui.Row(c).Width(32).Height(32).Radius(8).Background(t.Selection).Center().Children(func() {
						ui.Icon(c, phRefresh).Width(16).Height(16).TextColor(accentInk(t))
					})
					ui.Column(c).Grow(1).Gap(2).Children(func() {
						ui.Text(c, valueOrUnknown(msg, a.Name)).Bold().FontSize(13)
						monoText(c, a.BundleID+" · v"+valueOrUnknown(msg, a.Version)).FontSize(11).TextColor(t.TextMuted)
					})
				}, nil)
				if row.Clicked() {
					m.maintainApp = valueOrUnknown(msg, a.Name)
					m.recoveryMode = false
					m.goTaskSection("维护", 5)
				}
				if idx < limit-1 {
					ui.Divider(c)
				}
			}
		})
	}

	// Contextual help shortcut card
	insetGroup(c, "home-help-group", func() {
		row := groupRow(c, "home-open-help", msg.HomeHelpSummaryTitle(), func() {
			ui.Icon(c, phQuestion).Width(20).Height(20).TextColor(accentInk(t))
			ui.Column(c).Grow(1).Gap(2).Children(func() {
				ui.Text(c, msg.HomeHelpSummaryTitle()).Bold().FontSize(14)
				ui.Text(c, msg.HomeHelpSummaryDesc()).FontSize(12).TextColor(t.TextMuted)
			})
		}, func() {
			ui.Text(c, msg.HomeOpenHelp()).FontSize(12).Bold().TextColor(accentInk(t))
			ui.Icon(c, phCaretRight).Width(14).Height(14).TextColor(accentInk(t))
		})
		if row.Clicked() {
			m.openHelp("")
		}
	})
}

func (m *Model) currentStageSummary(msg locales.Messages) string {
	switch m.taskStage {
	case 2:
		return msg.TaskStage2()
	case 3:
		return msg.TaskStage3()
	case 4:
		if m.transferState == "done" {
			return msg.HandoffStageBadgeTransferred()
		}
		if m.exportedPath != "" {
			return msg.HandoffStageBadgeExported()
		}
		return msg.TaskStage4()
	case 5:
		return msg.TaskStage5()
	default:
		return msg.TaskStage1()
	}
}

func (m *Model) deviceCard(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	connected := m.hasConnectedDevice()
	m.mu.Lock()
	probing := m.deviceProbing
	m.mu.Unlock()
	targetDot := t.TextMuted
	if connected {
		targetDot = ui.Hex("#10B981")
	} else if m.deviceErr != "" {
		targetDot = ui.Hex("#EF4444")
	}

	cardTitle := msg.DeviceCardTitle()
	if connected && m.deviceInfo.Name != "" {
		cardTitle = m.deviceInfo.Name
	}
	card := ui.ButtonBase(c.Key("device-card")).FillWidth().Padding(16, 20).
		Radius(14).Background(t.Surface).
		Label(cardTitle + " · " + m.deviceStatusText(msg) + " · " + m.sideStoreSummaryText(msg)).
		Cursor(ui.CursorPointer).Transition(colorTransition)
	if t.Dark {
		card.Border(1, t.Border).InsetShadow(0, 1, 0, 0, ui.RGBA(255, 255, 255, 0.06))
	} else {
		card.Shadow(0, 1, 4, 0, ui.RGBA(15, 23, 42, 0.05)).Border(1, t.Border.Alpha(0.85))
	}
	if card.Hovered() {
		card.Background(t.SurfaceHover)
	}
	applyPressPose(card, 0.992)
	card.Children(func() {
		ui.Row(c).FillWidth().Gap(16).AlignItems(ui.Center).Children(func() {
			ui.Image(c, phoneBadgeSVG).Width(32).Height(54)
			ui.Column(c).Grow(1).Gap(4).Children(func() {
				ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
					title := msg.DeviceCardTitle()
					if connected && m.deviceInfo.Name != "" {
						title = m.deviceInfo.Name
					}
					ui.Text(c, title).Bold().FontSize(16)
					statusDot(c, "home-dev-dot", 8, targetDot, connected, probing)
				})
				ui.Row(c).FillWidth().Wrap().Gap(6).AlignItems(ui.Center).Children(func() {
					ui.Text(c.Key("device"), m.deviceStatusText(msg)).FontSize(13).TextColor(t.TextMuted)
					ui.Text(c, "·").FontSize(12).TextColor(t.TextMuted)
					ui.Text(c, m.sideStoreSummaryText(msg)).FontSize(12).TextColor(t.TextMuted)
				})
			})
			rowCaret(c, card, 16)
		})
	})
	if card.Clicked() {
		m.section = "设备"
	}
}

func (m *Model) recentFiles(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	files := m.archives()
	if len(files) == 1 {
		// Already shown in "Continue Current Task" right above; avoid repeating the exact same item.
		return
	}
	ui.Row(c).FillWidth().Margin(4, 0, 0, 0).AlignItems(ui.Center).Children(func() {
		ui.Text(c, msg.RecentFiles()).Bold().FontSize(14).TextColor(t.TextMuted).Grow(1)
		if uiBtn(c, "files", msg.SeeAll()).Clicked() {
			m.goTaskSection("文件", 1)
		}
	})
	if len(files) == 0 {
		insetGroup(c, "recent-empty-group", func() {
			ui.Row(c).FillWidth().Padding(14, 16).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Image(c, phPackageDuotone).Width(22).Height(22).TextColor(t.TextMuted)
				ui.Text(c, msg.NoRecentFiles()).TextColor(t.TextMuted).FontSize(13)
			})
		})
		return
	}
	limit := len(files)
	if limit > 3 {
		limit = 3
	}
	insetGroup(c, "recent-files-group", func() {
		for i := 0; i < limit; i++ {
			i, file := i, files[i]
			baseName := filepath.Base(file.path)
			name := file.report.DisplayName
			if name == "" {
				name = baseName
			}
			sub := msg.LibraryFileInfo(baseName, valueOrUnknown(msg, file.report.Version))
			if file.sizeBytes > 0 {
				sub = sub + " · " + formatBytes(file.sizeBytes)
			}
			row := groupRow(c, fmt.Sprintf("recent-%d", i), name, func() {
				appIconBadge(c, file, 36)
				ui.Column(c).Grow(1).Gap(2).Children(func() {
					ui.Text(c, name).Bold().FontSize(14)
					monoText(c, sub).FontSize(11).TextColor(t.TextMuted)
				})
			}, nil).Description(sub)
			if row.Clicked() {
				m.selectArchiveIndex(i)
				m.goTaskSection("文件", 1)
				m.narrowDetail = true
			}
			if i < limit-1 {
				ui.Divider(c)
			}
		}
	})
}

func (m *Model) choiceNote(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	if m.exporting {
		ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Spinner(c).Label(msg.DiffExporting())
			ui.Text(c, msg.DiffExporting()).FontSize(12).TextColor(accentInk(t))
		})
		return
	}
	if m.exportErr != "" {
		ui.Text(c.Key("export-err"), msg.DiffExportFailed(friendlyError(msg, m.exportErr))).FontSize(12).TextColor(ui.Hex("#EF4444"))
		return
	}
	if m.exportMsg != "" {
		ui.Column(c.Key("export-ok-box")).FillWidth().Padding(10, 12).Gap(8).Radius(10).
			Background(t.Selection).Border(1, ui.Hex("#10B981")).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, phCheckCircleFill).Width(16).Height(16).TextColor(ui.Hex("#10B981"))
				ui.Text(c.Key("export-ok"), m.exportMsg).FontSize(12).TextColor(t.Text).Grow(1)
			})
			if m.exportedPath != "" {
				if uiBtn(c, "export-handoff-now", msg.TransferAfterExportAction()).Clicked() {
					m.goTaskSection("交接", 4)
				}
			}
		})
		return
	}
	if m.dialogNote == "" && m.saved == "" && len(m.chosen) == 0 {
		return
	}
	text := m.dialogNote
	switch {
	case m.saved != "":
		text = msg.DialogWillSaveTo(m.saved)
	case len(m.chosen) > 0:
		text = msg.DialogSelectedFiles(len(m.chosen))
	}
	ui.Text(c.Key("choice"), text).FontSize(12).TextColor(t.TextMuted)
}

func (m *Model) ime(c *ui.Context, msg locales.Messages) {
	t := c.Theme()
	ui.Text(c, msg.DiffDisplayName()).FontSize(12).TextColor(t.TextMuted)
	field := ui.TextInput(c.Key("display-name"), &m.query).Placeholder(msg.DiffDisplayNamePlaceholder()).FillWidth().Label(msg.DiffDisplayName())
	if field.Composing() {
		ui.Text(c.Key("composition"), "…")
	}
}

func (m *Model) risk(c *ui.Context, msg locales.Messages) {
	open := true
	ui.Modal(c.Key("risk-dialog"), &open, func() {
		ui.Text(c, msg.RiskTitle()).Bold()
		ui.Text(c, msg.RiskBody())
		if uiPrimaryBtn(c, "risk-ok", msg.RiskAck()).Clicked() {
			m.section = "准备"
		}
	})
}

func (m *Model) pickIPA() {
	if m.win == nil {
		m.dialogNote = m.msg(nil).DialogNoWindowOpen()
		return
	}
	win := m.win
	title := m.msg(nil).ImportIPA()
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent:   win,
			Title:    title,
			Filters:  []mygo.FileFilter{{Name: "iOS App", Extensions: []string{"ipa"}}},
			Multiple: true,
		})
		win.Update(func() {
			msg := m.msg(nil)
			switch {
			case err != nil:
				m.dialogNote = msg.DialogOpenFailed(friendlyError(msg, err.Error()))
				m.chosen = nil
			case len(paths) == 0:
				m.dialogNote = msg.DialogOpenCanceled()
				m.chosen = nil
			default:
				m.dialogNote = ""
				m.chosen = append([]string(nil), paths...)
				m.inspectPathsAsync(paths)
			}
		})
	}()
}

// SaveCopy asks where to write a new IPA. Cancel leaves the path empty.
func (m *Model) SaveCopy() {
	if m.win == nil {
		m.dialogNote = m.msg(nil).DialogNoWindowSave()
		return
	}
	win := m.win
	msg := m.msg(nil)
	defaultName := msg.DialogExportDefaultFilename()
	if file, ok := m.selectedArchive(); ok {
		base := filepath.Base(file.path)
		ext := filepath.Ext(base)
		stem := base[:len(base)-len(ext)]
		if stem != "" {
			defaultName = stem + "-koiside.ipa"
		}
	}
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent:      win,
			Title:       msg.DiffExportBtn(),
			DefaultPath: defaultName,
			Filters:     []mygo.FileFilter{{Name: "iOS App", Extensions: []string{"ipa"}}},
		})
		win.Update(func() {
			curMsg := m.msg(nil)
			switch {
			case err != nil:
				m.dialogNote = curMsg.DialogSaveFailed(friendlyError(curMsg, err.Error()))
				m.saved = ""
			case path == "":
				m.dialogNote = curMsg.DialogSaveCanceled()
				m.saved = ""
			default:
				m.dialogNote = ""
				m.saved = path
				m.exportSelectedAsync(path)
			}
		})
	}()
}

func accent(dark bool) string {
	if dark {
		return accentDark
	}
	return accentLight
}
