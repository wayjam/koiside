package shell

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"koiside/internal/account"
	app "koiside/internal/app"
	"koiside/internal/appleauth"
	"koiside/internal/appstore"
	"koiside/internal/device"
	"koiside/internal/devportal"
	"koiside/internal/ipa"
)

func newTest(t *testing.T, dark bool) (*Model, *ui.Tester) {
	t.Helper()
	m := Open(nil, app.New())
	tt := ui.NewTester(m.view, 1180, 860)
	if dark {
		tt.SetDark(true)
	}
	return m, tt
}

func TestHomeShowsNextStep(t *testing.T) {
	m, tt := newTest(t, false)
	if err := tt.Click("侧载新的 App"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("还没有导入 IPA") || !tt.HasText("设备：未连接") || !tt.HasText("打开侧载帮助") {
		t.Fatalf("texts %q", tt.Texts())
	}
	if m.services.Accounts.Store().SignedIn() {
		t.Fatal("store session is signed in")
	}
}

func TestRecentFileOpensDetail(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sample.ipa")
	if err := os.WriteFile(file, []byte("not an ipa"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, tt := newTest(t, false)
	if tt.HasText("把 IPA 拖到这里") {
		t.Fatal("home should not render duplicate drop zone")
	}
	box, ok := tt.Find("侧载新的 App")
	if !ok {
		t.Fatal("primary import button missing")
	}
	if !tt.DropFiles(box.X+box.W/2, box.Y+box.H/2, file) {
		t.Fatal("drop was not accepted")
	}
	if err := tt.Click("sample.ipa"); err != nil {
		t.Fatal(err)
	}
	if m.section != "文件" || !tt.HasText("无法读取此 IPA") {
		t.Fatalf("section %s texts %q", m.section, tt.Texts())
	}
}

func TestGuideCanBeSkippedAndStepped(t *testing.T) {
	m, tt := newTest(t, false)
	if err := tt.Click("侧载帮助"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("SideStore 设置与恢复"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("第 1 步，共 3 步") || !tt.HasText("连接 iPhone") {
		t.Fatalf("step 1 texts %q", tt.Texts())
	}
	if err := tt.Click("继续"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("第 2 步，共 3 步") || !tt.HasText("准备并检查 IPA") {
		t.Fatalf("step 2 texts %q", tt.Texts())
	}
	if err := tt.Click("继续"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("第 3 步，共 3 步") || !tt.HasText("交接给 SideStore") {
		t.Fatalf("step 3 texts %q", tt.Texts())
	}
	if err := tt.Click("完成并前往首页"); err != nil {
		t.Fatal(err)
	}
	if m.section != "准备" || !tt.HasText("把想用的 App 装到 iPhone") {
		t.Fatalf("section %s texts %q", m.section, tt.Texts())
	}

	// Re-enter via help and skip
	if err := tt.Click("侧载帮助"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("SideStore 设置与恢复"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("跳过引导"); err != nil {
		t.Fatal(err)
	}
	if m.section != "准备" {
		t.Fatalf("expected home after skip, got %s", m.section)
	}
}

func TestRiskDialogHidesTheWindow(t *testing.T) {
	m, tt := newTest(t, true)
	m.section = "检查"
	tt.Frame()
	if _, ok := tt.AccessByRole(ui.RoleButton, "知道了"); !ok {
		t.Fatal("dialog button missing")
	}
	if _, ok := tt.AccessByRole(ui.RoleButton, "侧载新的 App"); ok {
		t.Fatal("import stays exposed behind the dialog")
	}
	if err := tt.Click("知道了"); err != nil {
		t.Fatal(err)
	}
	if m.section != "准备" {
		t.Fatalf("section %s", m.section)
	}
}

func TestDeviceAndTransferStayDistinct(t *testing.T) {
	m, tt := newTest(t, false)
	m.SetDevices([]device.Device{{ID: 1, ConnectionType: "USB"}}, nil)
	m.SetTransfer("sample.ipa", device.Transfer{Path: "Documents/sample.ipa"}, nil)
	m.section = "交接"
	m.taskStage = 4
	tt.Frame()
	if !tt.HasText("交接：文件已传送，尚未安装") || tt.HasText("已检测到匹配应用") {
		t.Fatalf("texts %q", tt.Texts())
	}
	m.section = "设备"
	tt.Frame()
	if !tt.HasText("设备：USB 已连接") {
		t.Fatalf("device texts %q", tt.Texts())
	}
}

type fakeTransfer struct{ err error }

func (f fakeTransfer) PutIPA(string) (device.Transfer, error) {
	if f.err != nil {
		return device.Transfer{}, f.err
	}
	return device.Transfer{Path: "Documents/sample.ipa", SHA256: "abc"}, nil
}

type recordingTransfer struct {
	err        error
	lastSource string
}

func (f *recordingTransfer) PutIPA(source string) (device.Transfer, error) {
	f.lastSource = source
	if f.err != nil {
		return device.Transfer{}, f.err
	}
	return device.Transfer{Path: "/Documents/" + filepath.Base(source), SHA256: "abc"}, nil
}

func TestHandoffUsesExportedPathWhenPresent(t *testing.T) {
	m, tt := newTest(t, false)
	tr := &recordingTransfer{}
	m.mu.Lock()
	m.files = []archiveState{{path: "/tmp/orig.ipa", ready: true}}
	m.exportedPath = "/tmp/edited-koiside.ipa"
	m.transferrer = tr
	m.section = "交接"
	m.taskStage = 4
	m.mu.Unlock()
	tt.Frame()
	if err := tt.Click("传送到 SideStore"); err != nil {
		t.Fatal(err)
	}
	if tr.lastSource != "/tmp/edited-koiside.ipa" {
		t.Fatalf("expected exportedPath to be transferred, got %q", tr.lastSource)
	}
	if !tt.HasText("交接：文件已传送，尚未安装") || !tt.HasText("edited-koiside.ipa") {
		t.Fatalf("texts %q", tt.Texts())
	}
}
func TestDeviceViewRendersDisconnectedAndConnected(t *testing.T) {
	m, tt := newTest(t, false)
	m.section = "设备"
	tt.Frame()
	if !tt.HasText("设备未连接") || !tt.HasText("离线使用") {
		t.Fatalf("disconnected texts %q", tt.Texts())
	}

	m.SetDevices([]device.Device{{ID: 1, ConnectionType: "USB"}}, nil)
	tt.Frame()
	if !tt.HasText("设备：USB 已连接") || !tt.HasText("SideStore") || !tt.HasText("运行状态未知") {
		t.Fatalf("connected texts %q", tt.Texts())
	}
	if err := tt.Click("查看工具指引"); err != nil {
		t.Fatal(err)
	}
	if m.section != "工具" {
		t.Fatalf("expected help/tools section, got %s", m.section)
	}
}

func TestHelpAndToolsHubRendersTroubleshootingAndOfficialSources(t *testing.T) {
	m, tt := newTest(t, false)
	m.section = "工具"
	tt.Frame()
	if !tt.HasText("SideStore") || !tt.HasText("LocalDevVPN") || !tt.HasText("LiveContainer") {
		t.Fatalf("tools view missing guides: %q", tt.Texts())
	}
	if !tt.HasText("设备连不上，或未弹出“信任”") || !tt.HasText("App 快到期或刷新失败") {
		t.Fatalf("help hub missing troubleshooting topics: %q", tt.Texts())
	}
}

func TestSettingsViewAllowsThemeAndLanguageToggle(t *testing.T) {
	m, tt := newTest(t, false)
	m.section = "设置"
	tt.Frame()
	if !tt.HasText("外观") || !tt.HasText("跟随系统") || !tt.HasText("隐私与本地数据") {
		t.Fatalf("settings missing items: %q", tt.Texts())
	}
	if err := tt.Click("深色"); err != nil {
		t.Fatal(err)
	}
	if m.appearanceMode() != "dark" {
		t.Fatalf("expected dark theme, got %s", m.appearanceMode())
	}
	if err := tt.Click("浅色"); err != nil {
		t.Fatal(err)
	}
	if m.appearanceMode() != "light" {
		t.Fatalf("expected light theme, got %s", m.appearanceMode())
	}

	// Switch language to English live
	if err := tt.Click("English"); err != nil {
		t.Fatal(err)
	}
	if m.currentLanguage() != "en" {
		t.Fatalf("expected en language, got %s", m.currentLanguage())
	}
	if !tt.HasText("Settings") || !tt.HasText("Appearance") || !tt.HasText("Logs stay on this Mac") {
		t.Fatalf("english settings missing: %q", tt.Texts())
	}
	if err := tt.Click("Home"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("Install your own app on iPhone") || !tt.HasText("Sideload New App") {
		t.Fatalf("english home missing: %q", tt.Texts())
	}

	// Switch back to Chinese
	if err := tt.Click("Settings"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("简体中文"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("设置") || !tt.HasText("外观") {
		t.Fatalf("zh-Hans settings missing: %q", tt.Texts())
	}
}

func TestTesterLocaleFollowsSystemWhenUnset(t *testing.T) {
	_, tt := newTest(t, false)
	tt.SetLocale("en")
	if !tt.HasText("Install your own app on iPhone") || !tt.HasText("Sideload Task") {
		t.Fatalf("expected English via Tester.SetLocale, got %q", tt.Texts())
	}
	tt.SetLocale("zh-Hans")
	if !tt.HasText("把想用的 App 装到 iPhone") || !tt.HasText("侧载任务") {
		t.Fatalf("expected Chinese via Tester.SetLocale, got %q", tt.Texts())
	}
}

func TestEndToEndTaskFlowRoutePrepareConflictHandoffVerifyAndMaintain(t *testing.T) {
	m, tt := newTest(t, false)
	m.SetSnapshot(device.Snapshot{
		Device: device.Device{ID: 1, UDID: "UDID-1", ConnectionType: "USB"},
		Info:   device.Info{Name: "Lumia1530", Version: "27.0.1", Type: "iPhone13,3"},
		Apps: []device.InstalledApp{
			{BundleID: "com.SideStore.SideStore.8K49", Name: "SideStore", Version: "0.7.0", TeamID: "8K49", Signer: "iPhone Developer: test"},
			{BundleID: "com.example.orbit.8K49", Name: "Orbit", Version: "1.1.0", TeamID: "8K49", Signer: "iPhone Developer: test"},
		},
		SideStore:     &device.InstalledApp{BundleID: "com.SideStore.SideStore.8K49", Name: "SideStore", Version: "0.7.0", TeamID: "8K49"},
		SideStoreDocs: []string{"Orbit.ipa"},
		USBVerified:   true,
	}, nil)
	m.mu.Lock()
	m.transferrer = fakeTransfer{}
	m.files = []archiveState{
		{
			path:  "Orbit.ipa",
			ready: true,
			report: ipa.Report{
				DisplayName: "Orbit",
				BundleID:    "com.example.orbit",
				Version:     "1.2.0",
			},
		},
	}
	m.section = "文件"
	m.taskStage = 1
	m.mu.Unlock()
	tt.Frame()

	// Stage 1 -> Stage 2 (Route selection)
	if !tt.HasText("可以继续准备") {
		t.Fatalf("stage 1 ready banner missing: %q", tt.Texts())
	}
	if err := tt.Click("选择安装方式"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("选择适合你的安装方式") {
		t.Fatalf("stage 2 missing: %q", tt.Texts())
	}
	// Evaluate LiveContainer
	if err := tt.Click("在 LiveContainer 里运行"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("选择安装在 LiveContainer 里面还是外面") {
		t.Fatalf("LiveContainer placement missing: %q", tt.Texts())
	}
	// Choose SideStore route and continue to Stage 3
	if err := tt.Click("独立安装 · 免费个人签名（推荐）"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("按此路线继续"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("要修改这个 IPA 吗？") || !tt.HasText("设备上已存在匹配标识：Orbit (com.example.orbit.8K49 · v1.1.0)") {
		t.Fatalf("stage 3 prepare or conflict missing: %q", tt.Texts())
	}

	// Continue as-is -> Stage 4 (Handoff & Verify)
	if err := tt.Click("按原样交接"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("交接与安装确认") || !tt.HasText("设备已检测到安装") {
		t.Fatalf("stage 4 verify missing: %q", tt.Texts())
	}

	// User confirms -> Stage 5 (Maintain & Recovery)
	if err := tt.Click("我已确认安装，查看续签维护"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("维护与 7 天续签") {
		t.Fatalf("stage 5 maintain missing: %q", tt.Texts())
	}
	if err := tt.Click("刷新失败或已到期？"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("SideStore 刷新失败或应用已到期") {
		t.Fatalf("recovery view missing: %q", tt.Texts())
	}
}

func TestDiffViewShowsBeforeAfterComparisonAndAdvancedRemoval(t *testing.T) {
	m, tt := newTest(t, false)
	m.mu.Lock()
	m.files = []archiveState{
		{
			path:  "Orbit.ipa",
			ready: true,
			report: ipa.Report{
				DisplayName: "Orbit",
				BundleID:    "com.example.orbit",
				Version:     "1.2.0",
				Components: []ipa.Component{
					{Path: "Payload/Orbit.app", Kind: "app", BundleID: "com.example.orbit"},
					{Path: "Payload/Orbit.app/PlugIns/Widget.appex", Kind: "extension", BundleID: "com.example.orbit.widget"},
				},
			},
		},
	}
	m.editName = "Orbit Lab"
	m.editBundleID = "com.example.orbitlab"
	m.section = "文件"
	m.taskStage = 1
	m.mu.Unlock()
	tt.Frame()

	// Toggle advanced details collapsible and mark extension for removal via Switch
	if err := tt.Click("高级详情"); err != nil {
		t.Fatal(err)
	}
	tt.Advance(250 * time.Millisecond)
	sw, ok := tt.AccessByRole(ui.RoleSwitch, "移除：Payload/Orbit.app/PlugIns/Widget.appex (扩展)")
	if !ok {
		t.Fatalf("removal switch missing, texts: %q", tt.Texts())
	}
	tt.ClickAt(sw.Bounds.X+sw.Bounds.W/2, sw.Bounds.Y+sw.Bounds.H/2)
	if err := tt.Click("准备修改与导出"); err != nil {
		t.Fatal(err)
	}

	if !tt.HasText("修改差异") || !tt.HasText("预览变更") || !tt.HasText("修改前") || !tt.HasText("修改后") {
		t.Fatalf("diff view missing before/after: %q", tt.Texts())
	}
	if !tt.HasText("修改后需要重新签名") || !tt.HasText("移除") {
		t.Fatalf("diff view missing warning or removal item: %q", tt.Texts())
	}
	if err := tt.Click("返回"); err != nil {
		t.Fatal(err)
	}
	if m.section != "文件" || m.taskStage != 3 {
		t.Fatalf("expected back to stage 3 prepare choice, got section=%s stage=%d", m.section, m.taskStage)
	}
}

func TestEncryptedAndCheckingStates(t *testing.T) {
	m, tt := newTest(t, true)
	m.mu.Lock()
	m.files = []archiveState{
		{
			path:  "StoreApp.ipa",
			ready: true,
			report: ipa.Report{
				DisplayName: "StoreApp",
				BundleID:    "com.example.store",
				Findings: []ipa.Finding{
					{Code: "fairplay", Severity: ipa.Block, Detail: "encrypted"},
				},
			},
		},
	}
	m.section = "文件"
	m.taskStage = 1
	m.mu.Unlock()
	tt.Frame()
	if !tt.HasText("IPA 已加密（FairPlay）") || !tt.HasText("选择其他 IPA") {
		t.Fatalf("encrypted state missing: %q", tt.Texts())
	}
	if err := tt.Click("查看详情"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("检查记录：") {
		t.Fatalf("encrypted details did not expand: %q", tt.Texts())
	}

	// Checking state with cancel
	m.mu.Lock()
	m.inspecting = true
	m.inspectName = "Checking.ipa"
	m.mu.Unlock()
	tt.Frame()
	if !tt.HasText("正在检查 IPA…") || !tt.HasText("Checking.ipa") {
		t.Fatalf("checking state missing: %q", tt.Texts())
	}
	if err := tt.Click("取消"); err != nil {
		t.Fatal(err)
	}
	if m.inspecting {
		t.Fatal("inspecting should be false after cancel")
	}
}

func TestNarrowWindowSwitchesToCompactNavigationAndDetailBack(t *testing.T) {
	m, tt := newTest(t, false)
	m.mu.Lock()
	m.files = []archiveState{
		{
			path:  "Orbit.ipa",
			ready: true,
			report: ipa.Report{
				DisplayName: "Orbit",
				BundleID:    "com.example.orbit",
				Version:     "1.2.0",
			},
		},
	}
	m.section = "文件"
	m.taskStage = 1
	m.mu.Unlock()

	tt.SetSize(640, 560)
	if err := tt.Click("Orbit"); err != nil {
		t.Fatal(err)
	}
	if !m.narrowDetail || !tt.HasText("‹ 返回") {
		t.Fatalf("expected narrow detail mode with back button, texts %q", tt.Texts())
	}
	if err := tt.Click("‹ 返回"); err != nil {
		t.Fatal(err)
	}
	if m.narrowDetail {
		t.Fatal("expected narrowDetail=false after back")
	}
}

func TestSetSnapshotDisplaysDetectedToolsAndApps(t *testing.T) {
	m, tt := newTest(t, false)
	m.SetSnapshot(device.Snapshot{
		Device: device.Device{ID: 1, UDID: "UDID-1", ConnectionType: "USB"},
		Info:   device.Info{Name: "Lumia1530", Version: "27.0.1", Build: "24A446", Type: "iPhone13,3"},
		Apps: []device.InstalledApp{
			{BundleID: "com.SideStore.SideStore.8K49", Name: "SideStore", Version: "0.7.0", TeamID: "8K49", Signer: "iPhone Developer: test"},
			{BundleID: "com.jkcoxson.LocalDevVPN", Name: "LocalDevVPN", Version: "1.3.0"},
		},
		SideStore:     &device.InstalledApp{BundleID: "com.SideStore.SideStore.8K49", Name: "SideStore", Version: "0.7.0", TeamID: "8K49"},
		LocalDevVPN:   &device.InstalledApp{BundleID: "com.jkcoxson.LocalDevVPN", Name: "LocalDevVPN", Version: "1.3.0"},
		SideStoreDocs: []string{"Aidoku-v0.9.ipa"},
		USBVerified:   true,
	}, nil)
	tt.Frame()

	if !tt.HasText("Lumia1530") || !tt.HasText("SideStore: 已检测到") {
		t.Fatalf("home snapshot missing: %q", tt.Texts())
	}
	if err := tt.Click("设备"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("型号：iPhone13,3 · 系统：27.0.1 (24A446)") || !tt.HasText("已检测到 (0.7.0) · 运行状态未知") {
		t.Fatalf("device snapshot missing: %q", tt.Texts())
	}
	if !tt.HasText("USB 文件共享就绪 · 文稿容器可访问") || !tt.HasText("SideStore 文稿目录 (/Documents)") || !tt.HasText("Aidoku-v0.9.ipa") {
		t.Fatalf("sidestore status or docs tree missing: %q", tt.Texts())
	}
	if tt.HasText("文稿容器可读") {
		t.Fatalf("sidestore status should not dump filenames inline: %q", tt.Texts())
	}
}

func TestDarkToLightSwitchResetsAllThemeTokens(t *testing.T) {
	m, tt := newTest(t, true)
	m.section = "设置"
	m.appearance = "dark"
	tt.Frame()

	if err := tt.Click("浅色"); err != nil {
		t.Fatal(err)
	}
	if m.appearanceMode() != "light" {
		t.Fatalf("expected light mode, got %s", m.appearanceMode())
	}
	// Check rendered pixel background on top-right workspace is light (#F3F5F8) and not dark (#111419)
	img := ui.Render(m.view, 960, 640, 1)
	c := img.RGBAAt(600, 30)
	if c.R < 220 || c.G < 220 || c.B < 220 {
		t.Fatalf("expected light background pixel after dark->light switch, got %+v", c)
	}

	// Verify dark mode switches back to dark background
	if err := tt.Click("深色"); err != nil {
		t.Fatal(err)
	}
	imgDark := ui.Render(m.view, 960, 640, 1)
	cd := imgDark.RGBAAt(600, 30)
	if cd.R > 40 || cd.G > 45 || cd.B > 55 {
		t.Fatalf("expected dark background pixel after light->dark switch, got %+v", cd)
	}
}

func TestDeviceDocTreeAndAppSearchFilter(t *testing.T) {
	m, tt := newTest(t, false)
	m.SetSnapshot(device.Snapshot{
		Device: device.Device{ID: 1, UDID: "UDID-1", ConnectionType: "USB"},
		Info:   device.Info{Name: "Lumia1530", Version: "27.0.1", Type: "iPhone13,3"},
		Apps: []device.InstalledApp{
			{BundleID: "com.SideStore.SideStore.8K49", Name: "SideStore", Version: "0.7.0", TeamID: "8K49", Signer: "iPhone Developer: test"},
			{BundleID: "com.tencent.xin", Name: "微信", Version: "8.0.80", TeamID: "HKB8"},
			{BundleID: "com.jkcoxson.LocalDevVPN", Name: "LocalDevVPN", Version: "1.3.0"},
		},
		SideStore:     &device.InstalledApp{BundleID: "com.SideStore.SideStore.8K49", Name: "SideStore", Version: "0.7.0", TeamID: "8K49"},
		LocalDevVPN:   &device.InstalledApp{BundleID: "com.jkcoxson.LocalDevVPN", Name: "LocalDevVPN", Version: "1.3.0"},
		SideStoreDocs: []string{"Apps", "Aidoku-v0.9.ipa"},
		SideStoreTree: []device.DocEntry{
			{
				Name:  "Apps",
				Path:  "/Documents/Apps",
				IsDir: true,
				Children: []device.DocEntry{
					{Name: "NestedApp.ipa", Path: "/Documents/Apps/NestedApp.ipa", Size: 2048},
				},
			},
			{Name: "Aidoku-v0.9.ipa", Path: "/Documents/Aidoku-v0.9.ipa", Size: 4096},
		},
		USBVerified: true,
	}, nil)
	m.section = "设备"
	tt.Frame()

	if !tt.HasText("Apps") || tt.HasText("NestedApp.ipa") {
		t.Fatalf("expected collapsed nested dir initially, texts: %q", tt.Texts())
	}
	if err := tt.Click("Apps"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("NestedApp.ipa") {
		t.Fatalf("expected expanded folder contents, texts: %q", tt.Texts())
	}

	// All apps visible initially, filter by search query
	if !tt.HasText("微信") || !tt.HasText("LocalDevVPN") {
		t.Fatalf("expected all apps shown in default All filter, texts: %q", tt.Texts())
	}
	m.mu.Lock()
	m.appQuery = "com.tencent"
	m.mu.Unlock()
	tt.Frame()
	if !tt.HasText("微信") || tt.HasText("com.jkcoxson.LocalDevVPN") {
		t.Fatalf("expected search filter to keep WeChat only, texts: %q", tt.Texts())
	}

	// Switch to sideloaded filter where WeChat (App Store) is excluded
	m.mu.Lock()
	m.appQuery = ""
	m.appFilter = 1
	m.mu.Unlock()
	tt.Frame()
	if tt.HasText("微信") || !tt.HasText("SideStore") {
		t.Fatalf("expected sideloaded filter to exclude App Store WeChat, texts: %q", tt.Texts())
	}
}

func TestExportLogsToFile(t *testing.T) {
	m, tt := newTest(t, false)
	m.addLog("sample diagnostic line")
	out := filepath.Join(t.TempDir(), "koiside-logs.txt")
	if err := m.ExportLogsTo(out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "sample diagnostic line") {
		t.Fatalf("exported log missing content: %q", string(data))
	}
	m.section = "设置"
	tt.Frame()
	if !tt.HasText("日志已导出：" + out) {
		t.Fatalf("settings missing export status: %q", tt.Texts())
	}
}

type fakeAccountManager struct {
	signedIn    bool
	email       string
	fullName    string
	anisetteURL string
	saved       []string
}

func (f *fakeAccountManager) Store() account.StoreSession { return account.Unavailable{}.Store() }
func (f *fakeAccountManager) SignInStore(context.Context, string, string, account.StoreCodeFunc) error {
	return nil
}
func (f *fakeAccountManager) RestoreStoreSession(context.Context) error { return nil }
func (f *fakeAccountManager) SignOutStore()                             {}
func (f *fakeAccountManager) SwitchStoreAccount(string) error           { return nil }
func (f *fakeAccountManager) ForgetStoreAccount(string) error           { return nil }
func (f *fakeAccountManager) SavedStoreAccounts() []account.StoreAccountSummary {
	return nil
}
func (f *fakeAccountManager) StoreClient() *appstore.Client { return appstore.NewClient() }
func (f *fakeAccountManager) UpdateStoreCookies(string, []appstore.Cookie) {
}
func (f *fakeAccountManager) Developer() account.DeveloperSession {
	return fakeDevSess{f: f}
}
func (f *fakeAccountManager) SignInDeveloper(_ context.Context, email, _ string, remember bool, on2FA appleauth.TwoFactorFunc) error {
	if on2FA != nil {
		resp, err := on2FA(context.Background(), appleauth.TwoFactorPrompt{})
		if err != nil {
			return err
		}
		if resp.Action == appleauth.ActionAbort {
			return context.Canceled
		}
	}
	f.signedIn = true
	f.email = email
	if remember {
		f.saved = append(f.saved, email)
	}
	return nil
}
func (f *fakeAccountManager) SignInSavedDeveloper(ctx context.Context, email string, on2FA appleauth.TwoFactorFunc) error {
	return f.SignInDeveloper(ctx, email, "pw", false, on2FA)
}
func (f *fakeAccountManager) RestoreDeveloperSession(context.Context) error { return nil }
func (f *fakeAccountManager) SignOutDeveloper()                             { f.signedIn = false }
func (f *fakeAccountManager) ForgetSavedAccount(string) error               { return nil }
func (f *fakeAccountManager) SavedAccounts() []string                       { return f.saved }
func (f *fakeAccountManager) AnisetteURL() string {
	if f.anisetteURL == "" {
		return appleauth.DefaultAnisetteV3URL
	}
	return f.anisetteURL
}
func (f *fakeAccountManager) SetAnisetteURL(u string)                  { f.anisetteURL = u }
func (f *fakeAccountManager) ResetAnisetteState(context.Context) error { return nil }
func (f *fakeAccountManager) Storage() appleauth.Storage               { return appleauth.NewMemoryStorage() }
func (f *fakeAccountManager) DeveloperPortal() (*devportal.Session, error) {
	return nil, context.Canceled
}

type fakeDevSess struct{ f *fakeAccountManager }

func (s fakeDevSess) SignedIn() bool   { return s.f.signedIn }
func (s fakeDevSess) Email() string    { return s.f.email }
func (s fakeDevSess) FullName() string { return s.f.fullName }
func (s fakeDevSess) Teams() []devportal.Team {
	return []devportal.Team{{TeamID: "T1", Name: "Ada", Type: "Individual"}}
}
func (s fakeDevSess) ActiveTeam() (devportal.Team, bool) {
	return devportal.Team{TeamID: "T1", Name: "Ada", Type: "Individual"}, true
}
func (s fakeDevSess) SelectTeam(string) bool { return true }

func TestAccountViewAnisette2FAAndToolsActions(t *testing.T) {
	mgr := &fakeAccountManager{fullName: "Ada Lovelace"}
	m := Open(nil, app.Services{Accounts: mgr})
	tt := ui.NewTester(m.view, 1180, 860)

	if err := tt.Click("Apple 账号"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("未登录 Apple 账号") && !tt.HasText("登录 Apple 账号") {
		t.Fatalf("account sign-in form missing: %q", tt.Texts())
	}
	if !tt.HasText("Anisette v3 服务") || !tt.HasText("App Store 下载与开发者签名保持独立会话") {
		t.Fatalf("anisette/store boundary missing: %q", tt.Texts())
	}
	if err := tt.Click("重置设备证明状态"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("Anisette 设备证明状态已清除") {
		t.Fatalf("expected anisette reset notice: %q", tt.Texts())
	}

	// Trigger 2FA modal and submit 6-digit code
	done := make(chan appleauth.TwoFactorResponse, 1)
	go func() {
		resp, err := m.prompt2FA(context.Background(), appleauth.TwoFactorPrompt{
			Numbers: []appleauth.TrustedNumber{{ID: 1, NumberWithDialCode: "+86 ••••1234", LastTwoDigits: "1234"}},
		})
		if err == nil {
			done <- resp
		}
	}()
	time.Sleep(30 * time.Millisecond)
	m.mu.Lock()
	m.twoFactorCode = "654321"
	m.mu.Unlock()
	tt.Frame()
	if !tt.HasText("双重认证验证码") {
		t.Fatalf("2FA modal not visible: %q", tt.Texts())
	}
	if err := tt.Click("验证并继续"); err != nil {
		t.Fatal(err)
	}
	resp := <-done
	if resp.Action != appleauth.ActionSubmitCode || resp.Code != "654321" {
		t.Fatalf("unexpected 2FA response: %+v", resp)
	}

	// Signed-in state shows team & certs section
	mgr.signedIn = true
	mgr.email = "ada@example.com"
	tt.Frame()
	if !tt.HasText("已登录：ada@example.com") || !tt.HasText("开发证书与 App ID 名额") {
		t.Fatalf("signed-in account view missing details: %q", tt.Texts())
	}

	// Device view exposes SideStore/LiveContainer install, LocalDevVPN App Store, Pairing, and Developer Mode controls
	m.SetSnapshot(device.Snapshot{
		Device:               device.Device{ID: 1, UDID: "UDID-1", ConnectionType: "USB"},
		Info:                 device.Info{Name: "iPhone", Version: "27.0", Type: "iPhone17,1"},
		DeveloperModeKnown:   true,
		DeveloperModeEnabled: false,
	}, nil)
	if err := tt.Click("设备"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("安装 SideStore") || !tt.HasText("安装 LiveContainer + SideStore") || !tt.HasText("打开 App Store 安装 LocalDevVPN") || !tt.HasText("生成并写入配对文件") || !tt.HasText("开启开发者模式") || !tt.HasText("开发者模式：未开启（无法启动侧载应用）") {
		t.Fatalf("device view missing phase 2 install/pairing/devmode actions: %q", tt.Texts())
	}
	// Post-install checklist renders after tool installation completes
	m.mu.Lock()
	m.toolInstallDone = true
	m.toolInstallMsg = "安装完成：com.SideStore.SideStore.T1"
	m.mu.Unlock()
	tt.Frame()
	if !tt.HasText("安装后在 iPhone 上的必做步骤") || !tt.HasText("VPN 与设备管理") {
		t.Fatalf("expected post-install Developer Mode & Trust checklist: %q", tt.Texts())
	}
}

func TestRoutePrecheckLoginFloatingOverlayReturnAndLCPlacement(t *testing.T) {
	mgr := &fakeAccountManager{fullName: "Ada Lovelace"}
	m := Open(nil, app.Services{Accounts: mgr})
	tt := ui.NewTester(m.view, 1180, 860)

	m.SetSnapshot(device.Snapshot{
		Device: device.Device{ID: 1, UDID: "UDID-1", ConnectionType: "USB"},
		Info:   device.Info{Name: "Lumia1530", Version: "27.0.1", Type: "iPhone13,3"},
		Apps: []device.InstalledApp{
			{BundleID: "com.kdt.livecontainer.8K49", Name: "LiveContainer", Version: "3.8.14", TeamID: "8K49", Signer: "Apple Development: ada@example.com"},
			{BundleID: "com.example.other.8K49", Name: "OtherApp", Version: "1.0.0", TeamID: "8K49"},
		},
		LiveContainer: &device.InstalledApp{BundleID: "com.kdt.livecontainer.8K49", Name: "LiveContainer", Version: "3.8.14", TeamID: "8K49"},
		USBVerified:   true,
	}, nil)
	if len(m.sideloadedApps()) != 2 {
		t.Fatalf("expected LiveContainer team apps in sideloadedApps, got %+v", m.sideloadedApps())
	}

	m.mu.Lock()
	m.files = []archiveState{{
		path:  "PiliPlus.ipa",
		ready: true,
		report: ipa.Report{
			DisplayName: "PiliPlus",
			BundleID:    "com.example.piliplus",
			Version:     "2.2.1",
		},
	}}
	m.section = "文件"
	m.taskStage = 2
	m.mu.Unlock()
	tt.Frame()

	// Pick LiveContainer route and verify inside/outside choice + login jump button
	if err := tt.Click("在 LiveContainer 里运行"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("选择安装在 LiveContainer 里面还是外面") || !tt.HasText("去登录 Apple 账号") {
		t.Fatalf("route precheck or LC placement missing: %q", tt.Texts())
	}
	if err := tt.Click("装在 LiveContainer 外面（主屏幕独立 App）"); err != nil {
		t.Fatal(err)
	}
	if m.lcPlacement != "outside" {
		t.Fatalf("expected lcPlacement=outside, got %q", m.lcPlacement)
	}
	if err := tt.Click("装在 LiveContainer 里面（推荐节省名额）"); err != nil {
		t.Fatal(err)
	}

	// Jump to Apple Account from Task Route -> floating return overlay appears
	if err := tt.Click("去登录 Apple 账号"); err != nil {
		t.Fatal(err)
	}
	if m.section != "账号" || !tt.HasText("返回继续") || !tt.HasText("关闭") {
		t.Fatalf("floating return overlay missing on account page: section=%s texts=%q", m.section, tt.Texts())
	}

	// Simulate login completed -> overlay updates and Return jumps back to Task Route
	mgr.signedIn = true
	mgr.email = "ada@example.com"
	tt.Frame()
	if !tt.HasText("已登录 ada@example.com。点击「返回继续」即可回到刚才的侧载流程。") {
		t.Fatalf("expected ready return message: %q", tt.Texts())
	}
	if err := tt.Click("返回继续"); err != nil {
		t.Fatal(err)
	}
	if m.section != "文件" || m.taskStage != 2 {
		t.Fatalf("expected return to task stage 2, got section=%s stage=%d", m.section, m.taskStage)
	}

	// Advance to Stage 4 (Handoff): LC inside shows Send to LiveContainer Documents + switch to outside option
	m.goTaskSection("交接", 4)
	tt.Frame()
	if !tt.HasText("写入 LiveContainer 文稿") || !tt.HasText("改到容器外面独立安装") {
		t.Fatalf("expected LC inside handoff controls: %q", tt.Texts())
	}
	if err := tt.Click("改到容器外面独立安装"); err != nil {
		t.Fatal(err)
	}
	if m.lcPlacement != "outside" || !tt.HasText("改到容器里面安装") {
		t.Fatalf("expected switch to outside in stage 4: placement=%s texts=%q", m.lcPlacement, tt.Texts())
	}
}

func TestOpenByPathModalAndOpenPaths(t *testing.T) {
	ipaPath := filepath.Join(t.TempDir(), "test.ipa")
	if err := os.WriteFile(ipaPath, []byte("not-a-zip"), 0o644); err != nil {
		t.Fatal(err)
	}

	m, tt := newTest(t, false)
	if err := tt.Click("侧载任务"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("输入路径打开…"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("从本地路径打开 IPA") {
		t.Fatalf("open-by-path modal missing: %q", tt.Texts())
	}

	// Missing file stays open with error message
	m.openPathInput = filepath.Join(t.TempDir(), "missing.ipa")
	tt.Frame()
	if err := tt.Click("打开并检查"); err != nil {
		t.Fatal(err)
	}
	if !m.openPathModal || !tt.HasText("找不到该路径或路径是文件夹，请检查后重试。") {
		t.Fatalf("expected missing path error, modal=%v texts=%q", m.openPathModal, tt.Texts())
	}

	// Existing file closes modal and inspects file
	m.openPathInput = ipaPath
	tt.Frame()
	if err := tt.Click("打开并检查"); err != nil {
		t.Fatal(err)
	}
	if m.openPathModal || len(m.archives()) != 1 || m.archives()[0].path != ipaPath {
		t.Fatalf("expected modal closed and archive loaded, modal=%v files=%+v", m.openPathModal, m.archives())
	}
}

func TestSourceKindSegmentedWrapsWithinBounds(t *testing.T) {
	m, tt := newTest(t, false)
	m.mu.Lock()
	m.files = []archiveState{{
		path:  "PiliPlus.ipa",
		ready: true,
		report: ipa.Report{
			DisplayName: "PiliPlus",
			BundleID:    "com.example.piliplus",
			Version:     "2.2.1",
		},
	}}
	m.section = "文件"
	m.taskStage = 1
	m.mu.Unlock()

	for _, sz := range [][2]int{{960, 640}, {540, 460}} {
		tt.SetSize(sz[0], sz[1])
		if sz[0] < 720 {
			m.narrowDetail = true
			tt.Frame()
		}
		group, ok := tt.AccessByRole(ui.RoleRadioGroup, "文件来源备注")
		if !ok {
			t.Fatalf("%dx%d: source radio group missing", sz[0], sz[1])
		}
		for _, label := range []string{"开源项目发布包（GitHub Release）", "自己构建 / 导出的包", "本地 IPA（来源未知）"} {
			opt, ok := tt.AccessByRole(ui.RoleRadio, label)
			if !ok {
				t.Fatalf("%dx%d: radio %q missing", sz[0], sz[1], label)
			}
			if opt.Bounds.X+opt.Bounds.W > group.Bounds.X+group.Bounds.W+1 {
				t.Fatalf("%dx%d: option %q overflowed group: opt=%+v group=%+v", sz[0], sz[1], label, opt.Bounds, group.Bounds)
			}
		}
	}

	if err := tt.Click("自己构建 / 导出的包"); err != nil {
		t.Fatal(err)
	}
	if m.sourceKind != "self" {
		t.Fatalf("expected sourceKind=self after click, got %q", m.sourceKind)
	}
}

func TestEmbeddedSideStoreInLiveContainerDetection(t *testing.T) {
	m, tt := newTest(t, false)
	m.SetSnapshot(device.Snapshot{
		Device: device.Device{ID: 1, UDID: "UDID-LC", ConnectionType: "USB"},
		Info:   device.Info{Name: "Lumia1530", Version: "27.0.1", Type: "iPhone13,3"},
		Apps: []device.InstalledApp{
			{BundleID: "com.kdt.livecontainer.8K49", Name: "LiveContainer", Version: "3.8.14", TeamID: "8K49", Signer: "iPhone Developer: test"},
		},
		LiveContainer: &device.InstalledApp{BundleID: "com.kdt.livecontainer.8K49", Name: "LiveContainer", Version: "3.8.14", TeamID: "8K49"},
		SideStoreTree: []device.DocEntry{
			{Name: "SideStore", Path: "/Documents/SideStore", IsDir: true},
		},
		DocsBundleID: "com.kdt.livecontainer.8K49",
		USBVerified:  true,
	}, nil)
	tt.Frame()
	if !tt.HasText("SideStore: 已内置 (LiveContainer)") {
		t.Fatalf("expected embedded SideStore summary on home: %q", tt.Texts())
	}
	if err := tt.Click("设备"); err != nil {
		t.Fatal(err)
	}
	if st, ok := tt.AccessByRole(ui.RoleStatus, "已内置于 LiveContainer"); !ok || st.Name != "已内置于 LiveContainer" {
		t.Fatalf("expected embedded SideStore status, got %+v texts=%q", st, tt.Texts())
	}
	if !tt.HasText("LiveContainer 文稿目录 (/Documents)") {
		t.Fatalf("expected LC docs title: %q", tt.Texts())
	}
}

func TestToolInstallConfirmModalAndLCAdvancedGuides(t *testing.T) {
	m, tt := newTest(t, false)
	m.SetSnapshot(device.Snapshot{
		Device:            device.Device{ID: 1, UDID: "UDID-LC", ConnectionType: "USB"},
		Info:              device.Info{Name: "Lumia1530", Version: "27.0.1", Type: "iPhone13,3"},
		LiveContainer:     &device.InstalledApp{BundleID: "com.kdt.livecontainer.8K49", Name: "LiveContainer", Version: "3.8.14", TeamID: "8K49"},
		SideStoreEmbedded: true,
		USBVerified:       true,
	}, nil)

	if err := tt.Click("设备"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("安装 SideStore"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("确认安装 SideStore") || !tt.HasText("LiveContainer + SideStore 合装版") {
		t.Fatalf("expected tool confirm modal with conflict warning: %q", tt.Texts())
	}
	if err := tt.Click("取消"); err != nil {
		t.Fatal(err)
	}
	if m.pendingToolInstall != "" || tt.HasText("确认安装 SideStore") {
		t.Fatalf("expected confirm modal closed after cancel")
	}

	// Stage 4 LiveContainer inside includes collapsible Shared App + Shortcuts guide
	m.mu.Lock()
	m.installRoute = "livecontainer"
	m.lcPlacement = "inside"
	m.section = "交接"
	m.taskStage = 4
	m.mu.Unlock()
	tt.Frame()
	if !tt.HasText("进阶用法：同时运行多个 App & 添加到桌面") {
		t.Fatalf("expected LC advanced usage collapsible in stage 4: %q", tt.Texts())
	}
}

func TestRevokeCertConfirmModalAndArchiveRemove(t *testing.T) {
	m, tt := newTest(t, false)
	m.mu.Lock()
	m.files = []archiveState{{path: "A.ipa", ready: true, report: ipa.Report{DisplayName: "AppA", BundleID: "com.example.a"}}}
	m.section = "文件"
	m.taskStage = 1
	m.mu.Unlock()
	tt.Frame()
	if err := tt.Click("移除"); err != nil {
		t.Fatal(err)
	}
	if len(m.archives()) != 0 {
		t.Fatalf("expected archive removed, got %d", len(m.archives()))
	}

	m.mu.Lock()
	m.pendingRevokeCert = &devportal.DevelopmentCertificate{
		Name:         "iOS Development",
		SerialNumber: "SER123",
		MachineName:  "koiside",
	}
	m.mu.Unlock()
	tt.Frame()
	if !tt.HasText("确认吊销开发证书？") || !tt.HasText("SER123") {
		t.Fatalf("expected revoke cert confirm modal: %q", tt.Texts())
	}
	if err := tt.Click("取消"); err != nil {
		t.Fatal(err)
	}
	if m.pendingRevokeCert != nil {
		t.Fatal("expected pendingRevokeCert cleared on cancel")
	}
}

func TestSidebarCollapseToIconRailAndResponsiveBreakpoints(t *testing.T) {
	m, tt := newTest(t, false)
	tt.SetSize(960, 640)
	if m.sidebarCollapsed {
		t.Fatal("sidebar should start expanded")
	}
	if err := tt.Click("收起侧栏"); err != nil {
		t.Fatal(err)
	}
	if !m.sidebarCollapsed {
		t.Fatal("expected sidebarCollapsed=true after clicking collapse")
	}
	// Collapsed icon rail still switches sections
	if err := tt.Click("设备"); err != nil {
		t.Fatal(err)
	}
	if m.section != "设备" {
		t.Fatalf("expected section=设备 from icon rail, got %s", m.section)
	}
	if err := tt.Click("展开侧栏"); err != nil {
		t.Fatal(err)
	}
	if m.sidebarCollapsed {
		t.Fatal("expected sidebarCollapsed=false after clicking expand")
	}

	// Medium window (800x600) stacks two-column task layouts cleanly without clipping
	m.mu.Lock()
	m.files = []archiveState{{
		path:  "PiliPlus.ipa",
		ready: true,
		report: ipa.Report{
			DisplayName: "PiliPlus",
			BundleID:    "com.example.piliplus",
			Version:     "2.2.1",
		},
	}}
	m.section = "文件"
	m.taskStage = 2
	m.mu.Unlock()
	tt.SetSize(800, 600)
	if !tt.HasText("按此路线继续") || !tt.HasText("PiliPlus") {
		t.Fatalf("medium window stage 2 missing content: %q", tt.Texts())
	}
}

func TestStoreViewAndSinfWorkbenchDirectInstall(t *testing.T) {
	m, tt := newTest(t, false)
	if err := tt.Click("商店"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("App Store 获取") || !tt.HasText("尚未登录 App Store 账号") {
		t.Fatalf("expected store view text, got %q", tt.Texts())
	}

	m.mu.Lock()
	m.storeResults = []appstore.Software{
		{ID: 1, Name: "FirstApp", BundleID: "com.example.first", Version: "1.0.0", FormattedPrice: "Free"},
		{ID: 2, Name: "SecondApp", BundleID: "com.example.second", Version: "2.3.4", FormattedPrice: "Free", ArtistName: "Acme"},
	}
	m.storeSelected = 0
	m.mu.Unlock()
	tt.Frame()
	if err := tt.Click("SecondApp"); err != nil {
		t.Fatal(err)
	}
	if !tt.HasText("com.example.second") || !tt.HasText("Acme") {
		t.Fatalf("expected second app detail visible in right pane, got %q", tt.Texts())
	}

	// Compact breakpoint drills into detail view and supports returning via top-bar back button
	tt.SetSize(600, 560)
	if err := tt.Click("FirstApp"); err != nil {
		t.Fatal(err)
	}
	if !m.storeNarrowDetail || !tt.HasText("com.example.first") {
		t.Fatalf("expected compact drill-down to FirstApp, storeNarrowDetail=%v texts=%q", m.storeNarrowDetail, tt.Texts())
	}
	if err := tt.Click("‹ 返回"); err != nil {
		t.Fatal(err)
	}
	if m.storeNarrowDetail || !tt.HasText("SecondApp") {
		t.Fatalf("expected compact back to restore search list, storeNarrowDetail=%v texts=%q", m.storeNarrowDetail, tt.Texts())
	}
	tt.SetSize(1180, 860)

	m.mu.Lock()
	m.files = []archiveState{{
		path:  "/tmp/WeChat.ipa",
		ready: true,
		report: ipa.Report{
			DisplayName: "WeChat",
			BundleID:    "com.tencent.xin",
			Version:     "8.0.50",
			HasSinf:     true,
			Findings:    []ipa.Finding{{Code: "fairplay", Severity: ipa.Block}},
		},
	}}
	m.selected = 0
	m.section = "文件"
	m.taskStage = 1
	m.mu.Unlock()
	tt.Frame()
	if !tt.HasText("已包含 App Store 授权 (SINF)") || !tt.HasText("直接通过 USB 安装正版包") {
		t.Fatalf("expected Store SINF direct install option in workbench, got %q", tt.Texts())
	}
}

func TestMotionTransitionsAndReduceMotionRespect(t *testing.T) {
	m := Open(nil, app.New())
	tt := ui.NewTesterWith(m.view, 1180, 860, ui.TesterOptions{
		Preferences: ui.Preferences{ReduceMotion: false, TextScale: 1},
	})

	// 1. Sidebar collapse smoothly interpolates width and settles cleanly
	if err := tt.Click("收起侧栏"); err != nil {
		t.Fatal(err)
	}
	if !m.sidebarCollapsed {
		t.Fatal("expected sidebar collapsed")
	}
	if err := tt.Click("展开侧栏"); err != nil {
		t.Fatal(err)
	}
	if m.sidebarCollapsed {
		t.Fatal("expected sidebar expanded")
	}

	// 2. Navigation switching and device status pulse transition cleanly
	m.devices = []device.Device{{ID: 1, ConnectionType: "USB"}}
	tt.Frame()
	if err := tt.Click("设置"); err != nil {
		t.Fatal(err)
	}
	if m.section != "设置" {
		t.Fatalf("expected section=设置, got %s", m.section)
	}

	// 3. Invalid bundle ID triggers error feedback and shake path without panic
	m.files = []archiveState{{
		path:  "/tmp/Demo.ipa",
		ready: true,
		report: ipa.Report{
			DisplayName: "Demo",
			BundleID:    "com.example.demo",
			Version:     "1.0.0",
		},
	}}
	m.selected = 0
	m.section = "差异"
	m.editBundleID = "bad bundle id!"
	tt.Frame()
	if !tt.HasText("Bundle ID") {
		t.Fatalf("expected diff view bundle ID error, texts=%q", tt.Texts())
	}

	// 4. ReduceMotion keeps all interactions & progress states immediate and valid
	tt.SetPreferences(ui.Preferences{ReduceMotion: true, TextScale: 1})
	m.mu.Lock()
	m.toolInstalling = true
	m.toolInstallPct = 65
	m.toolInstallMsg = "upload_ipa"
	m.mu.Unlock()
	m.section = "设备"
	tt.Frame()
	if err := tt.Click("首页"); err != nil {
		t.Fatal(err)
	}
	if m.section != "准备" {
		t.Fatalf("expected section=准备 under ReduceMotion, got %s", m.section)
	}
}
