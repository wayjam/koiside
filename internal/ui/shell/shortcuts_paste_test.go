package shell

import (
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"koiside/internal/device"
	"koiside/internal/shortcuts"
)

func TestShortcutPasteUniversalClipboard(t *testing.T) {
	m, tt := newTest(t, false)
	tt.SetClipboard("  livecontainer://livecontainer-launch?bundle-name=Demo.app  ")
	if err := tt.Click("侧载帮助"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("给容器 App 添加桌面入口"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("粘贴启动链接"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.shortcutLaunchURL, "Demo.app") {
		t.Fatalf("expected clipboard text to be set in input, got %q", m.shortcutLaunchURL)
	}
	if !shortcuts.ValidLaunchURL(m.shortcutLaunchURL) {
		t.Fatalf("expected valid launch URL from pasted clipboard, got %q", m.shortcutLaunchURL)
	}
	if _, ok := tt.AccessByRole(ui.RoleButton, "已粘贴"); !ok {
		t.Fatal("paste did not confirm on the button")
	}
	tt.Advance(2 * time.Second)
	if _, ok := tt.AccessByRole(ui.RoleButton, "粘贴启动链接"); !ok {
		t.Fatal("paste button did not restore its action label")
	}
}
func TestShortcutLaunchExportRendersLCSharedAndContainerOptions(t *testing.T) {
	m, tt := newTest(t, false)
	msg := m.msg(nil)
	m.lcApp = &device.InstalledApp{BundleID: "com.kdt.livecontainer", TeamID: "TEAM"}
	m.lcApps = []device.LiveContainerApp{
		{
			Folder:    "PiliPlus.app",
			Name:      "PiliPlus",
			BundleID:  "com.example.piliplus",
			Version:   "2.2.1",
			InfoKnown: true,
			Shared:    true,
			Multitask: 2,
			DataUUID:  "DATA-1",
			Containers: []device.LCContainer{
				{FolderName: "DATA-1", Name: "主数据"},
				{FolderName: "DATA-2", Name: "分身数据"},
			},
		},
	}
	for _, label := range []string{"侧载帮助", msg.HelpGuideLaunchShortcut()} {
		if err := tt.Click(label); err != nil {
			t.Fatal(err)
		}
	}
	tt.Frame()
	if !tt.HasText("PiliPlus") || !tt.HasText("已共享") || !tt.HasText("多任务：开") {
		t.Fatalf("expected guest card with shared and multitask status, got %q", tt.Texts())
	}
	if !tt.HasText("主数据") || !tt.HasText("分身数据") {
		t.Fatalf("expected container choices visible for guest with 2 containers, got %q", tt.Texts())
	}
}

func TestRefreshShortcutConfirmationAndDisclosure(t *testing.T) {
	m, tt := newTest(t, false)
	msg := m.msg(nil)
	m.sideStoreApp = &device.InstalledApp{BundleID: "com.SideStore.SideStore", TeamID: "TEAM"}
	m.lcApp = &device.InstalledApp{BundleID: "com.kdt.livecontainer", TeamID: "TEAM"}
	m.sideStoreEmbedded = true
	for _, label := range []string{"侧载帮助", msg.HelpGuideRefreshShortcut()} {
		if err := tt.Click(label); err != nil {
			t.Fatal(err)
		}
	}
	m.shortcutResults = map[string]shortcutResult{helpShortcutRefresh: {
		path: "refresh.shortcut", button: "shortcut-refresh-sidestore", confirmedUntil: tt.Now().Add(shortcutConfirmationDuration),
	}}
	tt.Frame()
	if _, ok := tt.AccessByRole(ui.RoleButton, msg.HelpGuideExportDone()); !ok {
		t.Fatal("successful export did not update its button")
	}
	if _, ok := tt.AccessByRole(ui.RoleButton, msg.HelpGuideExportLive()); !ok {
		t.Fatal("export changed the other host's button")
	}
	for _, label := range []string{msg.HelpGuideNext() + " →", msg.HelpGuideNext() + " →", msg.HelpGuideSchedule()} {
		if err := tt.Click(label); err != nil {
			t.Fatal(err)
		}
	}
	tt.Advance(250 * time.Millisecond)
	if disclosure, ok := tt.AccessByRole(ui.RoleDisclosure, msg.HelpGuideSchedule()); !ok || !disclosure.Expanded {
		t.Fatalf("scheduled refresh disclosure should be expanded, got %+v (found %v)", disclosure, ok)
	}
	if !tt.HasText(strings.Split(msg.HelpGuideScheduleSteps(), "\n")[0]) {
		t.Fatal("expanded disclosure did not reveal the automation steps")
	}
}

func TestLCLaunchTargetUsesPickedContainer(t *testing.T) {
	m, _ := newTest(t, false)
	app := device.LiveContainerApp{
		Folder:   "PiliPlus.app",
		DataUUID: "DATA-1",
		Containers: []device.LCContainer{
			{FolderName: "DATA-1", Name: "Default"},
			{FolderName: "DATA-2", Name: "Second"},
		},
	}
	if got := shortcuts.LaunchURL(m.lcLaunchTarget(app)); strings.Contains(got, "container-folder-name") {
		t.Fatalf("the default container must not be addressed explicitly, got %q", got)
	}
	m.lcContainerPick = map[string]string{"PiliPlus.app": "DATA-2"}
	got := shortcuts.LaunchURL(m.lcLaunchTarget(app))
	if !strings.Contains(got, "container-folder-name=DATA-2") {
		t.Fatalf("picked container missing from %q", got)
	}
}
