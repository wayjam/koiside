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
