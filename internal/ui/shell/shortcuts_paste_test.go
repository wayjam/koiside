package shell

import (
	"strings"
	"testing"

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
}
