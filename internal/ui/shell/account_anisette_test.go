package shell

import (
	"testing"
)

func TestAnisettePresetDropdown(t *testing.T) {
	m, tt := newTest(t, false)
	m.section = "账号"
	m.accountTab = accountTabDeveloper
	tt.Frame()

	// 1. Initial view: dropdown defaults to mac-ani.jkcoxson.com
	if !tt.HasText(anisettePresetJkcoxson) {
		t.Fatalf("expected default preset %q in text, got: %v", anisettePresetJkcoxson, tt.Texts())
	}
	// Custom input field should not show when a preset is selected
	if tt.HasText(m.msg(nil).AccountAnisetteCustom()) {
		t.Fatal("custom address input should be hidden when preset selected")
	}

	// 2. Click select trigger to open options
	if err := tt.Click(anisettePresetJkcoxson); err != nil {
		t.Fatalf("failed to click select trigger: %v", err)
	}
	tt.Frame()
	if !tt.HasText(anisettePresetSideStore) {
		t.Fatalf("expected option %q, got: %v", anisettePresetSideStore, tt.Texts())
	}

	// 3. Choose new.ani.sidestore.io
	if err := tt.Click(anisettePresetSideStore); err != nil {
		t.Fatalf("failed to choose SideStore preset: %v", err)
	}
	tt.Frame()
	if m.services.Accounts.AnisetteURL() != "https://"+anisettePresetSideStore {
		t.Fatalf("expected updated AnisetteURL %q, got %q", "https://"+anisettePresetSideStore, m.services.Accounts.AnisetteURL())
	}

	// 4. Choose custom
	customLabel := m.msg(nil).AccountAnisetteCustom()
	if err := tt.Click(anisettePresetSideStore); err != nil {
		t.Fatalf("failed to re-open select: %v", err)
	}
	tt.Frame()
	if err := tt.Click(customLabel); err != nil {
		t.Fatalf("failed to choose custom: %v", err)
	}
	tt.Frame()
	if !tt.HasText(m.msg(nil).AccountAnisetteSaveBtn()) {
		t.Fatal("expected custom Save URL button to appear")
	}
}
