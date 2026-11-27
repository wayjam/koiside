package shell

import (
	"testing"
)

func TestAnisettePresetDropdown(t *testing.T) {
	m, tt := newTest(t, false)
	m.section = "账号"
	m.accountTab = accountTabDeveloper
	// Ensure fresh test state defaults to jkcoxson preset
	m.anisettePreset = anisettePresetJkcoxson
	m.anisetteInput = "https://" + anisettePresetJkcoxson
	tt.Frame()

	// 1. Initial view: dropdown displays mac-ani.jkcoxson.com
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
	if m.anisettePreset != anisettePresetSideStore {
		t.Fatalf("expected preset %q, got %q", anisettePresetSideStore, m.anisettePreset)
	}

	// 4. Verify custom option exists in select options
	customLabel := m.msg(nil).AccountAnisetteCustom()
	if err := tt.Click(anisettePresetSideStore); err != nil {
		t.Fatalf("failed to re-open select: %v", err)
	}
	tt.Frame()
	if !tt.HasText(customLabel) {
		t.Fatalf("expected option %q, got: %v", customLabel, tt.Texts())
	}
}
