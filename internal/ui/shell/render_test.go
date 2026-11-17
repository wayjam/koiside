package shell

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/egoist/mygo/ui"

	app "koiside/internal/app"
	"koiside/internal/device"
	"koiside/internal/ipa"
)

func TestRenderScreenshots(t *testing.T) {
	outDir := filepath.Join(os.TempDir(), "koiside_visual")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}

	services := app.New()

	renderAndSave := func(filename string, w, h int, dark bool, lang string, setup func(m *Model)) {
		m := Open(nil, services)
		if dark {
			m.appearance = "dark"
		} else {
			m.appearance = "light"
		}
		m.language = lang
		if setup != nil {
			setup(m)
		}

		img := ui.Render(m.view, w, h, 2)
		outPath := filepath.Join(outDir, filename)
		f, err := os.Create(outPath)
		if err != nil {
			t.Fatalf("failed to create %s: %v", outPath, err)
		}
		defer f.Close()
		if err := png.Encode(f, img); err != nil {
			t.Fatalf("failed to encode %s: %v", outPath, err)
		}
		t.Logf("Saved %s (%dx%d)", outPath, img.Bounds().Dx(), img.Bounds().Dy())
	}

	sampleFiles := []archiveState{
		{
			path:      "/Users/test/Orbit_1.2.0.ipa",
			sizeBytes: 28400000,
			ready:     true,
			report: ipa.Report{
				DisplayName: "Orbit",
				BundleID:    "com.example.orbit",
				Version:     "1.2.0",
				MachOs:      []ipa.MachO{{Arch: "arm64"}},
				Components: []ipa.Component{
					{Path: "Payload/Orbit.app", Kind: "app", BundleID: "com.example.orbit", MinimumOS: "16.0"},
					{Path: "Payload/Orbit.app/PlugIns/Widget.appex", Kind: "extension", BundleID: "com.example.orbit.widget"},
				},
				Findings: []ipa.Finding{{Code: "provenance", Severity: ipa.Unknown}},
			},
		},
		{
			path:      "/Users/test/Stream_3.1.0.ipa",
			sizeBytes: 62700000,
			ready:     true,
			report: ipa.Report{
				DisplayName: "Stream",
				BundleID:    "com.example.stream",
				Version:     "3.1.0",
				MachOs:      []ipa.MachO{{Arch: "arm64"}},
			},
		},
	}

	// 1. Home view (zh-Hans & en)
	renderAndSave("01_home_light_zh.png", 960, 640, false, "zh-Hans", func(m *Model) {
		m.section = "准备"
		m.devices = []device.Device{{ID: 1, ConnectionType: "USB"}}
		m.files = sampleFiles
		m.taskStage = 2
	})
	renderAndSave("01_home_dark_en.png", 960, 640, true, "en", func(m *Model) {
		m.section = "准备"
		m.devices = []device.Device{{ID: 1, ConnectionType: "USB"}}
		m.files = sampleFiles
	})

	// 2. Task Stage 2 (Route selection) & Stage 3 (Prepare choice)
	renderAndSave("02_route_light_zh.png", 960, 640, false, "zh-Hans", func(m *Model) {
		m.section = "文件"
		m.taskStage = 2
		m.installRoute = "livecontainer"
		m.files = sampleFiles
	})
	renderAndSave("02_prepare_choice_dark_en.png", 960, 640, true, "en", func(m *Model) {
		m.section = "文件"
		m.taskStage = 3
		m.files = sampleFiles
	})

	// 3. Edit & Review Diff
	renderAndSave("03_diff_dark_en.png", 960, 640, true, "en", func(m *Model) {
		m.section = "差异"
		m.files = sampleFiles
		m.selected = 0
		m.editName = "Orbit Lab"
		m.editBundleID = "com.example.orbitlab"
	})

	// 4. Handoff & Maintain
	renderAndSave("04_transfer_verify_zh.png", 960, 640, false, "zh-Hans", func(m *Model) {
		m.section = "交接"
		m.files = sampleFiles
		m.transferState = "done"
		m.usbVerified = true
	})
	renderAndSave("05_maintain_dark_zh.png", 960, 640, true, "zh-Hans", func(m *Model) {
		m.section = "维护"
		m.files = sampleFiles
	})

	// 5. Help & Settings & Compact
	renderAndSave("06_help_hub_light_zh.png", 960, 640, false, "zh-Hans", func(m *Model) {
		m.section = "工具"
		m.lastTaskSection = "交接"
	})
	renderAndSave("07_device_tree_light_zh.png", 960, 640, false, "zh-Hans", func(m *Model) {
		m.SetSnapshot(device.Snapshot{
			Device: device.Device{ID: 1, UDID: "UDID-1", ConnectionType: "USB"},
			Info:   device.Info{Name: "iPhone", Version: "27.0", Build: "24A5264n", Type: "iPhone17,1"},
			Apps: []device.InstalledApp{
				{BundleID: "com.SideStore.SideStore.2N29H54X8D", Name: "SideStore", Version: "0.7.0", TeamID: "2N29H54X8D", Signer: "Apple Development: user@example.com"},
				{BundleID: "com.jkcoxson.LocalDevVPN", Name: "LocalDevVPN", Version: "1.3.0"},
				{BundleID: "com.tencent.xin", Name: "微信", Version: "8.0.80", TeamID: "HKB8WPFBR9"},
			},
			SideStore:     &device.InstalledApp{BundleID: "com.SideStore.SideStore.2N29H54X8D", Name: "SideStore", Version: "0.7.0", TeamID: "2N29H54X8D"},
			LocalDevVPN:   &device.InstalledApp{BundleID: "com.jkcoxson.LocalDevVPN", Name: "LocalDevVPN", Version: "1.3.0"},
			SideStoreDocs: []string{"Apps", "SideStore.ipa"},
			SideStoreTree: []device.DocEntry{
				{
					Name:  "Apps",
					Path:  "/Documents/Apps",
					IsDir: true,
					Children: []device.DocEntry{
						{Name: "SideStore-0.7.0.ipa", Path: "/Documents/Apps/SideStore-0.7.0.ipa", Size: 14500000},
					},
				},
				{Name: "README.txt", Path: "/Documents/README.txt", Size: 512},
			},
			USBVerified: true,
		}, nil)
		m.docTreeOpen["/Documents/Apps"] = true
		m.section = "设备"
	})
	renderAndSave("08_account_light_zh.png", 960, 640, false, "zh-Hans", func(m *Model) {
		m.section = "账号"
		m.loginEmail = "user@example.com"
	})
	renderAndSave("06_compact_library_light_zh.png", 600, 560, false, "zh-Hans", func(m *Model) {
		m.section = "文件"
		m.taskStage = 1
		m.files = sampleFiles
		m.narrowDetail = true
	})
}
