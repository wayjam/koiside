package shell

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	_ "golang.org/x/image/webp"

	"github.com/egoist/mygo/ui"

	app "koiside/internal/app"
	"koiside/internal/device"
	"koiside/internal/ipa"
)

func TestVisualCompare(t *testing.T) {
	services := app.New()
	m := Open(nil, services)
	m.appearance = "浅色"
	m.section = "准备"
	m.devices = []device.Device{{ID: 1, ConnectionType: "USB"}}
	m.files = []archiveState{
		{
			path:  "/Users/test/Orbit.ipa",
			ready: true,
			report: ipa.Report{
				DisplayName: "Orbit",
				BundleID:    "com.example.orbit",
				Version:     "1.2.0",
				MachOs:      []ipa.MachO{{Arch: "arm64"}},
				Components:  []ipa.Component{{Path: "Payload/Orbit.app", Kind: "主应用"}},
				Findings:    []ipa.Finding{{Code: "valid", Severity: ipa.Unknown, Detail: "签名结构完整"}},
			},
		},
		{
			path:  "/Users/test/Stream.ipa",
			ready: true,
			report: ipa.Report{
				DisplayName: "Stream",
				BundleID:    "com.example.stream",
				Version:     "3.1.0",
				MachOs:      []ipa.MachO{{Arch: "arm64"}},
			},
		},
	}

	// Target design
	targetPath := "/Users/wayjamsu/.local/state/magpie-agy-bridge/agy-home/antigravity-cli/brain/416c2b79-27da-45d7-a833-79f7668a451c/.user_uploaded/uploaded_media_1_1794732983562.webp"
	fTar, err := os.Open(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("skipping visual compare; target image not found: %v", err)
		}
		t.Fatalf("Open target failed: %v", err)
	}
	defer fTar.Close()
	imgTar, _, err := image.Decode(fTar)
	if err != nil {
		t.Fatalf("Decode target failed: %v", err)
	}
	tarW := imgTar.Bounds().Dx()
	tarH := imgTar.Bounds().Dy()
	t.Logf("Target bounds: %dx%d", tarW, tarH)

	// Render current UI at (784, 522.5) -> (784, 523) or (784, 522) with scale 2
	ptW := float64(tarW) / 2.0
	ptH := float64(tarH) / 2.0
	t.Logf("Rendering at pt size: %fx%f", ptW, ptH)

	rendered := ui.Render(m.view, int(ptW), int(ptH), 2)
	t.Logf("Rendered bounds: %dx%d", rendered.Bounds().Dx(), rendered.Bounds().Dy())

	outDir := filepath.Join(os.TempDir(), "koiside_visual")
	os.MkdirAll(outDir, 0o755)

	fCur, _ := os.Create(filepath.Join(outDir, "current_rendered.png"))
	png.Encode(fCur, rendered)
	fCur.Close()

	// Create side-by-side comparison: [Target | Rendered | Diff]
	diffW := tarW
	diffH := tarH
	if rendered.Bounds().Dy() < diffH {
		diffH = rendered.Bounds().Dy()
	}
	if rendered.Bounds().Dx() < diffW {
		diffW = rendered.Bounds().Dx()
	}

	diffImg := image.NewRGBA(image.Rect(0, 0, diffW, diffH))
	var totalDiff int64
	for y := 0; y < diffH; y++ {
		for x := 0; x < diffW; x++ {
			r1, g1, b1, _ := imgTar.At(x, y).RGBA()
			r2, g2, b2, _ := rendered.At(x, y).RGBA()
			dr := int(r1>>8) - int(r2>>8)
			dg := int(g1>>8) - int(g2>>8)
			db := int(b1>>8) - int(b2>>8)
			if dr < 0 {
				dr = -dr
			}
			if dg < 0 {
				dg = -dg
			}
			if db < 0 {
				db = -db
			}
			d := dr + dg + db
			totalDiff += int64(d)
			if d > 30 {
				diffImg.Set(x, y, color.RGBA{R: 255, G: 0, B: 0, A: 255})
			} else {
				diffImg.Set(x, y, color.RGBA{R: uint8(r2 >> 8), G: uint8(g2 >> 8), B: uint8(b2 >> 8), A: 100})
			}
		}
	}

	sideBySide := image.NewRGBA(image.Rect(0, 0, tarW*2, tarH))
	draw.Draw(sideBySide, image.Rect(0, 0, tarW, tarH), imgTar, image.Point{}, draw.Src)
	draw.Draw(sideBySide, image.Rect(tarW, 0, tarW*2, tarH), rendered, image.Point{}, draw.Src)

	fSbs, _ := os.Create(filepath.Join(outDir, "compare_sbs.png"))
	png.Encode(fSbs, sideBySide)
	fSbs.Close()

	fDiff, _ := os.Create(filepath.Join(outDir, "compare_diff.png"))
	png.Encode(fDiff, diffImg)

	// Copy to /tmp for easy reading
	if data, err := os.ReadFile(filepath.Join(outDir, "current_rendered.png")); err == nil {
		_ = os.WriteFile("/tmp/current_rendered.png", data, 0o644)
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "compare_sbs.png")); err == nil {
		_ = os.WriteFile("/tmp/compare_sbs.png", data, 0o644)
	}
	if data, err := os.ReadFile(filepath.Join(outDir, "compare_diff.png")); err == nil {
		_ = os.WriteFile("/tmp/compare_diff.png", data, 0o644)
	}

	avgDiff := float64(totalDiff) / float64(diffW*diffH*3)
	fmt.Printf("Average color difference: %.2f (lower is better)\n", avgDiff)
}
