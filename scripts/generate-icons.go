//go:build ignore

// Run from the repository root with go run scripts/generate-icons.go.
package main

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/image/draw"
)

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	f, err := os.Open("assets/brand/logo-master.png")
	if err != nil {
		return err
	}
	source, err := png.Decode(f)
	f.Close()
	if err != nil {
		return err
	}
	// Ignore nearly transparent generator residue when measuring the mark.
	bounds := image.Rectangle{}
	for y := source.Bounds().Min.Y; y < source.Bounds().Max.Y; y++ {
		for x := source.Bounds().Min.X; x < source.Bounds().Max.X; x++ {
			_, _, _, alpha := source.At(x, y).RGBA()
			if alpha >= 0x8000 {
				bounds = bounds.Union(image.Rect(x, y, x+1, y+1))
			}
		}
	}
	if bounds.Empty() {
		return fmt.Errorf("logo has no visible pixels")
	}
	iconset := "build/KoiSide.iconset"
	if err := os.MkdirAll(iconset, 0o755); err != nil {
		return err
	}
	for _, size := range []int{16, 32, 64, 128, 256, 512} {
		for _, scale := range []int{1, 2} {
			name := fmt.Sprintf("icon_%dx%d", size, size)
			if scale == 2 {
				name += "@2x"
			}
			if err := save(source, bounds, size*scale, .80, filepath.Join(iconset, name+".png")); err != nil {
				return err
			}
		}
	}
	if err := save(source, bounds, 1024, .80, "resources/icon.png"); err != nil {
		return err
	}
	if err := save(source, bounds, 256, .94, "internal/ui/shell/assets/brand/logo.png"); err != nil {
		return err
	}
	cmd := exec.Command("iconutil", "-c", "icns", "-o", "resources/icon.icns", iconset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iconutil: %w: %s", err, out)
	}
	return nil
}

func save(source image.Image, bounds image.Rectangle, size int, fraction float64, path string) error {
	maxSide := max(bounds.Dx(), bounds.Dy())
	factor := float64(size) * fraction / float64(maxSide)
	width := max(1, int(float64(bounds.Dx())*factor+.5))
	height := max(1, int(float64(bounds.Dy())*factor+.5))
	left, top := (size-width)/2, (size-height)/2
	result := image.NewNRGBA(image.Rect(0, 0, size, size))
	draw.CatmullRom.Scale(result, image.Rect(left, top, left+width, top+height), source, bounds, draw.Src, nil)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := png.Encode(f, result); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
