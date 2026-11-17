package ipa

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"
)

func TestNormalizePNGDecodesCgBI(t *testing.T) {
	// Build a minimal 2x2 Apple CgBI PNG (raw deflate + premultiplied BGRA)
	var ihdr bytes.Buffer
	_ = binary.Write(&ihdr, binary.BigEndian, uint32(2))
	_ = binary.Write(&ihdr, binary.BigEndian, uint32(2))
	ihdr.Write([]byte{8, 6, 0, 0, 0}) // 8-bit RGBA

	// Pixel (10, 128, 255, 255) -> BGRA = (255, 128, 10, 255)
	// Premultiplied alpha 50% (a=128): R=200->100, G=100->50, B=40->20 -> BGRA = (20, 50, 100, 128)
	scanlines := []byte{
		0, 255, 128, 10, 255, 20, 50, 100, 128,
		0, 0, 0, 0, 0, 255, 255, 255, 255,
	}
	var idat bytes.Buffer
	fw, _ := flate.NewWriter(&idat, flate.DefaultCompression)
	_, _ = fw.Write(scanlines)
	_ = fw.Close()

	var raw bytes.Buffer
	raw.Write(pngSignature)
	writeChunk(&raw, "CgBI", []byte{0x50, 0x00, 0x20, 0x06})
	writeChunk(&raw, "IHDR", ihdr.Bytes())
	writeChunk(&raw, "IDAT", idat.Bytes())
	writeChunk(&raw, "IEND", nil)

	out, err := normalizePNG(raw.Bytes())
	if err != nil {
		t.Fatalf("normalizePNG failed: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("standard png.Decode failed: %v", err)
	}
	c0 := color.NRGBAModel.Convert(img.At(0, 0)).(color.NRGBA)
	if c0.R != 10 || c0.G != 128 || c0.B != 255 || c0.A != 255 {
		t.Fatalf("pixel (0,0) = %+v, want {10 128 255 255}", c0)
	}
	c1 := color.NRGBAModel.Convert(img.At(1, 0)).(color.NRGBA)
	if c1.A != 128 || c1.R < 195 || c1.G < 95 || c1.B < 35 {
		t.Fatalf("un-premultiplied pixel (1,0) = %+v", c1)
	}
}

func TestExtractAppIconFromRealSampleIfPresent(t *testing.T) {
	const sample = "/Users/wayjamsu/Code/ios-sideapp/WeChat2-8.0.70-qy-no-watch.ipa"
	if _, err := os.Stat(sample); err != nil {
		t.Skip("local sample IPA not present")
	}
	report, err := Inspect(sample)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(report.IconPNG) == 0 {
		t.Fatal("expected non-empty IconPNG")
	}
	img, err := png.Decode(bytes.NewReader(report.IconPNG))
	if err != nil {
		t.Fatalf("decoded IconPNG invalid: %v", err)
	}
	if img.Bounds().Dx() < 60 || img.Bounds().Dy() < 60 {
		t.Fatalf("unexpected icon dimensions: %v", img.Bounds())
	}
	_ = image.ZP
}

func writeChunk(w *bytes.Buffer, typ string, data []byte) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(data)))
	w.WriteString(typ)
	w.Write(data)
	sum := crc32.NewIEEE()
	_, _ = sum.Write([]byte(typ))
	_, _ = sum.Write(data)
	_ = binary.Write(w, binary.BigEndian, sum.Sum32())
}
