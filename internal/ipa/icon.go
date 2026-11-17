package ipa

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"path"
	"strings"
)

var pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

func extractMainAppIcon(zr *zip.Reader, mainAppPath string, iconPrefixes []string) []byte {
	if mainAppPath == "" {
		return nil
	}
	dirPrefix := strings.TrimSuffix(mainAppPath, "/") + "/"
	var best *zip.File
	bestScore := -1

	for _, zf := range zr.File {
		if !strings.HasPrefix(zf.Name, dirPrefix) {
			continue
		}
		rest := strings.TrimPrefix(zf.Name, dirPrefix)
		if strings.Contains(rest, "/") {
			continue
		}
		lower := strings.ToLower(rest)
		if !strings.HasSuffix(lower, ".png") {
			continue
		}
		if zf.UncompressedSize64 == 0 || zf.UncompressedSize64 > 2<<20 {
			continue
		}
		score := scoreIconCandidate(rest, iconPrefixes, int(zf.UncompressedSize64))
		if score > bestScore {
			bestScore = score
			best = zf
		}
	}
	if best == nil || bestScore <= 0 {
		return nil
	}
	raw, err := readZipFile(best, 2<<20)
	if err != nil {
		return nil
	}
	normalized, err := normalizePNG(raw)
	if err != nil {
		return nil
	}
	return normalized
}

func scoreIconCandidate(filename string, prefixes []string, size int) int {
	lower := strings.ToLower(filename)
	matched := false
	score := 0
	for _, p := range prefixes {
		lp := strings.ToLower(p)
		if lp != "" && strings.HasPrefix(lower, lp) {
			matched = true
			score += 1000
			break
		}
	}
	if !matched && strings.HasPrefix(lower, "appicon") {
		matched = true
		score += 800
	}
	if !matched {
		return 0
	}
	switch {
	case strings.Contains(lower, "60x60@3x"):
		score += 400
	case strings.Contains(lower, "60x60@2x"):
		score += 350
	case strings.Contains(lower, "76x76@2x"):
		score += 300
	case strings.Contains(lower, "@3x"):
		score += 250
	case strings.Contains(lower, "@2x"):
		score += 200
	}
	if strings.Contains(lower, "~ipad") {
		score -= 20
	}
	score += min(size/256, 150)
	return score
}

func iconNamesFromPlist(values map[string]any) []string {
	var names []string
	addList := func(v any) {
		arr, _ := v.([]any)
		for _, item := range arr {
			if s := text(item); s != "" {
				names = append(names, s)
			}
		}
	}
	for _, key := range []string{"CFBundleIcons", "CFBundleIcons~ipad"} {
		if dict, ok := values[key].(map[string]any); ok {
			if primary, ok := dict["CFBundlePrimaryIcon"].(map[string]any); ok {
				addList(primary["CFBundleIconFiles"])
				if name := text(primary["CFBundleIconName"]); name != "" {
					names = append(names, name)
				}
			}
		}
	}
	addList(values["CFBundleIconFiles"])
	if s := text(values["CFBundleIconFile"]); s != "" {
		names = append(names, strings.TrimSuffix(path.Base(s), ".png"))
	}
	return names
}

// normalizePNG decodes standard PNG or Apple CgBI PNG and returns standard RGBA PNG bytes.
func normalizePNG(raw []byte) ([]byte, error) {
	if len(raw) < len(pngSignature) || !bytes.Equal(raw[:8], pngSignature) {
		return nil, fmt.Errorf("not a png")
	}
	// Apple CgBI PNGs start with a CgBI chunk right after the PNG signature.
	if len(raw) < 16 || string(raw[12:16]) != "CgBI" {
		if _, err := png.Decode(bytes.NewReader(raw)); err == nil {
			return raw, nil
		}
	}

	// Parse chunks for Apple CgBI PNG
	pos := 8
	hasCgBI := false
	var width, height int
	var bitDepth, colorType byte
	var idat bytes.Buffer

	for pos+12 <= len(raw) {
		length := int(binary.BigEndian.Uint32(raw[pos : pos+4]))
		chunkType := string(raw[pos+4 : pos+8])
		dataStart := pos + 8
		dataEnd := dataStart + length
		if length < 0 || dataEnd+4 > len(raw) {
			return nil, fmt.Errorf("corrupt png chunk")
		}
		data := raw[dataStart:dataEnd]
		switch chunkType {
		case "CgBI":
			hasCgBI = true
		case "IHDR":
			if len(data) < 13 {
				return nil, fmt.Errorf("short IHDR")
			}
			width = int(binary.BigEndian.Uint32(data[0:4]))
			height = int(binary.BigEndian.Uint32(data[4:8]))
			bitDepth = data[8]
			colorType = data[9]
		case "IDAT":
			idat.Write(data)
		case "IEND":
			pos = len(raw)
			continue
		}
		pos = dataEnd + 4
	}

	if !hasCgBI || width <= 0 || height <= 0 || width > 2048 || height > 2048 || bitDepth != 8 {
		return nil, fmt.Errorf("unsupported cgbi png")
	}

	var bpp int
	switch colorType {
	case 6: // RGBA / BGRA
		bpp = 4
	case 2: // RGB / BGR
		bpp = 3
	default:
		return nil, fmt.Errorf("unsupported cgbi color type %d", colorType)
	}

	fr := flate.NewReader(bytes.NewReader(idat.Bytes()))
	defer fr.Close()
	stride := width * bpp
	expected := height * (1 + stride)
	decompressed, err := io.ReadAll(io.LimitReader(fr, int64(expected)+1024))
	if err != nil {
		return nil, err
	}
	if len(decompressed) < expected {
		return nil, fmt.Errorf("incomplete cgbi pixel stream")
	}

	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	prev := make([]byte, stride)
	cur := make([]byte, stride)

	for y := 0; y < height; y++ {
		rowOffset := y * (1 + stride)
		filter := decompressed[rowOffset]
		src := decompressed[rowOffset+1 : rowOffset+1+stride]
		unfilterScanline(filter, cur, prev, src, bpp)
		for x := 0; x < width; x++ {
			off := x * bpp
			b := cur[off]
			g := cur[off+1]
			r := cur[off+2]
			a := byte(255)
			if bpp == 4 {
				a = cur[off+3]
				if a > 0 && a < 255 {
					r = byte(min(255, int(r)*255/int(a)))
					g = byte(min(255, int(g)*255/int(a)))
					b = byte(min(255, int(b)*255/int(a)))
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
		copy(prev, cur)
	}

	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func unfilterScanline(filter byte, cur, prev, src []byte, bpp int) {
	for i := 0; i < len(src); i++ {
		var left, up, upLeft byte
		if i >= bpp {
			left = cur[i-bpp]
			upLeft = prev[i-bpp]
		}
		up = prev[i]
		switch filter {
		case 0:
			cur[i] = src[i]
		case 1:
			cur[i] = src[i] + left
		case 2:
			cur[i] = src[i] + up
		case 3:
			cur[i] = src[i] + byte((int(left)+int(up))/2)
		case 4:
			cur[i] = src[i] + paethPredictor(left, up, upLeft)
		default:
			cur[i] = src[i]
		}
	}
}

func paethPredictor(a, b, c byte) byte {
	pa := int(b) - int(c)
	pb := int(a) - int(c)
	pc := pa + pb
	if pa < 0 {
		pa = -pa
	}
	if pb < 0 {
		pb = -pb
	}
	if pc < 0 {
		pc = -pc
	}
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}
