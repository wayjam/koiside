package ipa

import (
	"archive/zip"
	"bytes"
	"debug/macho"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectAndExportKeepsInput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sample.ipa")
	writeFixture(t, input, fixture{
		cryptid: 0, signed: true, chinese: true, watch: true, extension: true,
	})
	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.BundleID != "example.app" || report.Version != "1.0" {
		t.Fatalf("identity %+v", report)
	}
	if !has(report, "registration-name", Warn) || !has(report, "provenance", Unknown) {
		t.Fatalf("findings %+v", report.Findings)
	}
	var main MachO
	for _, slice := range report.MachOs {
		if slice.Path == "Payload/Sample.app/Sample" {
			main = slice
		}
	}
	if main.CryptID == nil || *main.CryptID != 0 || !main.Signed || main.Arch != "arm64" {
		t.Fatalf("macho %+v", report.MachOs)
	}
	diff := Preview(report, Change{BundleID: "example.copy", DisplayName: "Copy", Remove: []string{"Payload/Sample.app/Watch"}})
	if !hasItem(diff, "Payload/Sample.app/Watch/Watch.app", "\u7ec4\u4ef6") || !hasCode(diff, "remove") {
		t.Fatalf("diff %+v", diff)
	}

	output := filepath.Join(dir, "copy.ipa")
	record, err := Export(input, output, Change{
		BundleID: "example.copy", DisplayName: "Copy", LocalizedName: "Copy",
		Remove: []string{"Payload/Sample.app/Watch"},
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("input changed", err)
	}
	exported, err := Inspect(output)
	if err != nil {
		t.Fatal(err)
	}
	if exported.BundleID != "example.copy" || exported.DisplayName != "Copy" {
		t.Fatalf("exported %+v", exported)
	}
	for _, comp := range exported.Components {
		if comp.Kind == "watch" || comp.Kind == "watch-extension" {
			t.Fatalf("watch remained: %+v", comp)
		}
		if comp.BundleID != "example.copy" {
			t.Fatalf("component id %+v", comp)
		}
	}
	if record.InputSHA256 != report.SHA256 || record.OutputPath != output || len(record.Changes) == 0 {
		t.Fatalf("record %+v", record)
	}
	if _, err := Export(input, output, Change{}); !isExists(err) {
		t.Fatal("existing output was replaced", err)
	}
}

func TestRejectsUnsafeZIP(t *testing.T) {
	dir := t.TempDir()
	escape := filepath.Join(dir, "escape.ipa")
	writeRaw(t, escape, "../outside.txt", []byte("x"))
	link := filepath.Join(dir, "link.ipa")
	writeSymlink(t, link)
	bomb := filepath.Join(dir, "bomb.ipa")
	writeBomb(t, bomb)
	for _, file := range []string{escape, link, bomb} {
		if _, err := Inspect(file); err == nil {
			t.Fatalf("%s was accepted", file)
		}
	}
}

func TestFairPlayBlocks(t *testing.T) {
	file := filepath.Join(t.TempDir(), "store.ipa")
	writeFixture(t, file, fixture{cryptid: 1, signed: true})
	report, err := Inspect(file)
	if err != nil {
		t.Fatal(err)
	}
	if !has(report, "fairplay", Block) {
		t.Fatalf("findings %+v", report.Findings)
	}
}

func has(report Report, code string, severity Severity) bool {
	for _, finding := range report.Findings {
		if finding.Code == code && finding.Severity == severity {
			return true
		}
	}
	return false
}

func hasCode(diff Diff, code string) bool {
	for _, finding := range diff.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func hasItem(diff Diff, itemPath, field string) bool {
	for _, item := range diff.Items {
		if item.Path == itemPath && item.Field == field {
			return true
		}
	}
	return false
}

func isExists(err error) bool {
	return err != nil && (os.IsExist(err) || bytes.Contains([]byte(err.Error()), []byte("output exists")))
}

type fixture struct {
	cryptid   int
	signed    bool
	chinese   bool
	watch     bool
	extension bool
}

func writeFixture(t *testing.T, file string, fx fixture) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := zip.NewWriter(buf)
	add := func(name, body string) {
		t.Helper()
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	name := "Sample"
	if fx.chinese {
		name = "示例"
	}
	add("Payload/Sample.app/Info.plist", infoPlist("example.app", name, "Sample", "1.0", "1", "", "Sample"))
	add("Payload/Sample.app/zh-Hans.lproj/InfoPlist.strings", "\"CFBundleDisplayName\" = \""+name+"\";\n")
	addBinary(t, w, "Payload/Sample.app/Sample", fx.cryptid, fx.signed)
	if fx.extension {
		add("Payload/Sample.app/PlugIns/Share.appex/Info.plist", infoPlist("example.app.share", "Share", "Share", "1.0", "1", "", "Share"))
		addBinary(t, w, "Payload/Sample.app/PlugIns/Share.appex/Share", fx.cryptid, fx.signed)
	}
	if fx.watch {
		add("Payload/Sample.app/Watch/Watch.app/Info.plist", infoPlist("example.app.watch", "Watch", "Watch", "1.0", "1", "example.app", "Watch"))
		add("Payload/Sample.app/Watch/Watch.app/PlugIns/WatchExt.appex/Info.plist", infoPlist("example.app.watch.ext", "WatchExt", "WatchExt", "1.0", "1", "", "WatchExt"))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func infoPlist(id, display, bundleName, version, build, companion, executable string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>` + id + `</string>
<key>CFBundleDisplayName</key><string>` + display + `</string>
<key>CFBundleName</key><string>` + bundleName + `</string>
<key>CFBundleShortVersionString</key><string>` + version + `</string>
<key>CFBundleVersion</key><string>` + build + `</string>
<key>CFBundleExecutable</key><string>` + executable + `</string>
<key>MinimumOSVersion</key><string>15.0</string>
<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>example</string></array></dict></array>
` +
		optional("WKCompanionAppBundleIdentifier", companion) + `</dict></plist>
`
}

func optional(key, value string) string {
	if value == "" {
		return ""
	}
	return "<key>" + key + "</key><string>" + value + "</string>\n"
}

func addBinary(t *testing.T, w *zip.Writer, name string, cryptid int, signed bool) {
	t.Helper()
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(machoBytes(cryptid, signed)); err != nil {
		t.Fatal(err)
	}
}

func machoBytes(cryptid int, signed bool) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(macho.Magic64))
	binary.Write(&b, binary.LittleEndian, uint32(macho.CpuArm64))
	binary.Write(&b, binary.LittleEndian, uint32(0))
	binary.Write(&b, binary.LittleEndian, uint32(macho.TypeExec))
	ncmd := uint32(1)
	if signed {
		ncmd = 2
	}
	size := uint32(24)
	if signed {
		size = 40
	}
	binary.Write(&b, binary.LittleEndian, ncmd)
	binary.Write(&b, binary.LittleEndian, size)
	binary.Write(&b, binary.LittleEndian, uint32(0))
	binary.Write(&b, binary.LittleEndian, uint32(0))
	binary.Write(&b, binary.LittleEndian, uint32(0x80000000|0x21))
	binary.Write(&b, binary.LittleEndian, uint32(24))
	binary.Write(&b, binary.LittleEndian, uint32(0))
	binary.Write(&b, binary.LittleEndian, uint32(0))
	binary.Write(&b, binary.LittleEndian, uint32(0))
	binary.Write(&b, binary.LittleEndian, uint32(cryptid))
	if signed {
		binary.Write(&b, binary.LittleEndian, uint32(0x1D))
		binary.Write(&b, binary.LittleEndian, uint32(16))
		binary.Write(&b, binary.LittleEndian, uint32(0))
		binary.Write(&b, binary.LittleEndian, uint32(0))
	}
	return b.Bytes()
}

func writeRaw(t *testing.T, file, name string, body []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	f.Write(body)
	w.Close()
	os.WriteFile(file, buf.Bytes(), 0o644)
}

func writeSymlink(t *testing.T, file string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: "Payload/link"}
	h.SetMode(os.ModeSymlink | 0o777)
	f, err := w.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("/tmp"))
	w.Close()
	os.WriteFile(file, buf.Bytes(), 0o644)
}

func writeBomb(t *testing.T, file string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("bomb.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte{0}, 2<<20)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	os.WriteFile(file, buf.Bytes(), 0o644)
}
