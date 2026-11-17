package ipa

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"howett.net/plist"
)

// Inspect reads an IPA without extracting it. The input file is opened
// read-only. An unsafe ZIP returns ErrUnsafe and no report.
func Inspect(file string) (Report, error) {
	f, err := os.Open(file)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	return inspectReader(f)
}

func inspectReader(f *os.File) (Report, error) {
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return Report{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return Report{}, err
	}
	info, err := f.Stat()
	if err != nil {
		return Report{}, err
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrUnsafe, err)
	}
	if err := validateZIP(zr); err != nil {
		return Report{}, err
	}

	report := Report{
		SHA256: hex.EncodeToString(sum.Sum(nil)),
		Scope:  "ZIP 结构、Info.plist、本地化显示名、扩展、Watch、URL Scheme、Mach-O 加密标志与签名块是否存在",
	}
	var main *Component
	var iconPrefixes []string
	for _, zf := range zr.File {
		switch {
		case strings.HasSuffix(zf.Name, ".dylib"):
			report.Dylibs = append(report.Dylibs, zf.Name)
		case isInfoPlist(zf.Name):
			body, err := readZipFile(zf, 4<<20)
			if err != nil {
				return Report{}, err
			}
			comp, prefixes, err := componentAndIconsFromPlist(zf.Name, body)
			if err != nil {
				report.Findings = append(report.Findings, Finding{
					Code: "plist", Severity: Block, Path: zf.Name, Detail: err.Error(),
				})
				continue
			}
			if comp.Kind == "app" {
				if main != nil {
					report.Findings = append(report.Findings, Finding{
						Code: "payload", Severity: Block, Path: comp.Path, Detail: "发现多个主应用",
					})
				}
				copied := comp
				main = &copied
				iconPrefixes = prefixes
			}
			report.Components = append(report.Components, comp)
		case strings.HasSuffix(zf.Name, ".lproj/InfoPlist.strings"):
			body, err := readZipFile(zf, 1<<20)
			if err != nil {
				return Report{}, err
			}
			lang, name := localization(zf.Name, body)
			if name == "" {
				continue
			}
			attachLocalization(&report, path.Dir(path.Dir(zf.Name)), lang, name)
		}
	}
	if main == nil {
		report.Findings = append(report.Findings, Finding{
			Code: "payload", Severity: Block, Detail: "没有找到主应用 Info.plist",
		})
	} else {
		report.BundleID = main.BundleID
		report.DisplayName = main.DisplayName
		report.Version = main.Version
		report.Build = main.Build
		report.IconPNG = extractMainAppIcon(zr, main.Path, iconPrefixes)
		if nonASCII(main.DisplayName) || nonASCIINames(main.Localizations) {
			report.Findings = append(report.Findings, Finding{
				Code: "registration-name", Severity: Warn, Path: main.Path,
				Detail: "显示名包含非 ASCII 字符。签名器可能把它用作 App ID 名称并被拒绝；本工具不能把桌面名称和注册名称分开。",
			})
		}
	}
	for _, zf := range zr.File {
		if !isExecutable(zf.Name, report.Components) {
			continue
		}
		body, err := readZipFile(zf, machoHeaderLimit)
		if err != nil {
			return Report{}, err
		}
		slices, err := parseMachO(zf.Name, body)
		if err != nil {
			report.Findings = append(report.Findings, Finding{
				Code: "macho", Severity: Unknown, Path: zf.Name, Detail: "无法读取加密标志",
			})
			continue
		}
		report.MachOs = append(report.MachOs, slices...)
	}
	report.Findings = append(report.Findings, provenance(report)...)
	return report, nil
}

func validateZIP(zr *zip.Reader) error {
	if len(zr.File) > maxEntries {
		return fmt.Errorf("%w: too many entries", ErrUnsafe)
	}
	var total int64
	for _, zf := range zr.File {
		if err := safeName(zf.Name); err != nil {
			return err
		}
		if zf.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink %s", ErrUnsafe, zf.Name)
		}
		size := int64(zf.UncompressedSize64)
		if size < 0 || size > maxFileBytes {
			return fmt.Errorf("%w: entry too large", ErrUnsafe)
		}
		total += size
		if total > maxArchiveBytes {
			return fmt.Errorf("%w: archive too large", ErrUnsafe)
		}
		compressed := int64(zf.CompressedSize64)
		if compressed > 0 && size >= minBombCheckBytes && size/compressed > maxExpansion {
			return fmt.Errorf("%w: compression ratio", ErrUnsafe)
		}
	}
	return nil
}

func safeName(name string) error {
	if name == "" || path.IsAbs(name) || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("%w: path %q", ErrUnsafe, name)
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(name, "/../") {
		return fmt.Errorf("%w: path %q", ErrUnsafe, name)
	}
	return nil
}

func readZipFile(zf *zip.File, limit int64) ([]byte, error) {
	if int64(zf.UncompressedSize64) > limit {
		limit = maxFileBytes
	}
	r, err := zf.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnsafe, zf.Name)
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, limit))
}

func isInfoPlist(name string) bool {
	return strings.HasSuffix(name, "/Info.plist") && (isApp(name) || isExtension(name))
}

func isApp(name string) bool {
	return strings.HasSuffix(path.Dir(name), ".app")
}

func isExtension(name string) bool {
	return strings.HasSuffix(path.Dir(name), ".appex")
}

func componentFromPlist(plistPath string, body []byte) (Component, error) {
	comp, _, err := componentAndIconsFromPlist(plistPath, body)
	return comp, err
}

func componentAndIconsFromPlist(plistPath string, body []byte) (Component, []string, error) {
	values, err := decodePlist(body)
	if err != nil {
		return Component{}, nil, err
	}
	kind := "extension"
	root := path.Dir(plistPath)
	switch {
	case strings.Contains(root, "/Watch/") && strings.HasSuffix(root, ".appex"):
		kind = "watch-extension"
	case strings.Contains(root, "/Watch/") && strings.HasSuffix(root, ".app"):
		kind = "watch"
	case strings.HasSuffix(root, ".app") && !strings.Contains(root, ".app/"):
		kind = "app"
	}
	return Component{
		Path:        root,
		Kind:        kind,
		BundleID:    text(values["CFBundleIdentifier"]),
		DisplayName: firstText(values, "CFBundleDisplayName", "CFBundleName"),
		Version:     text(values["CFBundleShortVersionString"]),
		Build:       text(values["CFBundleVersion"]),
		MinimumOS:   text(values["MinimumOSVersion"]),
		Executable:  text(values["CFBundleExecutable"]),
		CompanionID: text(values["WKCompanionAppBundleIdentifier"]),
		URLSchemes:  urlSchemes(values),
	}, iconNamesFromPlist(values), nil
}

func decodePlist(body []byte) (map[string]any, error) {
	var values map[string]any
	if _, err := plist.Unmarshal(body, &values); err != nil {
		return nil, err
	}
	if values == nil {
		return nil, errors.New("empty plist")
	}
	return values, nil
}

func urlSchemes(values map[string]any) []string {
	types, _ := values["CFBundleURLTypes"].([]any)
	var out []string
	for _, item := range types {
		dict, _ := item.(map[string]any)
		schemes, _ := dict["CFBundleURLSchemes"].([]any)
		for _, scheme := range schemes {
			if s := text(scheme); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func text(v any) string {
	s, _ := v.(string)
	return s
}

func firstText(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if s := text(values[key]); s != "" {
			return s
		}
	}
	return ""
}

func localization(name string, body []byte) (string, string) {
	lproj := path.Base(path.Dir(name))
	lang := strings.TrimSuffix(lproj, ".lproj")
	text := decodeStrings(body)
	const key = `"CFBundleDisplayName"`
	at := strings.Index(text, key)
	if at < 0 {
		return lang, ""
	}
	rest := text[at+len(key):]
	eq := strings.Index(rest, "=")
	if eq < 0 {
		return lang, ""
	}
	rest = strings.TrimSpace(rest[eq+1:])
	if !strings.HasPrefix(rest, `"`) {
		return lang, ""
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return lang, ""
	}
	return lang, rest[:end]
}

func decodeStrings(body []byte) string {
	if bytes.HasPrefix(body, []byte{0xFF, 0xFE}) {
		return utf16BE(body[2:], true)
	}
	if bytes.HasPrefix(body, []byte{0xFE, 0xFF}) {
		return utf16BE(body[2:], false)
	}
	if utf8.Valid(body) {
		return string(body)
	}
	return utf16BE(body, true)
}

func utf16BE(body []byte, little bool) string {
	var b strings.Builder
	for i := 0; i+1 < len(body); i += 2 {
		var r uint16
		if little {
			r = uint16(body[i]) | uint16(body[i+1])<<8
		} else {
			r = uint16(body[i+1]) | uint16(body[i])<<8
		}
		b.WriteRune(rune(r))
	}
	return b.String()
}

func attachLocalization(report *Report, root, lang, name string) {
	for i := range report.Components {
		if report.Components[i].Path != root {
			continue
		}
		if report.Components[i].Localizations == nil {
			report.Components[i].Localizations = map[string]string{}
		}
		report.Components[i].Localizations[lang] = name
	}
}

func isExecutable(name string, components []Component) bool {
	for _, comp := range components {
		if comp.Executable != "" && name == comp.Path+"/"+comp.Executable {
			return true
		}
	}
	return false
}

func nonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func nonASCIINames(names map[string]string) bool {
	for _, name := range names {
		if nonASCII(name) {
			return true
		}
	}
	return false
}

func provenance(report Report) []Finding {
	var out []Finding
	encrypted := false
	missing := false
	for _, slice := range report.MachOs {
		if slice.CryptID == nil {
			missing = true
		}
		if slice.Encrypted {
			encrypted = true
		}
	}
	if encrypted {
		out = append(out, Finding{
			Code: "fairplay", Severity: Block,
			Detail: "至少一个 Mach-O 的 cryptid 为 1。它仍受 FairPlay 保护，修改或重签不能去掉这层保护。",
		})
	}
	if missing {
		out = append(out, Finding{
			Code: "cryptid", Severity: Unknown,
			Detail: "有可执行文件没有加密标志，不能判断它能否重签。",
		})
	}
	out = append(out, Finding{
		Code: "provenance", Severity: Unknown,
		Detail: "cryptid 为 0、没有独立 dylib，或哈希一致，都不能证明这是官方未修改的包。",
	})
	if len(report.Dylibs) > 0 {
		out = append(out, Finding{
			Code: "dylib", Severity: Unknown,
			Detail: fmt.Sprintf("发现 %d 个独立 dylib。这只说明文件存在，不能单独判定来源或是否注入。", len(report.Dylibs)),
		})
	}
	return out
}
