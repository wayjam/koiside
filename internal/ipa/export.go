package ipa

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"howett.net/plist"

	"koiside/internal/task"
)

// Preview returns the differences an export would make. It writes nothing.
func Preview(report Report, change Change) Diff {
	diff := Diff{Findings: []Finding{
		{Code: "resign", Severity: Warn, Detail: "修改 plist 后原签名失效。导出的包必须重新签名后才能安装。"},
		{Code: "sidestore-id", Severity: Unknown, Detail: "SideStore 可能给 Bundle ID 追加 Team ID。Watch 的伴随标识在签名后是否匹配，现在无法预测。"},
	}}
	remove := removalSet(change.Remove)
	for _, comp := range report.Components {
		if removed(remove, comp.Path, report.Components) {
			diff.Items = append(diff.Items, DiffItem{Path: comp.Path, Field: "组件", Before: comp.Kind, After: "移除"})
			diff.Findings = append(diff.Findings, Finding{
				Code: "remove", Severity: Warn, Path: comp.Path,
				Detail: "移除后该组件提供的系统入口不可用。默认应保留。",
			})
			continue
		}
		if change.BundleID != "" && change.BundleID != comp.BundleID {
			diff.Items = append(diff.Items, DiffItem{Path: comp.Path, Field: "Bundle ID", Before: comp.BundleID, After: change.BundleID})
		}
		if change.DisplayName != "" && change.DisplayName != comp.DisplayName {
			diff.Items = append(diff.Items, DiffItem{Path: comp.Path, Field: "显示名", Before: comp.DisplayName, After: change.DisplayName})
			if nonASCII(change.DisplayName) {
				diff.Findings = append(diff.Findings, Finding{
					Code: "registration-name", Severity: Warn, Path: comp.Path,
					Detail: "新的显示名包含非 ASCII 字符，签名器可能拒绝把它作为 App ID 名称。",
				})
			}
		}
		if change.LocalizedName != "" {
			for lang, old := range comp.Localizations {
				if old != change.LocalizedName {
					diff.Items = append(diff.Items, DiffItem{Path: comp.Path + "/" + lang, Field: "本地化名", Before: old, After: change.LocalizedName})
				}
			}
		}
		if comp.CompanionID != "" && change.BundleID != "" && comp.CompanionID != change.BundleID {
			diff.Items = append(diff.Items, DiffItem{Path: comp.Path, Field: "Watch 伴随标识", Before: comp.CompanionID, After: change.BundleID})
			diff.Findings = append(diff.Findings, Finding{
				Code: "watch", Severity: Unknown, Path: comp.Path,
				Detail: "已按预览同步伴随标识。若签名器再次改写主标识，安装仍可能失败。",
			})
		}
	}
	return diff
}

// Export writes a new IPA. It refuses to replace output, leaves input
// unchanged, and removes its temporary file when writing fails.
func Export(input, output string, change Change) (task.Record, error) {
	if _, err := os.Stat(output); err == nil {
		return task.Record{}, fmt.Errorf("%w: %s", ErrExists, output)
	} else if !os.IsNotExist(err) {
		return task.Record{}, err
	}
	report, err := Inspect(input)
	if err != nil {
		return task.Record{}, err
	}
	in, err := os.Open(input)
	if err != nil {
		return task.Record{}, err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return task.Record{}, err
	}
	zr, err := zip.NewReader(in, info.Size())
	if err != nil {
		return task.Record{}, fmt.Errorf("%w: %v", ErrUnsafe, err)
	}
	if err := validateZIP(zr); err != nil {
		return task.Record{}, err
	}

	temp := output + ".partial"
	defer os.Remove(temp)
	out, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return task.Record{}, err
	}
	sum := sha256.New()
	zw := zip.NewWriter(io.MultiWriter(out, sum))
	remove := removalSet(change.Remove)
	for _, zf := range zr.File {
		if removed(remove, zf.Name, report.Components) {
			continue
		}
		if err := writeEntry(zw, zf, change); err != nil {
			out.Close()
			return task.Record{}, err
		}
	}
	if err := zw.Close(); err != nil {
		out.Close()
		return task.Record{}, err
	}
	if err := out.Close(); err != nil {
		return task.Record{}, err
	}
	if err := os.Rename(temp, output); err != nil {
		return task.Record{}, err
	}
	record := task.Record{
		InputSHA256:  report.SHA256,
		OutputPath:   output,
		OutputSHA256: hex.EncodeToString(sum.Sum(nil)),
		Version:      report.Version,
		Changes:      describe(Preview(report, change)),
	}
	return record, nil
}

func writeEntry(zw *zip.Writer, zf *zip.File, change Change) error {
	h := zf.FileHeader
	w, err := zw.CreateHeader(&h)
	if err != nil {
		return err
	}
	r, err := zf.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	body, err := io.ReadAll(io.LimitReader(r, maxFileBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxFileBytes {
		return fmt.Errorf("%w: entry too large", ErrUnsafe)
	}
	if edited, ok := editBody(zf.Name, body, change); ok {
		body = edited
	}
	_, err = w.Write(body)
	return err
}

func editBody(name string, body []byte, change Change) ([]byte, bool) {
	switch {
	case strings.HasSuffix(name, "/Info.plist") && (isApp(name) || isExtension(name)):
		return editPlist(body, change)
	case strings.HasSuffix(name, ".lproj/InfoPlist.strings") && change.LocalizedName != "":
		return []byte(fmt.Sprintf("\"CFBundleDisplayName\" = \"%s\";\n", escapeStrings(change.LocalizedName))), true
	default:
		return nil, false
	}
}

func editPlist(body []byte, change Change) ([]byte, bool) {
	values, err := decodePlist(body)
	if err != nil {
		return nil, false
	}
	changed := false
	if change.BundleID != "" {
		values["CFBundleIdentifier"] = change.BundleID
		if _, ok := values["WKCompanionAppBundleIdentifier"]; ok {
			values["WKCompanionAppBundleIdentifier"] = change.BundleID
		}
		changed = true
	}
	if change.DisplayName != "" {
		values["CFBundleDisplayName"] = change.DisplayName
		changed = true
	}
	if !changed {
		return nil, false
	}
	out, err := plist.Marshal(values, plist.XMLFormat)
	if err != nil {
		return nil, false
	}
	return out, true
}

func removalSet(paths []string) map[string]bool {
	out := make(map[string]bool, len(paths))
	for _, item := range paths {
		out[strings.Trim(item, "/")] = true
	}
	return out
}

func removed(prefixes map[string]bool, name string, components []Component) bool {
	name = strings.Trim(name, "/")
	for prefix := range prefixes {
		if name == prefix || strings.HasPrefix(name, prefix+"/") {
			return true
		}
		for _, comp := range components {
			if comp.Path == prefix || strings.HasPrefix(comp.Path, prefix+"/") {
				if name == comp.Path || strings.HasPrefix(name, comp.Path+"/") {
					return true
				}
			}
		}
	}
	return false
}

func describe(diff Diff) []string {
	out := make([]string, 0, len(diff.Items))
	for _, item := range diff.Items {
		out = append(out, fmt.Sprintf("%s %s: %s -> %s", path.Base(item.Path), item.Field, item.Before, item.After))
	}
	return out
}

func escapeStrings(s string) string {
	return strings.NewReplacer(`\\`, `\\\\`, `"`, `\\"`).Replace(s)
}

// HashFile hashes a file without changing it.
func HashFile(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// SameBytes reports whether two files have the same bytes.
func SameBytes(a, b string) (bool, error) {
	ab, err := os.ReadFile(a)
	if err != nil {
		return false, err
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ab, bb), nil
}
