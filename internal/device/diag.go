package device

import (
	"path"
	"sort"
	"strings"

	"howett.net/plist"
)

// LCContainer is one data container a LiveContainer guest can run in.
type LCContainer struct {
	FolderName      string `json:"folder_name"`
	Name            string `json:"name,omitempty"`
	IsolateAppGroup bool   `json:"isolate_app_group,omitempty"`
}

// LiveContainerApp describes an IPA installed inside LiveContainer (/Documents/Applications/*.app).
// The settings fields come from LCAppInfo.plist; older LiveContainer builds lack it.
type LiveContainerApp struct {
	Folder   string `json:"folder"`
	Name     string `json:"name"`
	BundleID string `json:"bundle_id"`
	Version  string `json:"version"`
	Build    string `json:"build,omitempty"`

	InfoKnown  bool          `json:"info_known"`
	Shared     bool          `json:"shared"`
	Multitask  int           `json:"multitask"` // -1 unknown, 0 default, 1 no, 2 yes
	DataUUID   string        `json:"data_uuid,omitempty"`
	Containers []LCContainer `json:"containers,omitempty"`
}

// SideStoreLogSummary summarizes the latest SideStore ConsoleLog entry found on device.
type SideStoreLogSummary struct {
	File       string   `json:"file"`
	Operation  string   `json:"operation,omitempty"`
	AppID      string   `json:"app_id,omitempty"`
	Status     string   `json:"status,omitempty"`
	Elapsed    string   `json:"elapsed,omitempty"`
	LastError  string   `json:"last_error,omitempty"`
	FinishedAt string   `json:"finished_at,omitempty"`
	Tail       []string `json:"tail,omitempty"`
}

func parseLiveContainerAppPlist(folder string, raw []byte) (LiveContainerApp, bool) {
	if len(raw) == 0 {
		return LiveContainerApp{}, false
	}
	var m map[string]any
	if _, err := plist.Unmarshal(raw, &m); err != nil {
		return LiveContainerApp{}, false
	}
	bundleID := stringValue(m["CFBundleIdentifier"])
	if bundleID == "" {
		return LiveContainerApp{}, false
	}
	name := stringValue(m["CFBundleDisplayName"])
	if name == "" {
		name = stringValue(m["CFBundleName"])
	}
	return LiveContainerApp{
		Folder:    folder,
		Name:      name,
		BundleID:  bundleID,
		Version:   stringValue(m["CFBundleShortVersionString"]),
		Build:     stringValue(m["CFBundleVersion"]),
		Multitask: -1,
	}, true
}

// parseLCAppInfo fills the settings a LiveContainer guest keeps in LCAppInfo.plist.
func parseLCAppInfo(app *LiveContainerApp, raw []byte) {
	if app == nil || len(raw) == 0 {
		return
	}
	var m map[string]any
	if _, err := plist.Unmarshal(raw, &m); err != nil {
		return
	}
	app.InfoKnown = true
	app.Shared = boolValue(m["isShared"])
	app.Multitask = intValueOr(m["MultitaskSpecified"], 0)
	app.DataUUID = stringValue(m["LCDataUUID"])
	for _, rawItem := range anySlice(m["LCContainers"]) {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		folder := stringValue(item["folderName"])
		if folder == "" {
			continue
		}
		app.Containers = append(app.Containers, LCContainer{
			FolderName:      folder,
			Name:            stringValue(item["name"]),
			IsolateAppGroup: boolValue(item["isolateAppGroup"]),
		})
	}
}

func anySlice(v any) []any {
	x, _ := v.([]any)
	return x
}

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

func intValueOr(v any, fallback int) int {
	switch x := v.(type) {
	case int64:
		return int(x)
	case int:
		return x
	case uint64:
		return int(x)
	default:
		return fallback
	}
}

func readLiveContainerApps(afc *AFC) []LiveContainerApp {
	if afc == nil {
		return nil
	}
	entries, err := afc.ReadDir("/Documents/Applications")
	if err != nil || len(entries) == 0 {
		return nil
	}
	sort.Strings(entries)
	var out []LiveContainerApp
	for _, entry := range entries {
		if !strings.HasSuffix(strings.ToLower(entry), ".app") {
			continue
		}
		base := path.Join("/Documents/Applications", entry)
		raw, err := afc.ReadFile(path.Join(base, "Info.plist"))
		if err != nil {
			continue
		}
		app, ok := parseLiveContainerAppPlist(entry, raw)
		if !ok {
			continue
		}
		if infoRaw, err := afc.ReadFile(path.Join(base, "LCAppInfo.plist")); err == nil {
			parseLCAppInfo(&app, infoRaw)
		}
		out = append(out, app)
	}
	return out
}

// ParseSideStoreLog extracts the latest operation result and error summary from a SideStore ConsoleLog.
func ParseSideStoreLog(filename, content string) SideStoreLogSummary {
	summary := SideStoreLogSummary{File: filename}
	rawLines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var lines []string
	for _, l := range rawLines {
		t := strings.TrimSpace(l)
		if t != "" {
			lines = append(lines, t)
		}
	}
	if len(lines) == 0 {
		return summary
	}
	start := 0
	if len(lines) > 10 {
		start = len(lines) - 10
	}
	summary.Tail = append([]string(nil), lines[start:]...)

	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		ts := extractLogTimestamp(line)
		if summary.FinishedAt == "" && ts != "" {
			summary.FinishedAt = ts
		}
		// Match structured summary line: "2026-... [I]: Operation: refresh | App ID: com.kdt.livecontainer | Status: SUCCESS | Elapsed: 3.876s"
		if summary.Operation == "" && strings.Contains(line, "Operation:") && strings.Contains(line, "Status:") {
			if idx := strings.Index(line, "Operation:"); idx >= 0 {
				parts := strings.Split(line[idx:], "|")
				for _, p := range parts {
					kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
					if len(kv) != 2 {
						continue
					}
					k := strings.TrimSpace(kv[0])
					v := strings.TrimSpace(kv[1])
					switch k {
					case "Operation":
						summary.Operation = v
					case "App ID":
						summary.AppID = v
					case "Status":
						summary.Status = v
					case "Elapsed":
						summary.Elapsed = v
					}
				}
				if ts != "" {
					summary.FinishedAt = ts
				}
			}
		}
		// Fallback: "Finished refreshing with results: [("com.kdt.livecontainer", "success")]"
		if summary.Operation == "" && strings.Contains(line, "Finished refreshing with results:") {
			summary.Operation = "refresh"
			if strings.Contains(strings.ToLower(line), `"success"`) {
				summary.Status = "SUCCESS"
			} else {
				summary.Status = "FAILED"
			}
			if ts != "" {
				summary.FinishedAt = ts
			}
		}
		if summary.LastError == "" && (strings.Contains(line, " [E]: ") || (strings.Contains(line, "FAILED:") && !strings.Contains(line, "[CacheResignedMetadataOperation]"))) {
			summary.LastError = line
		}
	}
	return summary
}

func extractLogTimestamp(line string) string {
	idx := strings.IndexByte(line, ' ')
	if idx <= 0 {
		return ""
	}
	head := line[:idx]
	if strings.Contains(head, "T") && strings.Contains(head, "-") {
		return head
	}
	return ""
}

func readLatestSideStoreLog(afc *AFC, dirs []string) *SideStoreLogSummary {
	if afc == nil {
		return nil
	}
	for _, dir := range dirs {
		files, err := afc.ReadDir(dir)
		if err != nil || len(files) == 0 {
			continue
		}
		var logFiles []string
		for _, f := range files {
			if strings.HasSuffix(strings.ToLower(f), ".log") {
				logFiles = append(logFiles, f)
			}
		}
		if len(logFiles) == 0 {
			continue
		}
		sort.Strings(logFiles)
		// Inspect up to the newest 8 logs so a trivial app-open log doesn't hide a recent refresh/install result.
		var newest *SideStoreLogSummary
		var withErr *SideStoreLogSummary
		checked := 0
		for i := len(logFiles) - 1; i >= 0 && checked < 8; i-- {
			checked++
			name := logFiles[i]
			raw, err := afc.ReadFile(path.Join(dir, name))
			if err != nil || len(raw) == 0 {
				continue
			}
			parsed := ParseSideStoreLog(name, string(raw))
			if newest == nil {
				cp := parsed
				newest = &cp
			}
			if parsed.Operation != "" {
				cp := parsed
				return &cp
			}
			if withErr == nil && parsed.LastError != "" {
				cp := parsed
				withErr = &cp
			}
		}
		if withErr != nil {
			return withErr
		}
		if newest != nil {
			return newest
		}
	}
	return nil
}
