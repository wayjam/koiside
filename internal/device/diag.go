package device

import (
	"path"
	"sort"
	"strings"

	"howett.net/plist"
)

// LiveContainerApp describes an IPA installed inside LiveContainer (/Documents/Applications/*.app).
type LiveContainerApp struct {
	Folder   string `json:"folder"`
	Name     string `json:"name"`
	BundleID string `json:"bundle_id"`
	Version  string `json:"version"`
	Build    string `json:"build,omitempty"`
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
		Folder:   folder,
		Name:     name,
		BundleID: bundleID,
		Version:  stringValue(m["CFBundleShortVersionString"]),
		Build:    stringValue(m["CFBundleVersion"]),
	}, true
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
		raw, err := afc.ReadFile(path.Join("/Documents/Applications", entry, "Info.plist"))
		if err != nil {
			continue
		}
		if app, ok := parseLiveContainerAppPlist(entry, raw); ok {
			out = append(out, app)
		}
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
