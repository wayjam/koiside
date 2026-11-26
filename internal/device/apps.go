package device

import (
	"fmt"
	"sort"
	"strings"
)

const installationProxyService = "com.apple.mobile.installation_proxy"

// InstalledApp is one read-only entry returned by installation_proxy.
// Empty fields were absent and remain unknown.
type InstalledApp struct {
	BundleID        string
	Name            string
	Version         string
	Build           string
	Type            string
	Signer          string
	TeamID          string
	FileSharing     bool
	DocumentBrowser bool
	URLSchemes      []string
}

// ListApps queries user-installed apps over an authenticated Session (read-only).
func (s *Session) ListApps() ([]InstalledApp, error) {
	conn, err := s.StartService(installationProxyService)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = writePlistFrame(conn, map[string]any{
		"Command": "Browse",
		"ClientOptions": map[string]any{
			"ApplicationType": "User",
			"ReturnAttributes": []string{
				"CFBundleIdentifier",
				"CFBundleDisplayName",
				"CFBundleName",
				"CFBundleShortVersionString",
				"CFBundleVersion",
				"ApplicationType",
				"SignerIdentity",
				"UIFileSharingEnabled",
				"UISupportsDocumentBrowser",
				"CFBundleURLTypes",
				"Entitlements",
			},
		},
	})
	if err != nil {
		return nil, err
	}

	var apps []InstalledApp
	for {
		reply, err := readPlistFrame(conn)
		if err != nil {
			return nil, err
		}
		if errMsg := stringValue(reply["Error"]); errMsg != "" {
			return nil, fmt.Errorf("device: installation_proxy: %s", errMsg)
		}
		if list, ok := reply["CurrentList"].([]any); ok {
			for _, raw := range list {
				if m, ok := raw.(map[string]any); ok {
					apps = append(apps, parseInstalledApp(m))
				}
			}
		}
		status := stringValue(reply["Status"])
		if status == "Complete" {
			break
		}
		if status == "" && reply["CurrentList"] == nil {
			break
		}
	}

	sort.Slice(apps, func(i, j int) bool {
		return apps[i].BundleID < apps[j].BundleID
	})
	return apps, nil
}

func parseInstalledApp(m map[string]any) InstalledApp {
	name := stringValue(m["CFBundleDisplayName"])
	if name == "" {
		name = stringValue(m["CFBundleName"])
	}
	fileSharing, _ := m["UIFileSharingEnabled"].(bool)
	docBrowser, _ := m["UISupportsDocumentBrowser"].(bool)

	var teamID string
	if ent, ok := m["Entitlements"].(map[string]any); ok {
		teamID = stringValue(ent["com.apple.developer.team-identifier"])
		if teamID == "" {
			if appID := stringValue(ent["application-identifier"]); len(appID) > 10 {
				if dot := strings.IndexByte(appID, '.'); dot > 0 {
					teamID = appID[:dot]
				}
			}
		}
	}

	var urlSchemes []string
	if types, ok := m["CFBundleURLTypes"].([]any); ok {
		for _, entry := range types {
			item, _ := entry.(map[string]any)
			schemes, _ := item["CFBundleURLSchemes"].([]any)
			for _, value := range schemes {
				if scheme := stringValue(value); scheme != "" {
					urlSchemes = append(urlSchemes, scheme)
				}
			}
		}
	}

	return InstalledApp{
		BundleID:        stringValue(m["CFBundleIdentifier"]),
		Name:            name,
		Version:         stringValue(m["CFBundleShortVersionString"]),
		Build:           stringValue(m["CFBundleVersion"]),
		Type:            stringValue(m["ApplicationType"]),
		Signer:          stringValue(m["SignerIdentity"]),
		TeamID:          teamID,
		FileSharing:     fileSharing,
		DocumentBrowser: docBrowser,
		URLSchemes:      urlSchemes,
	}
}
