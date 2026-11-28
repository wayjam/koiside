// Package shortcuts exports iPhone workflows signed by the macOS Shortcuts tool.
package shortcuts

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

const launchHost = "livecontainer-launch"

// LaunchTarget addresses one guest in one LiveContainer instance.
// Instance 0 or 1 means the primary LiveContainer; 2 and up mean
// livecontainer2, livecontainer3, and so on.
type LaunchTarget struct {
	Folder          string
	ContainerFolder string
	Instance        int
}

// LaunchURL addresses a guest by its folder on the chosen LiveContainer.
func LaunchURL(target LaunchTarget) string {
	scheme := "livecontainer"
	if target.Instance > 1 {
		scheme = fmt.Sprintf("livecontainer%d", target.Instance)
	}
	query := url.Values{"bundle-name": {target.Folder}}
	if container := strings.TrimSpace(target.ContainerFolder); container != "" {
		query.Set("container-folder-name", container)
	}
	return (&url.URL{
		Scheme:   scheme,
		Host:     launchHost,
		RawQuery: encodeQuery(query),
	}).String()
}

// ValidLaunchURL reports whether the URL targets a LiveContainer guest.
func ValidLaunchURL(raw string) bool {
	_, err := parseLaunchURL(raw)
	return err == nil
}

func parseLaunchURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.Host != launchHost || u.Fragment != "" {
		return nil, fmt.Errorf("enter a launch URL copied from LiveContainer")
	}
	number, ok := strings.CutPrefix(u.Scheme, "livecontainer")
	if !ok || strings.Trim(number, "0123456789") != "" {
		return nil, fmt.Errorf("enter a launch URL copied from LiveContainer")
	}
	query, err := url.ParseQuery(strings.ReplaceAll(u.RawQuery, "+", "%2B"))
	if err != nil || len(query["bundle-name"]) != 1 || strings.TrimSpace(query.Get("bundle-name")) == "" {
		return nil, fmt.Errorf("LiveContainer launch URL must identify one app")
	}
	if containers := query["container-folder-name"]; len(containers) > 1 || (len(containers) == 1 && strings.TrimSpace(containers[0]) == "") {
		return nil, fmt.Errorf("LiveContainer launch URL names an invalid container")
	}
	if number == "1" {
		u.Scheme = "livecontainer"
	}
	u.RawQuery = encodeQuery(query)
	return u, nil
}

func encodeQuery(values url.Values) string {
	return strings.ReplaceAll(values.Encode(), "+", "%20")
}

type action struct {
	Identifier string         `plist:"WFWorkflowActionIdentifier"`
	Parameters map[string]any `plist:"WFWorkflowActionParameters"`
}

// ExportLaunch writes a signed shortcut that opens the specified LiveContainer guest.
func ExportLaunch(ctx context.Context, output, name, launchURL string) error {
	u, err := parseLaunchURL(launchURL)
	if err != nil {
		return err
	}
	return sign(ctx, output, name, []action{
		{Identifier: "is.workflow.actions.url", Parameters: map[string]any{"WFURLActionURL": u.String()}},
		{Identifier: "is.workflow.actions.openurl", Parameters: map[string]any{}},
	})
}

// ExportRefresh writes a signed shortcut for the installed app's refresh action.
func ExportRefresh(ctx context.Context, output, name, appName, bundleID, teamID string) error {
	if bundleID == "" || teamID == "" {
		return fmt.Errorf("refresh requires the installed app's Bundle ID and developer team")
	}
	const intent = "RefreshAllIntent"
	return sign(ctx, output, name, []action{{
		Identifier: bundleID + "." + intent,
		Parameters: map[string]any{
			"AppIntentDescriptor": map[string]string{
				"AppIntentIdentifier": intent,
				"BundleIdentifier":    bundleID,
				"Name":                appName,
				"TeamIdentifier":      teamID,
			},
		},
	}})
}

func sign(ctx context.Context, output, name string, actions []action) error {
	raw, err := plist.Marshal(map[string]any{
		"WFWorkflowActions":                    actions,
		"WFWorkflowClientVersion":              "4528.0.4.3",
		"WFWorkflowHasOutputFallback":          false,
		"WFWorkflowIcon":                       map[string]int{"WFWorkflowIconGlyphNumber": 59511, "WFWorkflowIconStartColor": 4282601983},
		"WFWorkflowImportQuestions":            []any{},
		"WFWorkflowMinimumClientVersion":       900,
		"WFWorkflowMinimumClientVersionString": "900",
		"WFWorkflowName":                       name,
		"WFWorkflowTypes":                      []string{},
	}, plist.BinaryFormat)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(output), ".koiside-shortcut-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	unsigned := filepath.Join(dir, "unsigned.shortcut")
	signed := filepath.Join(dir, "signed.shortcut")
	if err := os.WriteFile(unsigned, raw, 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/shortcuts", "sign", "--mode", "anyone", "--input", unsigned, "--output", signed)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sign shortcut: %w %s", err, strings.TrimSpace(string(output)))
	}
	return os.Rename(signed, output)
}
