package mcp

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"

	"koiside/internal/account"
	"koiside/internal/cli"
	"koiside/internal/device"
)

func makeTestIPA(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "TestApp.ipa")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	raw, _ := plist.Marshal(map[string]any{
		"CFBundleIdentifier":         "com.example.mcptest",
		"CFBundleDisplayName":        "MCPTest",
		"CFBundleShortVersionString": "1.2.3",
	}, plist.XMLFormat)
	w, _ := zw.Create("Payload/TestApp.app/Info.plist")
	_, _ = w.Write(raw)
	_ = zw.Close()
	_ = f.Close()
	return p
}

func TestMCPInitializeListAndToolsCall(t *testing.T) {
	ipaPath := makeTestIPA(t)

	requests := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"test","version":"1.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_ipa","arguments":{"path":` + mustJSON(ipaPath) + `}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_device_status","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_account_quota","arguments":{}}}`,
	}, "\n") + "\n"

	var out, errOut bytes.Buffer
	deps := cli.Deps{
		Accounts: account.Unavailable{},
		Probe: func() (device.Snapshot, error) {
			return device.Snapshot{
				Device: device.Device{ID: 1, UDID: "UDID-MCP", ConnectionType: "USB"},
				Info:   device.Info{Name: "Lumia1530", Version: "27.0.1"},
				LiveContainerApps: []device.LiveContainerApp{
					{Folder: "com.example.piliplus.app", Name: "PiliPlus", BundleID: "com.example.piliplus", Version: "2.2.1"},
				},
			}, nil
		},
	}

	if err := ServeStdio(context.Background(), strings.NewReader(requests), &out, &errOut, deps); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 JSON-RPC responses, got %d:\n%s", len(lines), out.String())
	}

	// 1. initialize
	var initResp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatal(err)
	}
	if initResp.Result.ProtocolVersion != protocolVersion || initResp.Result.ServerInfo.Name != "koiside" {
		t.Fatalf("unexpected initialize: %+v", initResp)
	}

	// 2. tools/list
	var listResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatal(err)
	}
	if len(listResp.Result.Tools) != 9 {
		t.Fatalf("expected 9 tools, got %d", len(listResp.Result.Tools))
	}

	// 3. inspect_ipa
	var inspectResp struct {
		Result struct {
			IsError           bool `json:"isError"`
			StructuredContent struct {
				BundleID string `json:"bundle_id"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &inspectResp); err != nil {
		t.Fatal(err)
	}
	if inspectResp.Result.IsError || inspectResp.Result.StructuredContent.BundleID != "com.example.mcptest" {
		t.Fatalf("unexpected inspect_ipa result: %s", lines[2])
	}

	// 4. get_device_status
	if !strings.Contains(lines[3], `"com.example.piliplus"`) {
		t.Fatalf("expected LiveContainerApps in get_device_status: %s", lines[3])
	}

	// 5. get_account_quota without Keychain session returns action_required gracefully (isError=false)
	var quotaResp struct {
		Result struct {
			IsError           bool `json:"isError"`
			StructuredContent struct {
				Status string `json:"status"`
				Reason string `json:"reason"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[4]), &quotaResp); err != nil {
		t.Fatal(err)
	}
	if quotaResp.Result.IsError || quotaResp.Result.StructuredContent.Status != "action_required" || quotaResp.Result.StructuredContent.Reason != "needs_apple_signin" {
		t.Fatalf("unexpected get_account_quota action_required: %s", lines[4])
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
