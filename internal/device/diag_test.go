package device

import (
	"testing"

	"howett.net/plist"
)

func TestParseLiveContainerAppPlist(t *testing.T) {
	raw, err := plist.Marshal(map[string]any{
		"CFBundleIdentifier":         "com.example.piliplus",
		"CFBundleDisplayName":        "PiliPlus",
		"CFBundleShortVersionString": "2.2.1",
		"CFBundleVersion":            "5655",
	}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	app, ok := parseLiveContainerAppPlist("com.example.piliplus.app", raw)
	if !ok {
		t.Fatal("expected valid LiveContainer app plist")
	}
	if app.BundleID != "com.example.piliplus" || app.Name != "PiliPlus" || app.Version != "2.2.1" || app.Build != "5655" {
		t.Fatalf("unexpected parsed app: %+v", app)
	}
}

func TestParseSideStoreLogExtractsOperationAndError(t *testing.T) {
	logText := `
2026-11-17T00:10:02.100 [D]: [RefreshAppOperation] execute() started
2026-11-17T00:10:05.900 [E]: [InstallAppOperation] FAILED: Error 1414 No Wi-Fi/LocalDevVPN
2026-11-17T00:10:06.322 [I]: Operation: refresh | App ID: com.kdt.livecontainer | Status: SUCCESS | Elapsed: 3.876s
`
	sum := ParseSideStoreLog("console_20261117.log", logText)
	if sum.Operation != "refresh" || sum.AppID != "com.kdt.livecontainer" || sum.Status != "SUCCESS" || sum.Elapsed != "3.876s" {
		t.Fatalf("unexpected log summary: %+v", sum)
	}
	if sum.FinishedAt != "2026-11-17T00:10:06.322" {
		t.Fatalf("unexpected FinishedAt: %q", sum.FinishedAt)
	}
	if sum.LastError == "" {
		t.Fatalf("expected LastError captured")
	}
}
