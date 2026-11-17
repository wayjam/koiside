package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"

	"koiside/internal/account"
	"koiside/internal/device"
)

func writeSampleIPA(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "Sample.ipa")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	infoBytes, _ := plist.Marshal(map[string]any{
		"CFBundleIdentifier":         "com.example.sample",
		"CFBundleDisplayName":        "SampleApp",
		"CFBundleShortVersionString": "1.0.0",
		"CFBundleVersion":            "1",
		"MinimumOSVersion":           "15.0",
	}, plist.XMLFormat)
	w, _ := zw.Create("Payload/Sample.app/Info.plist")
	_, _ = w.Write(infoBytes)
	_ = zw.Close()
	_ = f.Close()
	return p
}

func TestCLIIPAInspectAndExportJSON(t *testing.T) {
	dir := t.TempDir()
	inIPA := writeSampleIPA(t, dir)
	outIPA := filepath.Join(dir, "Out.ipa")

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"ipa", "inspect", inIPA, "--json"}, Deps{}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("inspect exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var rep IPAReportResult
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.BundleID != "com.example.sample" || rep.DisplayName != "SampleApp" {
		t.Fatalf("unexpected inspect report: %+v", rep)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"ipa", "export", inIPA, "--bundle-id", "com.example.copy", "-o", outIPA, "--json"}, Deps{}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("export exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var prep PrepareIPAResult
	if err := json.Unmarshal(stdout.Bytes(), &prep); err != nil {
		t.Fatal(err)
	}
	if prep.Exported == nil || prep.Exported.OutputPath != outIPA {
		t.Fatalf("unexpected export result: %+v", prep)
	}
}

func TestCLIDeviceStatusAndActionRequired(t *testing.T) {
	deps := Deps{
		Accounts: account.Unavailable{},
		Probe: func() (device.Snapshot, error) {
			return device.Snapshot{
				Device:               device.Device{ID: 1, UDID: "UDID-1", ConnectionType: "USB"},
				Info:                 device.Info{Name: "Lumia1530", Version: "27.0.1"},
				DeveloperModeKnown:   true,
				DeveloperModeEnabled: true,
				LiveContainer:        &device.InstalledApp{BundleID: "com.kdt.livecontainer.T1", Name: "LiveContainer", Version: "3.8.14"},
				LiveContainerApps:    []device.LiveContainerApp{{Folder: "com.example.piliplus.app", Name: "PiliPlus", BundleID: "com.example.piliplus", Version: "2.2.1"}},
				LatestSideStoreLog:   &device.SideStoreLogSummary{File: "console.log", Operation: "refresh", Status: "SUCCESS"},
				USBVerified:          true,
			}, nil
		},
	}

	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"device", "status", "--json"}, deps, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("device status exit=%d stderr=%s", code, stderr.String())
	}
	var ds DeviceStatusResult
	if err := json.Unmarshal(stdout.Bytes(), &ds); err != nil {
		t.Fatal(err)
	}
	if !ds.Connected || len(ds.LiveContainerApps) != 1 || ds.LatestSideStoreLog == nil || ds.LatestSideStoreLog.Status != "SUCCESS" {
		t.Fatalf("unexpected device status: %+v", ds)
	}

	// Attempting account certs without login yields ExitActionRequired + JSON action_required
	stdout.Reset()
	code = Run(context.Background(), []string{"account", "certs", "--json"}, deps, &stdout, &stderr)
	if code != ExitActionRequired {
		t.Fatalf("expected ExitActionRequired (3), got %d stdout=%s", code, stdout.String())
	}
	var ar map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &ar); err != nil {
		t.Fatal(err)
	}
	if ar["status"] != "action_required" || ar["reason"] != "needs_apple_signin" {
		t.Fatalf("unexpected action_required envelope: %+v", ar)
	}
}
