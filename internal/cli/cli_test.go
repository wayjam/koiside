package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"howett.net/plist"

	"koiside/internal/account"
	"koiside/internal/appleauth"
	"koiside/internal/appstore"
	"koiside/internal/appstore/sap"
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

func TestCLIStoreSearchDownloadAndActionRequired(t *testing.T) {
	var srvURL string
	var ipaBytes bytes.Buffer
	zw := zip.NewWriter(&ipaBytes)
	infoData, _ := plist.Marshal(map[string]any{
		"CFBundleExecutable":         "DemoApp",
		"CFBundleIdentifier":         "com.example.demo",
		"CFBundleShortVersionString": "2.0.0",
	}, plist.XMLFormat)
	w, _ := zw.Create("Payload/DemoApp.app/Info.plist")
	_, _ = w.Write(infoData)
	_ = zw.Close()
	rawIPA := ipaBytes.Bytes()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/search":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resultCount": 1,
				"results": []map[string]any{{
					"trackId":        999,
					"bundleId":       "com.example.demo",
					"trackName":      "DemoApp",
					"version":        "2.0.0",
					"price":          0,
					"formattedPrice": "Free",
				}},
			})
		case "/lookup":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resultCount": 1,
				"results": []map[string]any{{
					"trackId":   999,
					"bundleId":  "com.example.demo",
					"trackName": "DemoApp",
					"version":   "2.0.0",
					"price":     0,
				}},
			})
		case "/bag.xml":
			b, _ := plist.Marshal(map[string]any{
				"authenticateAccount": srvURL + "/auth/v1/native/fast/",
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		case "/WebObjects/MZFinance.woa/wa/buyProduct":
			b, _ := plist.Marshal(map[string]any{"jingleDocType": "purchaseSuccess", "status": 0}, plist.XMLFormat)
			_, _ = w.Write(b)
		case "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct":
			b, _ := plist.Marshal(map[string]any{
				"status": 0,
				"songList": []any{map[string]any{
					"URL": srvURL + "/cdn/demo.ipa",
					"metadata": map[string]any{
						"itemId":                   999,
						"softwareVersionBundleId":  "com.example.demo",
						"bundleShortVersionString": "2.0.0",
						"bundleVersion":            "200",
					},
					"sinfs": []any{map[string]any{"id": 0, "sinf": []byte("demo-sinf")}},
				}},
			}, plist.XMLFormat)
			_, _ = w.Write(b)
		case "/cdn/demo.ipa":
			_, _ = w.Write(rawIPA)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	storage := appleauth.NewMemoryStorage()
	mgr := account.NewLocalManager(storage)
	client := appstore.NewClient()
	client.SearchBase = srvURL
	client.BagURL = srvURL + "/bag.xml"
	client.CatalogHost = strings.TrimPrefix(srvURL, "http://")
	mgr.SetStoreClient(client)

	deps := Deps{Accounts: mgr, CacheDir: t.TempDir()}

	// Store search works without sign-in.
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"store", "search", "DemoApp", "--country", "US", "--json"}, deps, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("store search exit=%d stderr=%s", code, stderr.String())
	}
	var found []appstore.Software
	if err := json.Unmarshal(stdout.Bytes(), &found); err != nil || len(found) != 1 || found[0].BundleID != "com.example.demo" {
		t.Fatalf("unexpected search output: %s err=%v", stdout.String(), err)
	}

	// Download without sign-in yields ExitActionRequired (needs_store_signin).
	stdout.Reset()
	code = Run(context.Background(), []string{"store", "download", "com.example.demo", "--json"}, deps, &stdout, &stderr)
	if code != ExitActionRequired {
		t.Fatalf("expected ExitActionRequired, got %d stdout=%s", code, stdout.String())
	}

	// Persist a mock store session and run DownloadStoreApp.
	_ = sap.Handshake{}
	accData, _ := json.Marshal(appstore.Account{
		Email:            "store@example.invalid",
		Store:            "143441",
		PasswordToken:    "tok",
		DSID:             "42",
		DeviceIdentifier: "aabbccddeeff",
	})
	_ = storage.Set("store_session_store@example.invalid", accData)
	_ = storage.Set("store_active_account", []byte("store@example.invalid"))
	_ = storage.Set("store_account_index", []byte(`["store@example.invalid"]`))

	outIPA := filepath.Join(t.TempDir(), "out.ipa")
	dlRes, err := DownloadStoreApp(context.Background(), deps, "com.example.demo", "", "US", outIPA, true, nil)
	if err != nil {
		t.Fatalf("DownloadStoreApp failed: %v", err)
	}
	if dlRes.OutputPath != outIPA || dlRes.SizeBytes == 0 {
		t.Fatalf("unexpected DownloadStoreApp result: %+v", dlRes)
	}
}
