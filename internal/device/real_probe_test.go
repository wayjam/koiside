package device

import (
	"os"
	"strings"
	"testing"
)

func TestRealDeviceProbe(t *testing.T) {
	if os.Getenv("KOISIDE_REAL_DEVICE") != "1" {
		t.Skip("set KOISIDE_REAL_DEVICE=1 to probe attached device")
	}
	c, err := Dial()
	if err != nil {
		t.Fatalf("Dial usbmuxd: %v", err)
	}
	defer c.Close()
	devs, err := c.List()
	if err != nil {
		t.Fatalf("List devices: %v", err)
	}
	t.Logf("Found %d device(s)", len(devs))
	for _, d := range devs {
		udidMask := d.UDID
		if len(udidMask) > 8 {
			udidMask = udidMask[:4] + "..." + udidMask[len(udidMask)-4:]
		}
		t.Logf("Device ID=%d Conn=%s UDID=%s", d.ID, d.ConnectionType, udidMask)
		info, err := Query(nil, d.ID)
		if err != nil {
			t.Logf("  Unpaired Query error: %v", err)
		} else {
			t.Logf("  Public Info: Name=%q Version=%q Build=%q Type=%q", info.Name, info.Version, info.Build, info.Type)
		}

		sess, err := DialSession(nil, d.ID, d.UDID)
		if err != nil {
			t.Fatalf("  DialSession error: %v", err)
		}
		defer sess.Close()
		t.Logf("  Session Info: Name=%q Version=%q Build=%q Type=%q", sess.Info.Name, sess.Info.Version, sess.Info.Build, sess.Info.Type)

		apps, err := sess.ListApps()
		if err != nil {
			t.Fatalf("  ListApps error: %v", err)
		}
		t.Logf("  Installed user apps: %d", len(apps))
		var sideStoreID string
		for _, app := range apps {
			lower := strings.ToLower(app.BundleID + " " + app.Name)
			if strings.Contains(lower, "sidestore") ||
				strings.Contains(lower, "localdevvpn") ||
				strings.Contains(lower, "livecontainer") ||
				strings.Contains(lower, "aidoku") ||
				strings.Contains(lower, "tencent") {
				t.Logf("    App: BundleID=%s Name=%q Version=%s Build=%s TeamID=%s FileSharing=%v DocBrowser=%v Signer=%q",
					app.BundleID, app.Name, app.Version, app.Build, app.TeamID, app.FileSharing, app.DocumentBrowser, app.Signer)
			}
			if strings.Contains(strings.ToLower(app.BundleID), "sidestore") && !strings.Contains(strings.ToLower(app.BundleID), "altstore") ||
				strings.Contains(strings.ToLower(app.Name), "sidestore") {
				if sideStoreID == "" || len(app.BundleID) < len(sideStoreID) {
					sideStoreID = app.BundleID
				}
			}
		}

		if sideStoreID != "" {
			afc, err := sess.VendDocuments(sideStoreID)
			if err != nil {
				t.Logf("  VendDocuments(%s) error: %v", sideStoreID, err)
			} else {
				defer afc.Close()
				entries, err := afc.ReadDir("/Documents")
				if err != nil {
					t.Logf("  ReadDir(/Documents) error: %v", err)
				} else {
					t.Logf("  SideStore (%s) /Documents entries (%d): %v", sideStoreID, len(entries), entries)
					for _, entry := range entries {
						st, err := afc.Stat("/Documents/" + entry)
						if err != nil {
							t.Logf("    Stat(%s) err: %v", entry, err)
						} else {
							t.Logf("    Entry %s: size=%d type=%s", entry, st.Size, st.Type)
						}
						if entry == "Aidoku-v0.9.ipa" {
							data, err := afc.ReadFile("/Documents/" + entry)
							if err != nil {
								t.Fatalf("    ReadFile(%s) err: %v", entry, err)
							}
							t.Logf("    ReadFile(%s): bytes=%d sha256=%s", entry, len(data), SHA256(data))
						}
					}
				}
			}
		} else {
			t.Logf("  SideStore not detected among user apps")
		}
	}
}

func TestRealProbeFirst(t *testing.T) {
	if os.Getenv("KOISIDE_REAL_DEVICE") != "1" {
		t.Skip("set KOISIDE_REAL_DEVICE=1 to probe attached device")
	}
	snap, err := ProbeFirst(nil)
	if err != nil {
		t.Fatalf("ProbeFirst: %v", err)
	}
	if snap.Device.ID == 0 {
		t.Skip("no attached iOS device detected")
	}
	if snap.SessionErr != nil {
		t.Fatalf("snap session failed: device=%+v sessionErr=%v", snap.Device, snap.SessionErr)
	}
	t.Logf("Snapshot: Name=%q Version=%q Build=%q Type=%q Apps=%d USBVerified=%v",
		snap.Info.Name, snap.Info.Version, snap.Info.Build, snap.Info.Type, len(snap.Apps), snap.USBVerified)
	if snap.SideStore != nil {
		t.Logf("  SideStore: %s (%s)", snap.SideStore.BundleID, snap.SideStore.Version)
	}
	if snap.LocalDevVPN != nil {
		t.Logf("  LocalDevVPN: %s (%s)", snap.LocalDevVPN.BundleID, snap.LocalDevVPN.Version)
	}
	t.Logf("  LiveContainer: %v", snap.LiveContainer != nil)
	t.Logf("  SideStoreDocs: %v", snap.SideStoreDocs)
}

func TestRealAFCWriteAtomicRoundtrip(t *testing.T) {
	if os.Getenv("KOISIDE_REAL_DEVICE") != "1" || os.Getenv("KOISIDE_REAL_WRITE_TEST") != "1" {
		t.Skip("set KOISIDE_REAL_DEVICE=1 KOISIDE_REAL_WRITE_TEST=1 to test AFC write+rename+remove")
	}
	snap, err := ProbeFirst(nil)
	if err != nil {
		t.Fatalf("ProbeFirst: %v", err)
	}
	if snap.Device.ID == 0 || snap.SideStore == nil {
		t.Skip("device or SideStore not connected")
	}
	sess, err := DialSession(nil, snap.Device.ID, snap.Device.UDID)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer sess.Close()
	afc, err := sess.VendDocuments(snap.SideStore.BundleID)
	if err != nil {
		t.Fatalf("VendDocuments: %v", err)
	}
	defer afc.Close()

	testPath := "/Documents/.koiside_probe_test.txt"
	_ = afc.Remove(testPath)
	payload := []byte("koiside-afc-write-verify-test")
	tr, err := afc.WriteAtomic(testPath, payload)
	if err != nil {
		t.Fatalf("WriteAtomic failed: %v", err)
	}
	t.Logf("WriteAtomic succeeded: %+v", tr)
	if err := afc.Remove(testPath); err != nil {
		t.Fatalf("cleanup Remove failed: %v", err)
	}
}
