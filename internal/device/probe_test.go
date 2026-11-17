package device

import (
	"io"
	"testing"
)

func TestProbeFirstEmptyList(t *testing.T) {
	conn := &scriptConn{reply: frame(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>DeviceList</key><array></array></dict></plist>`)}
	snap, err := ProbeFirst(func() (io.ReadWriteCloser, error) { return conn, nil })
	if err != nil {
		t.Fatal(err)
	}
	if snap.Device.ID != 0 || snap.USBVerified {
		t.Fatalf("unexpected snap: %+v", snap)
	}
}

func TestProbeFirstHandlesUntrustedSessionGracefully(t *testing.T) {
	calls := 0
	dial := func() (io.ReadWriteCloser, error) {
		calls++
		switch calls {
		case 1: // ListDevices
			return &scriptConn{reply: frame(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>DeviceList</key><array><dict>
<key>Properties</key><dict>
<key>DeviceID</key><integer>9</integer>
<key>SerialNumber</key><string>UDID-9</string>
<key>ConnectionType</key><string>USB</string>
</dict></dict></array></dict></plist>`)}, nil
		case 2: // Query Info
			return &scriptConn{reply: append(
				frame(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Number</key><integer>0</integer></dict></plist>`),
				lockdownFrame(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Value</key><dict><key>DeviceName</key><string>TestPhone</string></dict></dict></plist>`)...,
			)}, nil
		default: // ReadPairRecord returns missing
			return &scriptConn{reply: frame(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Number</key><integer>1</integer></dict></plist>`)}, nil
		}
	}
	snap, err := ProbeFirst(dial)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Device.ID != 9 || snap.Info.Name != "TestPhone" || snap.SessionErr == nil || snap.USBVerified {
		t.Fatalf("unexpected snap: %+v", snap)
	}
}

func TestParseInstalledAppExtractsTeamAndFlags(t *testing.T) {
	app := parseInstalledApp(map[string]any{
		"CFBundleIdentifier":         "com.SideStore.SideStore.ABC123",
		"CFBundleDisplayName":        "SideStore",
		"CFBundleShortVersionString": "0.7.0",
		"UIFileSharingEnabled":       true,
		"Entitlements": map[string]any{
			"application-identifier": "ABC123DEFG.com.SideStore.SideStore.ABC123",
		},
	})
	if app.BundleID != "com.SideStore.SideStore.ABC123" || app.TeamID != "ABC123DEFG" || !app.FileSharing {
		t.Fatalf("app: %+v", app)
	}
}
