package device

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestInfoReadsPublicFields(t *testing.T) {
	value := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Value</key><dict>
<key>DeviceName</key><string>Example</string>
<key>ProductVersion</key><string>17.0</string>
<key>ProductType</key><string>iPhone0,0</string>
</dict></dict></plist>`
	conn := &scriptConn{reply: append(frame(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Number</key><integer>0</integer></dict></plist>`), lockdownFrame(value)...)}
	info, err := Query(func() (io.ReadWriteCloser, error) { return conn, nil }, 7)
	if err != nil {
		t.Fatal(err)
	}
	if info != (Info{Name: "Example", Version: "17.0", Type: "iPhone0,0"}) {
		t.Fatalf("info %+v", info)
	}
	if !bytes.Contains(conn.written, []byte("GetValue")) {
		t.Fatal("lockdown query was not sent")
	}
}

func TestInfoRejectsFailedConnect(t *testing.T) {
	conn := &scriptConn{reply: frame(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Number</key><integer>2</integer></dict></plist>`)}
	if _, err := Query(func() (io.ReadWriteCloser, error) { return conn, nil }, 7); err == nil {
		t.Fatal("rejected connect was accepted")
	}
}

func lockdownFrame(body string) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out
}

func TestStartServiceReturnsPort(t *testing.T) {
	conn := &scriptConn{reply: lockdownFrame(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Port</key><integer>4321</integer></dict></plist>`)}
	service, err := StartService(conn, "com.apple.mobile.installation_proxy")
	if err != nil || service.Port != 4321 {
		t.Fatalf("service %+v err %v", service, err)
	}
	if !bytes.Contains(conn.written, []byte("installation_proxy")) || bytes.Contains(conn.written, []byte("Uninstall")) {
		t.Fatalf("request %q", conn.written)
	}
}

func TestStartServiceRefusesError(t *testing.T) {
	conn := &scriptConn{reply: lockdownFrame(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Error</key><string>InvalidService</string></dict></plist>`)}
	if _, err := StartService(conn, "com.apple.mobile.installation_proxy"); err == nil {
		t.Fatal("service error was accepted")
	}
}
