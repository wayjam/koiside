package device

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestListDevicesFromFixture(t *testing.T) {
	reply := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>DeviceList</key><array><dict>
<key>Properties</key><dict>
<key>DeviceID</key><integer>7</integer>
<key>SerialNumber</key><string>00008101-EXAMPLE</string>
<key>ConnectionType</key><string>USB</string>
</dict></dict></array></dict></plist>`
	conn := &scriptConn{reply: frame(reply)}
	devices, err := New(conn).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].ID != 7 || devices[0].UDID != "00008101-EXAMPLE" || devices[0].ConnectionType != "USB" {
		t.Fatalf("devices %+v", devices)
	}
	if !bytes.Contains(conn.written, []byte("ListDevices")) {
		t.Fatalf("request %q", conn.written)
	}
}

func TestMissingDeviceFieldsStayUnknown(t *testing.T) {
	reply := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>DeviceList</key><array><dict>
<key>Properties</key><dict><key>DeviceID</key><integer>3</integer></dict>
</dict></array></dict></plist>`
	devices, err := New(&scriptConn{reply: frame(reply)}).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].UDID != "" || devices[0].ConnectionType != "" {
		t.Fatalf("devices %+v", devices)
	}
}

func frame(body string) []byte {
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[0:], uint32(len(body)+headerSize))
	binary.LittleEndian.PutUint32(header[4:], plistVersion)
	binary.LittleEndian.PutUint32(header[8:], messagePlist)
	binary.LittleEndian.PutUint32(header[12:], 1)
	return append(header, body...)
}

type scriptConn struct {
	reply   []byte
	written []byte
	read    int
}

func (c *scriptConn) Read(p []byte) (int, error) {
	if c.read >= len(c.reply) {
		return 0, io.EOF
	}
	n := copy(p, c.reply[c.read:])
	c.read += n
	return n, nil
}

func (c *scriptConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	return len(p), nil
}

func (c *scriptConn) Close() error { return nil }
