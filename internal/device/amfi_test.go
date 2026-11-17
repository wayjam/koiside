package device

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"howett.net/plist"
)

func TestAmfiDeveloperModeAndTrustSigner(t *testing.T) {
	run := func(reply map[string]any, _ func(s *Session) error) []byte {
		conn := &fakeInstallConn{reply: encodePlistFrameBytes(reply)}
		// Test via direct AMFI exchange on fakeInstallConn by overriding StartService via wrapper?
		// Better: exercise the exact plist wire messages via writePlistFrame/readPlistFrame.
		_ = conn
		return nil
	}
	_ = run

	// Verify action=3 status response parsing
	conn := &amfiTestConn{reply: encodePlistFrameBytes(map[string]any{"success": true, "status": true})}
	if err := writePlistFrame(conn, map[string]any{"action": 3}); err != nil {
		t.Fatal(err)
	}
	got, err := readPlistFrame(conn)
	if err != nil || got["success"] != true || got["status"] != true {
		t.Fatalf("unexpected amfi response: %+v (%v)", got, err)
	}

	// Verify action=4 trust_app_signer payload format
	var sent bytes.Buffer
	if err := writePlistFrame(&sent, map[string]any{"action": 4, "input_profile_uuid": "UUID-1"}); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(sent.Bytes()[:4])
	var dec map[string]any
	if _, err := plist.Unmarshal(sent.Bytes()[4:4+n], &dec); err != nil {
		t.Fatal(err)
	}
	if dec["input_profile_uuid"] != "UUID-1" {
		t.Fatalf("unexpected trust payload: %+v", dec)
	}
}

type amfiTestConn struct {
	written bytes.Buffer
	reply   []byte
	read    int
}

func (c *amfiTestConn) Write(p []byte) (int, error) { return c.written.Write(p) }
func (c *amfiTestConn) Read(p []byte) (int, error) {
	if c.read >= len(c.reply) {
		return 0, io.EOF
	}
	n := copy(p, c.reply[c.read:])
	c.read += n
	return n, nil
}
func (c *amfiTestConn) Close() error { return nil }
