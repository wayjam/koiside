package device

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"howett.net/plist"
)

type fakeInstallConn struct {
	written []byte
	reply   []byte
	read    int
}

func (f *fakeInstallConn) Write(p []byte) (int, error) {
	f.written = append(f.written, p...)
	return len(p), nil
}

func (f *fakeInstallConn) Read(p []byte) (int, error) {
	if f.read >= len(f.reply) {
		return 0, io.EOF
	}
	n := copy(p, f.reply[f.read:])
	f.read += n
	return n, nil
}

func (f *fakeInstallConn) Close() error { return nil }

func encodePlistFrameBytes(v any) []byte {
	raw, _ := plist.Marshal(v, plist.XMLFormat)
	out := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(out[:4], uint32(len(raw)))
	copy(out[4:], raw)
	return out
}

func TestInstallStagedPackageStreamsProgressAndHandlesErrors(t *testing.T) {
	var reply bytes.Buffer
	reply.Write(encodePlistFrameBytes(map[string]any{"PercentComplete": int64(50), "Status": "ExtractingPackage"}))
	reply.Write(encodePlistFrameBytes(map[string]any{"PercentComplete": int64(100), "Status": "Complete"}))

	conn := &fakeInstallConn{reply: reply.Bytes()}
	var pcts []int
	err := InstallStagedPackage(conn, "PublicStaging/SideStore.app", func(pct int, _ string) {
		pcts = append(pcts, pct)
	})
	if err != nil {
		t.Fatalf("InstallStagedPackage failed: %v", err)
	}
	if len(pcts) < 2 || pcts[len(pcts)-1] != 100 {
		t.Fatalf("expected streamed progress ending at 100, got %v", pcts)
	}
	if !bytes.Contains(conn.written, []byte("PublicStaging/SideStore.app")) {
		t.Fatal("Install command missing PackagePath")
	}

	errConn := &fakeInstallConn{
		reply: encodePlistFrameBytes(map[string]any{
			"Error":            "ApplicationVerificationFailed",
			"ErrorDescription": "Failed to verify code signature",
		}),
	}
	if err := InstallStagedPackage(errConn, "PublicStaging/Bad.app", nil); err == nil {
		t.Fatal("expected install error")
	}
}

func TestInstallStagedPackageWithOptionsOmitsPackageTypeForStore(t *testing.T) {
	var reply bytes.Buffer
	reply.Write(encodePlistFrameBytes(map[string]any{"PercentComplete": int64(100), "Status": "Complete"}))

	conn := &fakeInstallConn{reply: reply.Bytes()}
	err := InstallStagedPackageWithOptions(conn, "PublicStaging/StoreApp.ipa", InstallOptions{}, nil)
	if err != nil {
		t.Fatalf("InstallStagedPackageWithOptions failed: %v", err)
	}
	if !bytes.Contains(conn.written, []byte("PublicStaging/StoreApp.ipa")) {
		t.Fatal("Install command missing PackagePath")
	}
	if bytes.Contains(conn.written, []byte("PackageType")) {
		t.Fatal("Store install should not force PackageType=Developer")
	}
}

func TestStagedUpgradeUsesUpgradeCommand(t *testing.T) {
	conn := &fakeInstallConn{reply: encodePlistFrameBytes(map[string]any{"Status": "Complete"})}
	err := installStagedPackage(conn, "PublicStaging/LiveContainer.app", "Upgrade", InstallOptions{PackageType: "Developer"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if _, err := plist.Unmarshal(conn.written[4:], &request); err != nil {
		t.Fatal(err)
	}
	if request["Command"] != "Upgrade" || request["PackagePath"] != "PublicStaging/LiveContainer.app" {
		t.Fatalf("unexpected upgrade request: %v", request)
	}
}

func TestRpPairingFileAndOpackAndDetectTargets(t *testing.T) {
	rpf, err := GenerateRpPairingFile("koiside-test")
	if err != nil {
		t.Fatal(err)
	}
	rpf.AltIRK = bytes.Repeat([]byte{0xAB}, 16)
	raw, err := rpf.MarshalPlist()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRpPairingFile(raw)
	if err != nil || parsed.Identifier != rpf.Identifier || len(parsed.AltIRK) != 16 {
		t.Fatalf("RpPairingFile roundtrip mismatch: %+v (%v)", parsed, err)
	}

	in := map[string]any{
		"altIRK":    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		"accountID": "acc-1",
		"name":      "koiside",
	}
	op := encodeOpackDict(in)
	dec, err := decodeOpackDict(op)
	if err != nil || dec["accountID"] != "acc-1" || dec["name"] != "koiside" {
		t.Fatalf("OPACK roundtrip mismatch: %+v (%v)", dec, err)
	}

	targets := DetectPairingTargets([]InstalledApp{
		{BundleID: "com.SideStore.SideStore.8K49", Name: "SideStore"},
		{BundleID: "com.kdt.livecontainer.8K49", Name: "LiveContainer"},
		{BundleID: "com.rileytestut.AltStore", Name: "AltStore"},
		{BundleID: "com.tencent.xin", Name: "微信"},
	})
	if len(targets) != 3 || targets[0].Name != "SideStore" || targets[1].Name != "LiveContainer" || targets[2].Name != "AltStore" {
		t.Fatalf("unexpected pairing targets: %+v", targets)
	}
	altFound := false
	for _, p := range targets[2].Paths {
		if p == "ALTPairingFile.plist" {
			altFound = true
			break
		}
	}
	if !altFound {
		t.Fatalf("AltStore missing ALTPairingFile.plist in targets: %+v", targets[2])
	}
}
func TestInstallProvisioningProfileSendsMisagentPayload(t *testing.T) {
	conn := &fakeInstallConn{
		reply: encodePlistFrameBytes(map[string]any{"Status": int64(0)}),
	}
	payload := []byte("fake-mobileprovision-bytes")
	sess := &Session{
		startService: func(name string) (io.ReadWriteCloser, error) {
			if name != misagentService {
				t.Fatalf("unexpected service: %s", name)
			}
			return conn, nil
		},
	}
	if err := sess.InstallProvisioningProfile(payload); err != nil {
		t.Fatalf("InstallProvisioningProfile failed: %v", err)
	}

	var req map[string]any
	if _, err := plist.Unmarshal(conn.written[4:], &req); err != nil {
		t.Fatal(err)
	}
	if req["MessageType"] != "Install" || req["ProfileType"] != "Provisioning" {
		t.Fatalf("unexpected misagent message: %+v", req)
	}
	if !bytes.Equal(req["Profile"].([]byte), payload) {
		t.Fatalf("unexpected profile payload in misagent request")
	}
}

func TestInstallProvisioningProfileHandlesRefusal(t *testing.T) {
	conn := &fakeInstallConn{
		reply: encodePlistFrameBytes(map[string]any{
			"Status": int64(1),
			"Error":  "ProfileNotFound",
		}),
	}
	sess := &Session{
		startService: func(_ string) (io.ReadWriteCloser, error) {
			return conn, nil
		},
	}
	if err := sess.InstallProvisioningProfile([]byte("sample")); err == nil {
		t.Fatal("expected error on status != 0, got nil")
	}
}

func TestSetSideStorePairingPreferences(t *testing.T) {
	conn := &afcConn{}
	afc := NewAFC(conn)
	prefsPath := "/Documents/SideStore/Library/Preferences/com.SideStore.SideStore.plist"
	if err := SetSideStorePairingPreferences(afc, prefsPath); err != nil {
		t.Fatalf("SetSideStorePairingPreferences failed: %v", err)
	}
	// Verify written bytes contain isPairingReset and rppairing
	if !bytes.Contains(conn.written, []byte("isPairingReset")) || !bytes.Contains(conn.written, []byte("rppairing")) {
		t.Fatalf("expected written preferences to contain isPairingReset and rppairing, got: %s", string(conn.written))
	}
}
