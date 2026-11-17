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
		{BundleID: "com.tencent.xin", Name: "微信"},
	})
	if len(targets) != 2 || targets[0].Name != "SideStore" || targets[1].Name != "LiveContainer" {
		t.Fatalf("unexpected pairing targets: %+v", targets)
	}
}
