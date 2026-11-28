package device

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicVerifiesBytes(t *testing.T) {
	conn := &afcConn{}
	transfer, err := NewAFC(conn).WriteAtomic("Documents/test.ipa", []byte("ipa"))
	if err != nil {
		t.Fatal(err)
	}
	if transfer.Path != "Documents/test.ipa" || transfer.SHA256 != SHA256([]byte("ipa")) {
		t.Fatalf("transfer %+v", transfer)
	}
	if !bytes.Contains(conn.written, []byte("Documents/test.ipa.partial")) {
		t.Fatal("temporary path was not used")
	}
}

func TestWriteReaderStreamsAllBytes(t *testing.T) {
	conn := &afcConn{}
	payload := bytes.Repeat([]byte("A"), 600*1024)
	var seen []int64
	err := NewAFC(conn).WriteReader("PublicStaging/test.ipa", bytes.NewReader(payload), int64(len(payload)), func(up, tot int64) {
		seen = append(seen, up)
		if tot != int64(len(payload)) {
			t.Fatalf("unexpected total %d", tot)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) < 2 || seen[len(seen)-1] != int64(len(payload)) {
		t.Fatalf("unexpected progress sequence: %v", seen)
	}
}

func TestWriteAtomicUsesRename0x18AndCleansUpOnError(t *testing.T) {
	conn := &afcConn{}
	transfer, err := NewAFC(conn).WriteAtomic("/Documents/existing.ipa", []byte("ipa"))
	if err != nil {
		t.Fatal(err)
	}
	if transfer.Path != "/Documents/existing.ipa" {
		t.Fatalf("path %s", transfer.Path)
	}
	var sawRename bool
	for _, op := range conn.ops {
		if op == afcOpRenamePath {
			sawRename = true
		}
	}
	if afcOpRenamePath != 0x18 {
		t.Fatalf("afcOpRenamePath = %#x, want 0x18", afcOpRenamePath)
	}
	if !sawRename {
		t.Fatalf("expected rename 0x18 op, got %v", conn.ops)
	}
	if !bytes.Contains(conn.written, []byte("/Documents/existing.ipa.partial\x00/Documents/existing.ipa\x00")) {
		t.Fatal("rename payload did not contain null-separated source and target paths")
	}

	failConn := &afcConn{failRename: true}
	if _, err := NewAFC(failConn).WriteAtomic("/Documents/existing.ipa", []byte("ipa")); err == nil {
		t.Fatal("expected rename error")
	}
	var sawCleanupRemove bool
	for _, op := range failConn.ops {
		if op == afcOpRemovePath {
			sawCleanupRemove = true
		}
	}
	if !sawCleanupRemove {
		t.Fatalf("expected temp file cleanup remove on rename error, got %v", failConn.ops)
	}
}

func TestWriteAtomicRejectsDifferentBytes(t *testing.T) {
	conn := &afcConn{corrupt: true}
	if _, err := NewAFC(conn).WriteAtomic("Documents/test.ipa", []byte("ipa")); err == nil {
		t.Fatal("different remote bytes were accepted")
	}
}

func TestReadDirAndStat(t *testing.T) {
	conn := &afcConn{}
	afc := NewAFC(conn)
	entries, err := afc.ReadDir("/Documents")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0] != "Aidoku-v0.9.ipa" {
		t.Fatalf("entries %+v", entries)
	}
	st, err := afc.Stat("/Documents/Aidoku-v0.9.ipa")
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != 12345 || st.Type != "S_IFREG" {
		t.Fatalf("stat %+v", st)
	}
}

type afcConn struct {
	written      []byte
	reply        []byte
	read         int
	corrupt      bool
	failRename   bool
	ops          []uint64
	lastFileData []byte
}

func (c *afcConn) Write(p []byte) (int, error) {
	c.written = append(c.written, p...)
	if len(p) < afcHeaderSize {
		return len(p), nil
	}
	op := binary.LittleEndian.Uint64(p[32:40])
	c.ops = append(c.ops, op)
	switch op {
	case afcOpFileWrite:
		if len(p) > afcHeaderSize+8 {
			c.lastFileData = append(c.lastFileData, p[afcHeaderSize+8:]...)
		}
		c.reply = append(c.reply, afcPacket(afcOpStatus, statusBody(afcSuccess))...)
	case afcOpFileOpen:
		res := make([]byte, 8)
		binary.LittleEndian.PutUint64(res, 1)
		c.reply = append(c.reply, afcPacket(afcOpFileOpenRes, res)...)
	case afcOpFileRead:
		body := []byte("ipa")
		if len(c.lastFileData) > 0 {
			body = c.lastFileData
		}
		if c.corrupt {
			body = []byte("bad")
		}
		c.reply = append(c.reply, afcPacket(afcOpData, body)...)
	case afcOpReadDir:
		c.reply = append(c.reply, afcPacket(afcOpData, []byte(".\x00..\x00Aidoku-v0.9.ipa\x00"))...)
	case afcOpGetFileInfo:
		c.reply = append(c.reply, afcPacket(afcOpData, []byte("st_size\x0012345\x00st_ifmt\x00S_IFREG\x00"))...)
	case afcOpRenamePath:
		if c.failRename {
			c.reply = append(c.reply, afcPacket(afcOpStatus, statusBody(8))...)
		} else {
			c.reply = append(c.reply, afcPacket(afcOpStatus, statusBody(afcSuccess))...)
		}
	default:
		c.reply = append(c.reply, afcPacket(afcOpStatus, statusBody(afcSuccess))...)
	}
	return len(p), nil
}

func (c *afcConn) Read(p []byte) (int, error) {
	if c.read >= len(c.reply) {
		return 0, io.EOF
	}
	n := copy(p, c.reply[c.read:])
	c.read += n
	return n, nil
}

func (c *afcConn) Close() error { return nil }

func afcPacket(operation uint64, body []byte) []byte {
	header := make([]byte, afcHeaderSize)
	copy(header, afcMagic)
	binary.LittleEndian.PutUint64(header[8:], uint64(afcHeaderSize+len(body)))
	binary.LittleEndian.PutUint64(header[16:], afcHeaderSize)
	binary.LittleEndian.PutUint64(header[32:], operation)
	return append(header, body...)
}

func statusBody(code uint64) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint64(body, code)
	return body
}

func TestUploadDirStreamsFilesWithoutBuffering(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f1Data := bytes.Repeat([]byte("A"), 600*1024)
	f2Data := bytes.Repeat([]byte("B"), 100*1024)
	if err := os.WriteFile(filepath.Join(tmp, "file1.bin"), f1Data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "file2.bin"), f2Data, 0o644); err != nil {
		t.Fatal(err)
	}

	conn := &afcConn{}
	afc := NewAFC(conn)
	var lastSeen int64
	err := afc.UploadDir(tmp, "PublicStaging/app.app", func(up, tot int64) {
		lastSeen = up
		if tot != int64(len(f1Data)+len(f2Data)) {
			t.Fatalf("unexpected total size: %d", tot)
		}
	})
	if err != nil {
		t.Fatalf("UploadDir failed: %v", err)
	}
	if lastSeen != int64(len(f1Data)+len(f2Data)) {
		t.Fatalf("expected uploaded bytes %d, got %d", len(f1Data)+len(f2Data), lastSeen)
	}
	// Verify that write operations were performed
	writeOps := 0
	for _, op := range conn.ops {
		if op == afcOpFileWrite {
			writeOps++
		}
	}
	if writeOps < 2 {
		t.Fatalf("expected multiple write ops, got %d", writeOps)
	}
}
