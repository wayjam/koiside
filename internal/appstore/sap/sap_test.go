package sap

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
)

//go:embed testdata/sap-handshake.json
var handshakeFixtureJSON []byte

type handshakeFixture struct {
	Certificate string `json:"certificate"`
	Cases       []struct {
		Entropy      [3]uint32 `json:"entropy"`
		Seconds      int64     `json:"seconds"`
		Microseconds uint32    `json:"microseconds"`
		Request      string    `json:"request"`
		Reply        string    `json:"reply"`
		RandomHash   string    `json:"randomHash"`
		Cursor       int       `json:"cursor"`
		Seed30       uint32    `json:"seed30"`
		Seed54       uint32    `json:"seed54"`
		F2Input2     string    `json:"f2Input2"`
		F2Tail       string    `json:"f2Tail"`
	} `json:"cases"`
}

func TestSAPHandshakeVectors(t *testing.T) {
	var fixture handshakeFixture
	if err := json.Unmarshal(handshakeFixtureJSON, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	certBytes, err := hex.DecodeString(fixture.Certificate)
	if err != nil {
		t.Fatalf("decode certificate: %v", err)
	}

	expectedSource := make([]byte, 576)
	for i := range expectedSource {
		expectedSource[i] = byte(i*17 + 3)
	}

	for i, tc := range fixture.Cases {
		sec := uint32(tc.Seconds)
		usec := tc.Microseconds
		hs, err := CreateHandshake(certBytes, &tc.Entropy, &sec, &usec)
		if err != nil {
			t.Fatalf("case %d CreateHandshake: %v", i, err)
		}
		if got := hex.EncodeToString(hs.Request); got != tc.Request {
			t.Fatalf("case %d request mismatch:\ngot:  %s\nwant: %s", i, got, tc.Request)
		}

		replyBytes, err := hex.DecodeString(tc.Reply)
		if err != nil {
			t.Fatalf("case %d decode reply: %v", i, err)
		}
		sess, err := hs.Complete(replyBytes)
		if err != nil {
			t.Fatalf("case %d Complete: %v", i, err)
		}

		wordsBuf := make([]byte, 624*4)
		for wi, w := range sess.Random.Words {
			binary.LittleEndian.PutUint32(wordsBuf[wi*4:], w)
		}
		randSum := sha256.Sum256(wordsBuf)
		if got := hex.EncodeToString(randSum[:]); got != tc.RandomHash {
			t.Fatalf("case %d randomHash mismatch: got %s, want %s", i, got, tc.RandomHash)
		}
		if sess.Random.Cursor != tc.Cursor {
			t.Fatalf("case %d cursor mismatch: got %d, want %d", i, sess.Random.Cursor, tc.Cursor)
		}
		if sess.Seed30 != tc.Seed30 {
			t.Fatalf("case %d seed30 mismatch: got %d, want %d", i, sess.Seed30, tc.Seed30)
		}
		if sess.Seed54 != tc.Seed54 {
			t.Fatalf("case %d seed54 mismatch: got %d, want %d", i, sess.Seed54, tc.Seed54)
		}
		if got := hex.EncodeToString(sess.F2Input2); got != tc.F2Input2 {
			t.Fatalf("case %d f2Input2 mismatch: got %s, want %s", i, got, tc.F2Input2)
		}
		if got := hex.EncodeToString(sess.F2Tail); got != tc.F2Tail {
			t.Fatalf("case %d f2Tail mismatch: got %s, want %s", i, got, tc.F2Tail)
		}
		if !bytes.Equal(sess.Source, expectedSource) {
			t.Fatalf("case %d source mismatch", i)
		}
		if len(sess.F3) != 159 {
			t.Fatalf("case %d f3 length mismatch: got %d, want 159", i, len(sess.F3))
		}
	}
}

func TestSAPRejectsTruncatedAndUnrelatedReplies(t *testing.T) {
	var fixture handshakeFixture
	if err := json.Unmarshal(handshakeFixtureJSON, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	certBytes, _ := hex.DecodeString(fixture.Certificate)
	tc := fixture.Cases[0]
	sec := uint32(tc.Seconds)
	usec := tc.Microseconds
	hs, err := CreateHandshake(certBytes, &tc.Entropy, &sec, &usec)
	if err != nil {
		t.Fatalf("CreateHandshake: %v", err)
	}
	reply, _ := hex.DecodeString(tc.Reply)
	for _, n := range []int{0, 20, 21, len(reply) - 1} {
		if _, err := hs.Complete(reply[:n]); err == nil {
			t.Fatalf("expected error for truncated reply of length %d", n)
		}
	}
	otherReply, _ := hex.DecodeString(fixture.Cases[1].Reply)
	if _, err := hs.Complete(otherReply); err == nil {
		t.Fatal("expected error for unrelated reply")
	}
}

func TestSAPF2CipherAndSignatures(t *testing.T) {
	state := uint32(0x53595031)
	nextWord := func() uint32 {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		return state
	}
	genBytes := func(n int) []byte {
		out := make([]byte, n)
		for i := range n {
			out[i] = byte(nextWord())
		}
		return out
	}

	source := genBytes(576)
	source[0xfa] = source[0xca] ^ 10
	source[0xf3] = source[0xc3] ^ 147
	f2Input1 := genBytes(16)
	f2Input2 := genBytes(16)
	f2Tail := genBytes(7)
	label := []byte("SYNTHETIC TEST SESSION / NEVER SERVER-ISSUED / ")
	f3 := append(append([]byte{}, label...), genBytes(159-len(label))...)
	var words [624]uint32
	for i := range 624 {
		words[i] = nextWord()
	}
	sess := &Session{
		Source:    source,
		F2Input1:  f2Input1,
		F2Input2:  f2Input2,
		F2Tail:    f2Tail,
		F3:        f3,
		Random:    &Random{Words: words, Cursor: 624},
		Seed30:    nextWord(),
		Seed54:    nextWord(),
		F1Address: 0x34500044,
		IVAddress: 0xeed00050,
	}

	tables, err := LoadTables()
	if err != nil {
		t.Fatalf("LoadTables: %v", err)
	}
	f2Out, err := DeriveF2(f2Input1, f2Input2, tables)
	if err != nil {
		t.Fatalf("DeriveF2: %v", err)
	}
	if got, want := hex.EncodeToString(f2Out), "ad1adda4bad5ada37fd54543681d001c"; got != want {
		t.Fatalf("F2 mismatch: got %s, want %s", got, want)
	}

	encrypt, err := CreateCipher(source, tables)
	if err != nil {
		t.Fatalf("CreateCipher: %v", err)
	}
	block1 := make([]byte, 16)
	block2 := make([]byte, 16)
	block3 := make([]byte, 16)
	for i := range 16 {
		block2[i] = byte(i)
		block3[i] = 255
	}
	expectedBlocks := []string{
		"8fcdc9e6d7c5009c7f489288231582de",
		"65810b6c7555809e4b87529110631a4c",
		"73d2bd4f671e9abe8b105aac1883036d",
	}
	for i, blk := range [][]byte{block1, block2, block3} {
		gotBytes, err := encrypt(blk)
		if err != nil {
			t.Fatalf("encrypt block %d: %v", i, err)
		}
		if got := hex.EncodeToString(gotBytes); got != expectedBlocks[i] {
			t.Fatalf("block %d mismatch: got %s, want %s", i, got, expectedBlocks[i])
		}
	}

	signer, err := CreateSigner(sess, 7)
	if err != nil {
		t.Fatalf("CreateSigner: %v", err)
	}
	body3 := make([]byte, 256)
	for i := range 256 {
		body3[i] = byte(i)
	}
	bodies := [][]byte{
		{},
		append([]byte("synthetic SAP\nbody-2"), 0, 255),
		body3,
	}
	expectedSigs := []string{
		"ba76e674c73d9db75c2986233016b94b22e062556fd029d71733726519756517",
		"4acc6269de932c753260fecfa375a6405b5b63cf621a8adace3bd7b5f0305287",
		"853914149c9de004852fffa75a4489c3cdec3f179c92903e3d94b8b2d494e4e4",
	}
	for i, body := range bodies {
		sig, err := signer.Sign(body)
		if err != nil {
			t.Fatalf("Sign %d: %v", i, err)
		}
		if len(sig) != 501 {
			t.Fatalf("signature %d length: got %d, want 501", i, len(sig))
		}
		sum := sha256.Sum256(sig)
		if got := hex.EncodeToString(sum[:]); got != expectedSigs[i] {
			t.Fatalf("signature %d hash mismatch: got %s, want %s", i, got, expectedSigs[i])
		}
	}
}
