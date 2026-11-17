package device

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"howett.net/plist"
)

const (
	rpPairingMagic       = "RPPairing"
	rpWireProtoVersion   = 19
	rpPairingLockdownSvc = "com.apple.dt.remotepairingdeviced.lockdown"
)

// RpPairingFile holds the Ed25519 identity + alt_irk generated during RemotePairing.
type RpPairingFile struct {
	PublicKey  []byte `plist:"public_key"`
	PrivateKey []byte `plist:"private_key"`
	Identifier string `plist:"identifier"`
	AltIRK     []byte `plist:"alt_irk,omitempty"`
}

func GenerateRpPairingFile(sendingHost string) (*RpPairingFile, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := uuidv3DNS(sendingHost)
	return &RpPairingFile{
		PublicKey:  []byte(pub),
		PrivateKey: priv.Seed(),
		Identifier: id,
	}, nil
}

func (f *RpPairingFile) MarshalPlist() ([]byte, error) {
	doc := map[string]any{
		"public_key":  f.PublicKey,
		"private_key": f.PrivateKey,
		"identifier":  f.Identifier,
	}
	if len(f.AltIRK) > 0 {
		doc["alt_irk"] = f.AltIRK
	}
	return plist.Marshal(doc, plist.XMLFormat)
}

func ParseRpPairingFile(raw []byte) (*RpPairingFile, error) {
	var f RpPairingFile
	if _, err := plist.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if len(f.PublicKey) != 32 || len(f.PrivateKey) != 32 || f.Identifier == "" {
		return nil, errors.New("device: invalid RPPairing file")
	}
	return &f, nil
}

// GenerateRPPairing performs RemotePairing over lockdown (com.apple.dt.remotepairingdeviced.lockdown),
// validates cached pairing or establishes a new pair-setup, and returns the serialized XML plist.
func (s *Session) GenerateRPPairing(sendingHost string, cached []byte) ([]byte, error) {
	if sendingHost == "" {
		sendingHost = "koiside-host"
	}
	conn, err := s.StartService(rpPairingLockdownSvc)
	if err != nil {
		return nil, fmt.Errorf("device: start %s: %w", rpPairingLockdownSvc, err)
	}
	defer conn.Close()

	var rpf *RpPairingFile
	if len(cached) > 0 {
		if parsed, perr := ParseRpPairingFile(cached); perr == nil {
			rpf = parsed
		}
	}
	if rpf == nil {
		rpf, err = GenerateRpPairingFile(sendingHost)
		if err != nil {
			return nil, err
		}
	}

	client := &rpClient{
		conn:        conn,
		sendingHost: sendingHost,
	}
	if err := client.connect(rpf); err != nil {
		return nil, err
	}
	return rpf.MarshalPlist()
}

// GenerateSideStorePairingFiles prepares both Lockdown pairing (with EnableWifiDebugging)
// and iOS 17.4+ RemotePairing (if available) for SideStore and other pairing apps.
func GenerateSideStorePairingFiles(dial Dialer, deviceID int, udid, iosVersion, hostLabel string, cachedRPPairing []byte) (lockdownPlist, rpPlist []byte, err error) {
	sess, err := DialSession(dial, deviceID, udid)
	if err != nil {
		return nil, nil, err
	}
	defer sess.Close()

	_ = sess.EnableWifiDebugging()
	lockdownPlist, err = ExportLockdownPairingPlist(dial, udid)
	if err != nil {
		return nil, nil, err
	}

	if !isIOSBelow(iosVersion, 17, 4) {
		rpPlist, err = sess.GenerateRPPairing(hostLabel, cachedRPPairing)
		if err != nil {
			// Return lockdown plist along with error so caller can inspect or retry.
			return lockdownPlist, nil, err
		}
	}
	return lockdownPlist, rpPlist, nil
}

// PairingTarget describes one installed app and the relative path(s) inside /Documents where pairing files are placed.
type PairingTarget struct {
	Name     string
	BundleID string
	Paths    []string
}

var knownPairingTargets = []struct {
	name     string
	matchIDs []string
	paths    []string
}{
	{name: "SideStore", matchIDs: []string{"com.sidestore.sidestore"}, paths: []string{"ALTPairingFile.mobiledevicepairing", "PairingFile_RemoteRP.plist", "PairingFile_Lockdown.plist"}},
	{name: "LiveContainer", matchIDs: []string{"com.kdt.livecontainer"}, paths: []string{"SideStore/Documents/ALTPairingFile.mobiledevicepairing", "SideStore/Documents/PairingFile_RemoteRP.plist"}},
	{name: "Feather", matchIDs: []string{"kh.crysalis.feather"}, paths: []string{"pairingFile.plist"}},
	{name: "StikDebug", matchIDs: []string{"com.stik.stikdebug", "stikdebug"}, paths: []string{"pairingFile.plist"}},
	{name: "Protokolle", matchIDs: []string{"protokolle"}, paths: []string{"pairingFile.plist"}},
	{name: "Antrag", matchIDs: []string{"antrag"}, paths: []string{"pairingFile.plist"}},
	{name: "SparseBox", matchIDs: []string{"sparsebox"}, paths: []string{"pairingFile.plist"}},
}

// DetectPairingTargets filters installed apps to those known to accept pairing files via AFC Documents.
func DetectPairingTargets(apps []InstalledApp) []PairingTarget {
	var out []PairingTarget
	for _, a := range apps {
		lowID := strings.ToLower(a.BundleID)
		lowName := strings.ToLower(a.Name)
		for _, spec := range knownPairingTargets {
			matched := lowName == strings.ToLower(spec.name)
			if !matched {
				for _, m := range spec.matchIDs {
					if strings.Contains(lowID, m) {
						matched = true
						break
					}
				}
			}
			if matched {
				out = append(out, PairingTarget{
					Name:     a.Name,
					BundleID: a.BundleID,
					Paths:    append([]string(nil), spec.paths...),
				})
				break
			}
		}
	}
	return out
}

// PlacePairingFiles writes pairing payloads into bundleID's /Documents container via house_arrest + AFC.
// SideStore receives RPPairing in PairingFile_RemoteRP.plist and ALTPairingFile.mobiledevicepairing (when present),
// and Lockdown pairing in PairingFile_Lockdown.plist.
func PlacePairingFiles(dial Dialer, deviceID int, udid, bundleID string, targetPaths []string, lockdownPlist, rpPlist []byte) error {
	sess, err := DialSession(dial, deviceID, udid)
	if err != nil {
		return err
	}
	defer sess.Close()

	afcConn, err := sess.VendDocuments(bundleID)
	if err != nil {
		return err
	}
	defer afcConn.Close()

	for _, rel := range targetPaths {
		rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
		if rel == "" {
			continue
		}
		payload := rpPlist
		if rel == "PairingFile_Lockdown.plist" || len(payload) == 0 {
			payload = lockdownPlist
		}
		if len(payload) == 0 {
			continue
		}
		remotePath := path.Join("/Documents", rel)
		if dir := path.Dir(remotePath); dir != "/Documents" && dir != "." {
			_ = afcConn.Mkdir(dir)
		}
		if _, err := afcConn.WriteAtomic(remotePath, payload); err != nil {
			return fmt.Errorf("device: write pairing %s: %w", remotePath, err)
		}
	}
	return nil
}

type rpClient struct {
	conn        io.ReadWriteCloser
	sendingHost string
	seq         int
}

func (c *rpClient) sendPlain(msg any) error {
	env := map[string]any{
		"message":        map[string]any{"plain": map[string]any{"_0": msg}},
		"originatedBy":   "host",
		"sequenceNumber": c.seq,
	}
	c.seq++
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	frame := make([]byte, len(rpPairingMagic)+2+len(raw))
	copy(frame, rpPairingMagic)
	binary.BigEndian.PutUint16(frame[len(rpPairingMagic):], uint16(len(raw)))
	copy(frame[len(rpPairingMagic)+2:], raw)
	_, err = c.conn.Write(frame)
	return err
}

func (c *rpClient) recvPlain() (map[string]any, error) {
	magic := make([]byte, len(rpPairingMagic))
	if _, err := io.ReadFull(c.conn, magic); err != nil {
		return nil, err
	}
	if string(magic) != rpPairingMagic {
		return nil, fmt.Errorf("device: unexpected RPPairing magic %q", string(magic))
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
		return nil, err
	}
	sz := binary.BigEndian.Uint16(lenBuf[:])
	payload := make([]byte, sz)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, err
	}
	var env map[string]any
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, err
	}
	if msg, _ := env["message"].(map[string]any); msg != nil {
		if plain, _ := msg["plain"].(map[string]any); plain != nil {
			if inner, _ := plain["_0"].(map[string]any); inner != nil {
				return inner, nil
			}
		}
	}
	return env, nil
}

func (c *rpClient) sendPairingData(data map[string]any) error {
	return c.sendPlain(map[string]any{
		"event": map[string]any{
			"_0": map[string]any{
				"pairingData": map[string]any{"_0": data},
			},
		},
	})
}

func (c *rpClient) recvPairingData() ([]byte, error) {
	msg, err := c.recvPlain()
	if err != nil {
		return nil, err
	}
	ev, _ := msg["event"].(map[string]any)
	ev0, _ := ev["_0"].(map[string]any)
	if ev0 == nil {
		return nil, errors.New("device: RPPairing missing event._0")
	}
	if rej, _ := ev0["pairingRejectedWithError"].(map[string]any); rej != nil {
		return nil, fmt.Errorf("device: RPPairing rejected: %v", rej)
	}
	pd, _ := ev0["pairingData"].(map[string]any)
	pd0, _ := pd["_0"].(map[string]any)
	b64, _ := pd0["data"].(string)
	if b64 == "" {
		return nil, errors.New("device: RPPairing missing pairingData.data")
	}
	return base64.StdEncoding.DecodeString(b64)
}

func (c *rpClient) connect(rpf *RpPairingFile) error {
	if err := c.attemptPairVerify(); err != nil {
		return err
	}
	if err := c.validatePairing(rpf); err == nil {
		return nil
	}
	return c.pairSetup(rpf)
}

func (c *rpClient) attemptPairVerify() error {
	err := c.sendPlain(map[string]any{
		"request": map[string]any{
			"_0": map[string]any{
				"handshake": map[string]any{
					"_0": map[string]any{
						"hostOptions":         map[string]any{"attemptPairVerify": true},
						"wireProtocolVersion": rpWireProtoVersion,
					},
				},
			},
		},
	})
	if err != nil {
		return err
	}
	_, err = c.recvPlain()
	return err
}

func (c *rpClient) validatePairing(rpf *RpPairingFile) error {
	privX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pubX := privX.PublicKey().Bytes()

	m1 := encodeTLV8([]tlvEntry{
		{t: 0x06, v: []byte{0x01}},
		{t: 0x03, v: pubX},
	})
	if err := c.sendPairingData(map[string]any{
		"data":            base64.StdEncoding.EncodeToString(m1),
		"kind":            "verifyManualPairing",
		"startNewSession": true,
	}); err != nil {
		return err
	}
	rawM2, err := c.recvPairingData()
	if err != nil {
		return err
	}
	m2 := decodeTLV8(rawM2)
	if hasTLV(m2, 0x07) {
		_ = c.sendPairVerifyFailed()
		return errors.New("device: pair-verify error")
	}
	peerPubBytes := collectTLV(m2, 0x03)
	if len(peerPubBytes) != 32 {
		return errors.New("device: missing peer X25519 key")
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return err
	}
	shared, err := privX.ECDH(peerPub)
	if err != nil {
		return err
	}

	okm := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, shared, []byte("Pair-Verify-Encrypt-Salt"), []byte("Pair-Verify-Encrypt-Info")), okm); err != nil {
		return err
	}
	aead, err := chacha20poly1305.New(okm)
	if err != nil {
		return err
	}

	edPriv := ed25519.NewKeyFromSeed(rpf.PrivateKey)
	var signBuf bytes.Buffer
	signBuf.Write(pubX)
	signBuf.WriteString(rpf.Identifier)
	signBuf.Write(peerPubBytes)
	sig := ed25519.Sign(edPriv, signBuf.Bytes())

	inner := encodeTLV8([]tlvEntry{
		{t: 0x01, v: []byte(rpf.Identifier)},
		{t: 0x0a, v: sig},
	})
	nonce := []byte("\x00\x00\x00\x00PV-Msg03")
	ct := aead.Seal(nil, nonce, inner, nil)

	m3 := encodeTLV8([]tlvEntry{
		{t: 0x06, v: []byte{0x03}},
		{t: 0x05, v: ct},
	})
	if err := c.sendPairingData(map[string]any{
		"data":            base64.StdEncoding.EncodeToString(m3),
		"kind":            "verifyManualPairing",
		"startNewSession": false,
	}); err != nil {
		return err
	}
	rawM4, err := c.recvPairingData()
	if err != nil {
		return err
	}
	m4 := decodeTLV8(rawM4)
	if hasTLV(m4, 0x07) {
		_ = c.sendPairVerifyFailed()
		return errors.New("device: pair-verify rejected")
	}
	return nil
}

func (c *rpClient) sendPairVerifyFailed() error {
	return c.sendPlain(map[string]any{
		"event": map[string]any{
			"_0": map[string]any{"pairVerifyFailed": map[string]any{}},
		},
	})
}

func (c *rpClient) pairSetup(rpf *RpPairingFile) error {
	m1 := encodeTLV8([]tlvEntry{
		{t: 0x00, v: []byte{0x00}},
		{t: 0x06, v: []byte{0x01}},
	})
	if err := c.sendPairingData(map[string]any{
		"data":            base64.StdEncoding.EncodeToString(m1),
		"kind":            "setupManualPairing",
		"sendingHost":     c.sendingHost,
		"startNewSession": true,
	}); err != nil {
		return err
	}

	evMsg, err := c.recvPlain()
	if err != nil {
		return err
	}
	ev, _ := evMsg["event"].(map[string]any)
	ev0, _ := ev["_0"].(map[string]any)
	if ev0 == nil {
		return errors.New("device: pairSetup missing event._0")
	}
	if rej, _ := ev0["pairingRejectedWithError"].(map[string]any); rej != nil {
		return fmt.Errorf("device: pairing rejected: %v", rej)
	}
	var rawPD []byte
	if _, waiting := ev0["awaitingUserConsent"]; waiting {
		rawPD, err = c.recvPairingData()
		if err != nil {
			return err
		}
	} else {
		pd, _ := ev0["pairingData"].(map[string]any)
		pd0, _ := pd["_0"].(map[string]any)
		b64, _ := pd0["data"].(string)
		rawPD, err = base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return err
		}
	}

	m2 := decodeTLV8(rawPD)
	if hasTLV(m2, 0x07) {
		return errors.New("device: device returned pairing error during setup")
	}
	salt := collectTLV(m2, 0x02)
	bPub := collectTLV(m2, 0x03)
	if len(salt) == 0 || len(bPub) == 0 {
		return errors.New("device: pairSetup missing salt or public key")
	}

	// SRP-6a 3072-bit (RFC 5054 G3072, g=5, SHA-512) with Pair-Setup / "000000"
	key, err := c.srp3072PairSetup(salt, bPub, "000000")
	if err != nil {
		return err
	}

	setupEncKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, key, []byte("Pair-Setup-Encrypt-Salt"), []byte("Pair-Setup-Encrypt-Info")), setupEncKey); err != nil {
		return err
	}
	ctrlSignKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, key, []byte("Pair-Setup-Controller-Sign-Salt"), []byte("Pair-Setup-Controller-Sign-Info")), ctrlSignKey); err != nil {
		return err
	}

	// Recreate Ed25519 keys for this fresh pairing
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	rpf.PublicKey = []byte(pub)
	rpf.PrivateKey = priv.Seed()

	var signBuf bytes.Buffer
	signBuf.Write(ctrlSignKey)
	signBuf.WriteString(rpf.Identifier)
	signBuf.Write(rpf.PublicKey)
	sig := ed25519.Sign(priv, signBuf.Bytes())

	devInfo := map[string]any{
		"altIRK":                     []byte("\xe9\xe8-\xc0jIykVoT\x00\x19\xb1\xc7{"),
		"btAddr":                     "11:22:33:44:55:66",
		"mac":                        []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		"remotepairing_serial_number": "AAAAAAAAAAAA",
		"accountID":                  rpf.Identifier,
		"model":                      "computer-model",
		"name":                       c.sendingHost,
	}
	infoOpack := encodeOpackDict(devInfo)

	plainM5 := encodeTLV8([]tlvEntry{
		{t: 0x01, v: []byte(rpf.Identifier)},
		{t: 0x03, v: rpf.PublicKey},
		{t: 0x0a, v: sig},
		{t: 0x11, v: infoOpack},
	})
	aead, err := chacha20poly1305.New(setupEncKey)
	if err != nil {
		return err
	}
	ct := aead.Seal(nil, []byte("\x00\x00\x00\x00PS-Msg05"), plainM5, nil)

	m5 := encodeTLV8(append(fragmentTLV(0x05, ct), tlvEntry{t: 0x06, v: []byte{0x05}}))
	if err := c.sendPairingData(map[string]any{
		"data":            base64.StdEncoding.EncodeToString(m5),
		"kind":            "setupManualPairing",
		"sendingHost":     c.sendingHost,
		"startNewSession": false,
	}); err != nil {
		return err
	}

	rawM6, err := c.recvPairingData()
	if err != nil {
		return err
	}
	m6 := decodeTLV8(rawM6)
	if hasTLV(m6, 0x07) {
		return errors.New("device: pairSetup M6 returned error")
	}
	encM6 := collectTLV(m6, 0x05)
	plainM6, err := aead.Open(nil, []byte("\x00\x00\x00\x00PS-Msg06"), encM6, nil)
	if err != nil {
		return fmt.Errorf("device: decrypt PS-Msg06: %w", err)
	}
	decM6 := decodeTLV8(plainM6)
	infoBytes := collectTLV(decM6, 0x11)
	if parsed, err := decodeOpackDict(infoBytes); err == nil {
		if irk, ok := parsed["altIRK"].([]byte); ok && len(irk) == 16 {
			rpf.AltIRK = irk
		}
	}
	return nil
}

const rfc5054G3072Hex = "" +
	"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74" +
	"020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437" +
	"4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" +
	"ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05" +
	"98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb" +
	"9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" +
	"e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718" +
	"3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33" +
	"a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" +
	"abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864" +
	"d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2" +
	"08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"

func (c *rpClient) srp3072PairSetup(salt, bPubBytes []byte, pin string) ([]byte, error) {
	nBytes, _ := hex.DecodeString(rfc5054G3072Hex)
	n := new(big.Int).SetBytes(nBytes)
	g := big.NewInt(5)
	nLen := len(nBytes)

	aBytes := make([]byte, 32)
	if _, err := rand.Read(aBytes); err != nil {
		return nil, err
	}
	a := new(big.Int).SetBytes(aBytes)
	aPub := new(big.Int).Exp(g, a, n).Bytes()
	bPub := new(big.Int).SetBytes(bPubBytes)
	if new(big.Int).Mod(bPub, n).Sign() == 0 {
		return nil, errors.New("device: invalid SRP B")
	}

	padN := func(b []byte) []byte {
		if len(b) >= nLen {
			return b[len(b)-nLen:]
		}
		out := make([]byte, nLen)
		copy(out[nLen-len(b):], b)
		return out
	}
	hash512 := func(parts ...[]byte) []byte {
		h := sha512.New()
		for _, p := range parts {
			_, _ = h.Write(p)
		}
		return h.Sum(nil)
	}

	u := new(big.Int).SetBytes(hash512(aPub, bPubBytes))
	k := new(big.Int).SetBytes(hash512(nBytes, padN(g.Bytes())))
	idHash := hash512([]byte("Pair-Setup:"), []byte(pin))
	x := new(big.Int).SetBytes(hash512(salt, idHash))

	gx := new(big.Int).Exp(g, x, n)
	kgx := new(big.Int).Mod(new(big.Int).Mul(k, gx), n)
	base := new(big.Int).Sub(bPub, kgx)
	base.Mod(base, n)
	if base.Sign() < 0 {
		base.Add(base, n)
	}
	exp := new(big.Int).Add(a, new(big.Int).Mul(u, x))
	premaster := new(big.Int).Exp(base, exp, n).Bytes()
	key := hash512(premaster)

	nHash := hash512(nBytes)
	gHash := hash512(g.Bytes())
	hng := make([]byte, len(nHash))
	for i := range hng {
		hng[i] = nHash[i] ^ gHash[i]
	}
	m1 := hash512(hng, hash512([]byte("Pair-Setup")), salt, padN(aPub), padN(bPubBytes), key)
	m2 := hash512(aPub, m1, key)

	m3 := encodeTLV8(append(append([]tlvEntry{{t: 0x06, v: []byte{0x03}}}, fragmentTLV(0x03, aPub)...), tlvEntry{t: 0x04, v: m1}))
	if err := c.sendPairingData(map[string]any{
		"data":            base64.StdEncoding.EncodeToString(m3),
		"kind":            "setupManualPairing",
		"sendingHost":     c.sendingHost,
		"startNewSession": false,
	}); err != nil {
		return nil, err
	}
	rawM4, err := c.recvPairingData()
	if err != nil {
		return nil, err
	}
	m4 := decodeTLV8(rawM4)
	if hasTLV(m4, 0x07) {
		return nil, errors.New("device: pairSetup SRP M4 rejected")
	}
	srvProof := collectTLV(m4, 0x04)
	if len(srvProof) != len(m2) || subtle.ConstantTimeCompare(srvProof, m2) != 1 {
		return nil, errors.New("device: pairSetup server proof mismatch")
	}
	return key, nil
}

type tlvEntry struct {
	t byte
	v []byte
}

func fragmentTLV(typ byte, data []byte) []tlvEntry {
	if len(data) == 0 {
		return []tlvEntry{{t: typ}}
	}
	var out []tlvEntry
	for len(data) > 0 {
		n := len(data)
		if n > 254 {
			n = 254
		}
		out = append(out, tlvEntry{t: typ, v: data[:n]})
		data = data[n:]
	}
	return out
}

func encodeTLV8(entries []tlvEntry) []byte {
	var out []byte
	for _, e := range entries {
		for _, chunk := range fragmentTLV(e.t, e.v) {
			out = append(out, chunk.t, byte(len(chunk.v)))
			out = append(out, chunk.v...)
		}
	}
	return out
}

func decodeTLV8(in []byte) []tlvEntry {
	var out []tlvEntry
	for i := 0; i+2 <= len(in); {
		t := in[i]
		l := int(in[i+1])
		i += 2
		if i+l > len(in) {
			break
		}
		out = append(out, tlvEntry{t: t, v: in[i : i+l]})
		i += l
	}
	return out
}

func collectTLV(entries []tlvEntry, typ byte) []byte {
	var out []byte
	for _, e := range entries {
		if e.t == typ {
			out = append(out, e.v...)
		}
	}
	return out
}

func hasTLV(entries []tlvEntry, typ byte) bool {
	for _, e := range entries {
		if e.t == typ {
			return true
		}
	}
	return false
}

func encodeOpackDict(m map[string]any) []byte {
	var buf bytes.Buffer
	count := len(m)
	if count < 15 {
		buf.WriteByte(byte(0xE0 + count))
	} else {
		buf.WriteByte(0xEF)
	}
	for k, v := range m {
		encodeOpackVal(&buf, k)
		encodeOpackVal(&buf, v)
	}
	if count > 14 {
		buf.WriteByte(0x03)
	}
	return buf.Bytes()
}

func encodeOpackVal(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case string:
		b := []byte(x)
		if len(b) <= 0x20 {
			buf.WriteByte(byte(0x40 + len(b)))
		} else if len(b) <= 0xFF {
			buf.WriteByte(0x61)
			buf.WriteByte(byte(len(b)))
		} else {
			buf.WriteByte(0x62)
			_ = binary.Write(buf, binary.LittleEndian, uint16(len(b)))
		}
		buf.Write(b)
	case []byte:
		if len(x) <= 0x20 {
			buf.WriteByte(byte(0x70 + len(x)))
		} else if len(x) <= 0xFF {
			buf.WriteByte(0x91)
			buf.WriteByte(byte(len(x)))
		} else {
			buf.WriteByte(0x92)
			_ = binary.Write(buf, binary.LittleEndian, uint16(len(x)))
		}
		buf.Write(x)
	case bool:
		if x {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(2)
		}
	}
}

func decodeOpackDict(b []byte) (map[string]any, error) {
	off := 0
	var objs []any
	val, err := decodeOpackVal(b, &off, &objs)
	if err != nil {
		return nil, err
	}
	m, ok := val.(map[string]any)
	if !ok {
		return nil, errors.New("device: OPACK root not a dict")
	}
	return m, nil
}

func decodeOpackVal(b []byte, off *int, objs *[]any) (any, error) {
	if *off >= len(b) {
		return nil, io.ErrUnexpectedEOF
	}
	tag := b[*off]
	*off++
	remember := func(v any) any {
		*objs = append(*objs, v)
		return v
	}
	switch {
	case tag == 0x01:
		return true, nil
	case tag == 0x02:
		return false, nil
	case tag >= 0x08 && tag <= 0x2F:
		return uint64(tag - 8), nil
	case tag == 0x30:
		v := uint64(b[*off])
		*off++
		return remember(v), nil
	case tag == 0x31:
		v := uint64(binary.LittleEndian.Uint16(b[*off : *off+2]))
		*off += 2
		return remember(v), nil
	case tag == 0x32:
		v := uint64(binary.LittleEndian.Uint32(b[*off : *off+4]))
		*off += 4
		return remember(v), nil
	case tag == 0x33:
		v := binary.LittleEndian.Uint64(b[*off : *off+8])
		*off += 8
		return remember(v), nil
	case tag >= 0x40 && tag <= 0x64:
		n, err := readOpackLen(tag, 0x40, 0x61, b, off)
		if err != nil {
			return nil, err
		}
		s := string(b[*off : *off+n])
		*off += n
		return remember(s), nil
	case tag >= 0x70 && tag <= 0x94:
		n, err := readOpackLen(tag, 0x70, 0x91, b, off)
		if err != nil {
			return nil, err
		}
		d := append([]byte(nil), b[*off:*off+n]...)
		*off += n
		return remember(d), nil
	case tag >= 0xA0 && tag <= 0xC0:
		idx := int(tag - 0xA0)
		if idx >= len(*objs) {
			return nil, errors.New("device: OPACK back-ref out of range")
		}
		return (*objs)[idx], nil
	case tag >= 0xE0 && tag <= 0xEF:
		m := map[string]any{}
		if tag == 0xEF {
			for *off < len(b) && b[*off] != 0x03 {
				k, err := decodeOpackVal(b, off, objs)
				if err != nil {
					return nil, err
				}
				v, err := decodeOpackVal(b, off, objs)
				if err != nil {
					return nil, err
				}
				if ks, ok := k.(string); ok {
					m[ks] = v
				}
			}
			if *off < len(b) && b[*off] == 0x03 {
				*off++
			}
		} else {
			cnt := int(tag - 0xE0)
			for i := 0; i < cnt; i++ {
				k, err := decodeOpackVal(b, off, objs)
				if err != nil {
					return nil, err
				}
				v, err := decodeOpackVal(b, off, objs)
				if err != nil {
					return nil, err
				}
				if ks, ok := k.(string); ok {
					m[ks] = v
				}
			}
		}
		return m, nil
	default:
		return nil, fmt.Errorf("device: unsupported OPACK tag 0x%02x", tag)
	}
}

func readOpackLen(tag, base, u8Tag byte, b []byte, off *int) (int, error) {
	if tag < u8Tag {
		return int(tag - base), nil
	}
	switch tag - u8Tag {
	case 0:
		v := int(b[*off])
		*off++
		return v, nil
	case 1:
		v := int(binary.LittleEndian.Uint16(b[*off : *off+2]))
		*off += 2
		return v, nil
	case 2:
		v := int(binary.LittleEndian.Uint32(b[*off : *off+4]))
		*off += 4
		return v, nil
	default:
		v := int(binary.LittleEndian.Uint64(b[*off : *off+8]))
		*off += 8
		return v, nil
	}
}

func uuidv3DNS(name string) string {
	ns, _ := hex.DecodeString("6ba7b8109dad11d180b400c04fd430c8")
	h := md5.New()
	_, _ = h.Write(ns)
	_, _ = h.Write([]byte(name))
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x30
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func isIOSBelow(ver string, maj, minor int) bool {
	if ver == "" {
		return false
	}
	parts := strings.Split(ver, ".")
	var pmaj, pmin int
	_, _ = fmt.Sscanf(parts[0], "%d", &pmaj)
	if len(parts) > 1 {
		_, _ = fmt.Sscanf(parts[1], "%d", &pmin)
	}
	return pmaj < maj || (pmaj == maj && pmin < minor)
}
