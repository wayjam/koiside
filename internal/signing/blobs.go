package signing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"howett.net/plist"
)

const (
	csMagicRequirement    uint32 = 0xfade0c00
	csMagicRequirementSet uint32 = 0xfade0c01
	csMagicCodeDirectory  uint32 = 0xfade0c02
	csMagicEmbeddedSig    uint32 = 0xfade0cc0
	csMagicEntitlements   uint32 = 0xfade7171
	csMagicEntitlementsDR uint32 = 0xfade7172
	csMagicBlobWrapper    uint32 = 0xfade0b01

	csSlotCodeDirectory  uint32 = 0
	csSlotInfo           uint32 = 1
	csSlotRequirements   uint32 = 2
	csSlotResourceDir    uint32 = 3
	csSlotEntitlements   uint32 = 5
	csSlotEntitlementsDR uint32 = 7
	csSlotAltCD0         uint32 = 0x1000
	csSlotSignature      uint32 = 0x10000

	csHashSHA1   uint8 = 1
	csHashSHA256 uint8 = 2

	csVersionScatter  uint32 = 0x20100
	csVersionTeamID   uint32 = 0x20200
	csVersionLimit64  uint32 = 0x20300
	csVersionExecSeg  uint32 = 0x20400

	csFlagAdhoc uint32 = 0x0002

	execSegMainBinary    uint64 = 0x0001
	execSegAllowUnsigned uint64 = 0x0010
	execSegDebugger      uint64 = 0x0020
	execSegJIT           uint64 = 0x0040
	execSegSkipLibVal    uint64 = 0x0080
	execSegCanLoadCDHash uint64 = 0x0100
	execSegCanExecCDHash uint64 = 0x0200
)

func wrapBlob(magic uint32, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:4], magic)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(out)))
	copy(out[8:], payload)
	return out
}

func wrapSuperBlob(magic uint32, slots []slotBlob) []byte {
	sort.Slice(slots, func(i, j int) bool { return slots[i].slot < slots[j].slot })
	headerSize := 12 + len(slots)*8
	total := headerSize
	for _, s := range slots {
		total += len(s.data)
	}
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:4], magic)
	binary.BigEndian.PutUint32(out[4:8], uint32(total))
	binary.BigEndian.PutUint32(out[8:12], uint32(len(slots)))
	offset := headerSize
	for i, s := range slots {
		idxOff := 12 + i*8
		binary.BigEndian.PutUint32(out[idxOff:idxOff+4], s.slot)
		binary.BigEndian.PutUint32(out[idxOff+4:idxOff+8], uint32(offset))
		copy(out[offset:], s.data)
		offset += len(s.data)
	}
	return out
}

type slotBlob struct {
	slot uint32
	data []byte
}

// buildDesignatedRequirement builds a WWDR-pinned or team-pinned designated requirement blob.
func buildDesignatedRequirement(ident string, leaf *x509.Certificate) []byte {
	const (
		reqTypeDesignated uint32 = 3
		opAnd             uint32 = 6
		opIdent           uint32 = 2
		opAnchorAppleGen  uint32 = 15
		opCertField       uint32 = 11
		opCertGeneric     uint32 = 14
		matchEqual        uint32 = 1
		matchExists       uint32 = 0
	)
	wwdrOID := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x06, 0x02, 0x01} // 1.2.840.113635.100.6.2.1

	var buf []byte
	putU32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf = append(buf, b[:]...)
	}
	putData := func(d []byte) {
		putU32(uint32(len(d)))
		buf = append(buf, d...)
		if rem := len(d) % 4; rem != 0 {
			buf = append(buf, make([]byte, 4-rem)...)
		}
	}

	// identifier "<ident>" and anchor apple generic and (certificate leaf[subject.CN] = "<cn>" and certificate 1[field.1.2.840.113635.100.6.2.1] exists)
	putU32(1) // expr kind = opExpr
	if leaf != nil && leaf.Subject.CommonName != "" {
		putU32(opAnd)
		putU32(opIdent)
		putData([]byte(ident))
		putU32(opAnd)
		putU32(opAnchorAppleGen)
		putU32(opAnd)
		putU32(opCertField)
		putU32(0) // leaf
		putData([]byte("subject.CN"))
		putU32(matchEqual)
		putData([]byte(leaf.Subject.CommonName))
		putU32(opCertGeneric)
		putU32(1) // intermediate
		putData(wwdrOID)
		putU32(matchExists)
	} else {
		putU32(opIdent)
		putData([]byte(ident))
	}

	reqBlob := wrapBlob(csMagicRequirement, buf)
	setPayload := make([]byte, 4+8+len(reqBlob))
	binary.BigEndian.PutUint32(setPayload[0:4], 1)
	binary.BigEndian.PutUint32(setPayload[4:8], reqTypeDesignated)
	binary.BigEndian.PutUint32(setPayload[8:12], uint32(12+len(reqBlob)-len(reqBlob)+8+12-8))
	// Offset is relative to start of RequirementSetBlob (8 bytes header + 4 bytes count + 8 bytes 1 index = 20).
	binary.BigEndian.PutUint32(setPayload[8:12], 20)
	copy(setPayload[12:], reqBlob)
	return wrapBlob(csMagicRequirementSet, setPayload)
}

// encodeDEREntitlements encodes a Go plist dictionary into Apple's DER entitlements format (APPLICATION 16).
func encodeDEREntitlements(dict map[string]any) ([]byte, error) {
	encodedDict, err := encodeDERDict(dict)
	if err != nil {
		return nil, err
	}
	ver, err := asn1.Marshal(1)
	if err != nil {
		return nil, err
	}
	inner := append(ver, encodedDict...)
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        16,
		IsCompound: true,
		Bytes:      inner,
	})
}

func encodeDERDict(dict map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(dict))
	for k := range dict {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var seqBytes []byte
	for _, k := range keys {
		kBytes, err := asn1.MarshalWithParams(k, "utf8")
		if err != nil {
			return nil, err
		}
		vBytes, err := encodeDERValue(dict[k])
		if err != nil {
			return nil, fmt.Errorf("entitlement %q: %w", k, err)
		}
		pair, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      append(kBytes, vBytes...),
		})
		if err != nil {
			return nil, err
		}
		seqBytes = append(seqBytes, pair...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        16,
		IsCompound: true,
		Bytes:      seqBytes,
	})
}

func encodeDERValue(v any) ([]byte, error) {
	switch x := v.(type) {
	case bool:
		return asn1.Marshal(x)
	case string:
		return asn1.MarshalWithParams(x, "utf8")
	case int:
		return asn1.Marshal(x)
	case int64:
		return asn1.Marshal(x)
	case uint64:
		return asn1.Marshal(new(big.Int).SetUint64(x))
	case []string:
		var items []byte
		for _, item := range x {
			b, err := asn1.MarshalWithParams(item, "utf8")
			if err != nil {
				return nil, err
			}
			items = append(items, b...)
		}
		return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: items})
	case []any:
		var items []byte
		for _, item := range x {
			b, err := encodeDERValue(item)
			if err != nil {
				return nil, err
			}
			items = append(items, b...)
		}
		return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: items})
	case map[string]any:
		return encodeDERDict(x)
	default:
		return nil, fmt.Errorf("unsupported entitlement value type %T", v)
	}
}

func entitlementsToExecSegFlags(ent map[string]any, isMain bool) uint64 {
	var flags uint64
	if isMain {
		flags |= execSegMainBinary
	}
	if b, _ := ent["get-task-allow"].(bool); b {
		flags |= execSegAllowUnsigned
	}
	if b, _ := ent["run-unsigned-code"].(bool); b {
		flags |= execSegAllowUnsigned
	}
	if b, _ := ent["com.apple.private.cs.debugger"].(bool); b {
		flags |= execSegDebugger
	}
	if b, _ := ent["dynamic-codesigning"].(bool); b {
		flags |= execSegJIT
	}
	if b, _ := ent["com.apple.private.skip-library-validation"].(bool); b {
		flags |= execSegSkipLibVal
	}
	if b, _ := ent["com.apple.private.amfi.can-load-cdhash"].(bool); b {
		flags |= execSegCanLoadCDHash
	}
	if b, _ := ent["com.apple.private.amfi.can-execute-cdhash"].(bool); b {
		flags |= execSegCanExecCDHash
	}
	return flags
}

type cdParams struct {
	ident         string
	teamID        string
	flags         uint32
	codeLimit     uint64
	execSegBase   uint64
	execSegLimit  uint64
	execSegFlags  uint64
	platform      uint8
	digestType    uint8
	specialSlots  map[uint32][]byte
	codeBytes     []byte
}

func buildCodeDirectories(p cdParams, computeCodeHashes bool) (cdSHA1, cdSHA256 []byte) {
	const pageSize = 4096
	const pageShift = 12

	maxSpecial := uint32(0)
	for slot := range p.specialSlots {
		if slot > 0 && slot < 0x1000 && slot > maxSpecial {
			maxSpecial = slot
		}
	}

	nCodeSlots := int((p.codeLimit + pageSize - 1) / pageSize)
	const hdrLen = 88

	identOff := hdrLen
	identBytes := append([]byte(p.ident), 0)
	teamOff := 0
	var teamBytes []byte
	curOff := identOff + len(identBytes)
	if p.teamID != "" {
		teamOff = curOff
		teamBytes = append([]byte(p.teamID), 0)
		curOff += len(teamBytes)
	}

	hashOff1 := curOff + int(maxSpecial)*20
	totalLen1 := hashOff1 + nCodeSlots*20

	hashOff2 := curOff + int(maxSpecial)*32
	totalLen2 := hashOff2 + nCodeSlots*32

	buf1 := make([]byte, totalLen1)
	buf2 := make([]byte, totalLen2)

	fillHeader := func(buf []byte, totalLen, hashOffset int, digestLen byte, digestType uint8) {
		binary.BigEndian.PutUint32(buf[0:4], csMagicCodeDirectory)
		binary.BigEndian.PutUint32(buf[4:8], uint32(totalLen))
		binary.BigEndian.PutUint32(buf[8:12], csVersionExecSeg)
		binary.BigEndian.PutUint32(buf[12:16], p.flags)
		binary.BigEndian.PutUint32(buf[16:20], uint32(hashOffset))
		binary.BigEndian.PutUint32(buf[20:24], uint32(identOff))
		binary.BigEndian.PutUint32(buf[24:28], maxSpecial)
		binary.BigEndian.PutUint32(buf[28:32], uint32(nCodeSlots))
		if p.codeLimit <= 0xffffffff {
			binary.BigEndian.PutUint32(buf[32:36], uint32(p.codeLimit))
		} else {
			binary.BigEndian.PutUint32(buf[32:36], 0)
		}
		buf[36] = digestLen
		buf[37] = digestType
		buf[38] = p.platform
		buf[39] = pageShift
		binary.BigEndian.PutUint32(buf[40:44], 0) // spare2
		binary.BigEndian.PutUint32(buf[44:48], 0) // scatterOffset
		binary.BigEndian.PutUint32(buf[48:52], uint32(teamOff))
		binary.BigEndian.PutUint32(buf[52:56], 0) // spare3
		if p.codeLimit > 0xffffffff {
			binary.BigEndian.PutUint64(buf[56:64], p.codeLimit)
		}
		binary.BigEndian.PutUint64(buf[64:72], p.execSegBase)
		binary.BigEndian.PutUint64(buf[72:80], p.execSegLimit)
		binary.BigEndian.PutUint64(buf[80:88], p.execSegFlags)

		copy(buf[identOff:], identBytes)
		if teamOff > 0 {
			copy(buf[teamOff:], teamBytes)
		}
	}

	fillHeader(buf1, totalLen1, hashOff1, 20, csHashSHA1)
	fillHeader(buf2, totalLen2, hashOff2, 32, csHashSHA256)

	for s := uint32(1); s <= maxSpecial; s++ {
		off1 := hashOff1 - int(s)*20
		off2 := hashOff2 - int(s)*32
		if raw, ok := p.specialSlots[s]; ok {
			s1 := sha1.Sum(raw)
			s2 := sha256.Sum256(raw)
			copy(buf1[off1:off1+20], s1[:])
			copy(buf2[off2:off2+32], s2[:])
		}
	}

	if computeCodeHashes && len(p.codeBytes) > 0 {
		for i := 0; i < nCodeSlots; i++ {
			start := i * pageSize
			end := start + pageSize
			if uint64(end) > p.codeLimit {
				end = int(p.codeLimit)
			}
			chunk := p.codeBytes[start:end]
			s1 := sha1.Sum(chunk)
			s2 := sha256.Sum256(chunk)
			copy(buf1[hashOff1+i*20:hashOff1+(i+1)*20], s1[:])
			copy(buf2[hashOff2+i*32:hashOff2+(i+1)*32], s2[:])
		}
	}

	return buf1, buf2
}

func buildCodeDirectory(p cdParams) []byte {
	cdSHA1, cdSHA256 := buildCodeDirectories(p, true)
	if p.digestType == csHashSHA1 {
		return cdSHA1
	}
	return cdSHA256
}

// buildCMSSignature builds an Apple-compatible PKCS#7 / CMS SignedData DER signature over mainCD,
// embedding Apple's cdhashes plist and ASN.1 digest attributes.
func buildCMSSignature(key *rsa.PrivateKey, leaf *x509.Certificate, chain []*x509.Certificate, mainCD []byte, allCDs [][]byte, digestTypes []uint8) ([]byte, error) {
	if key == nil || leaf == nil {
		return nil, errors.New("signing: CMS signature requires key and certificate")
	}

	// 1. Build Apple cdhashes XML plist attribute (1.2.840.113635.100.9.1)
	cdHashes := make([][]byte, 0, len(allCDs))
	type oidDigest struct {
		OID    asn1.ObjectIdentifier
		Digest []byte
	}
	var seqAttrs []asn1.RawValue
	for i, cd := range allCDs {
		dt := digestTypes[i]
		var full []byte
		var oid asn1.ObjectIdentifier
		if dt == csHashSHA1 {
			s := sha1.Sum(cd)
			full = s[:]
			oid = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
		} else {
			s := sha256.Sum256(cd)
			full = s[:]
			oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
		}
		trunc := make([]byte, 20)
		copy(trunc, full[:20])
		cdHashes = append(cdHashes, trunc)

		b, err := asn1.Marshal(oidDigest{OID: oid, Digest: full})
		if err != nil {
			return nil, err
		}
		seqAttrs = append(seqAttrs, asn1.RawValue{FullBytes: b})
	}
	plistXML, err := plist.Marshal(map[string]any{"cdhashes": cdHashes}, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(string(plistXML), "\n") {
		plistXML = append(plistXML, '\n')
	}

	// 2. SignedAttributes
	mainDigest := sha256.Sum256(mainCD)
	oidContentType := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCDDigestsPlist := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
	oidCDDigests := asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}

	attrBytes := func(oid asn1.ObjectIdentifier, vals ...[]byte) ([]byte, error) {
		var inner []byte
		for _, v := range vals {
			inner = append(inner, v...)
		}
		setRaw, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: inner})
		if err != nil {
			return nil, err
		}
		oidRaw, err := asn1.Marshal(oid)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(oidRaw, setRaw...)})
	}

	vContentType, _ := asn1.Marshal(oidData)
	vDigest, _ := asn1.Marshal(mainDigest[:])
	vTime, _ := asn1.Marshal(time.Now().UTC())
	vPlist, _ := asn1.Marshal(plistXML)

	aCT, _ := attrBytes(oidContentType, vContentType)
	aTime, _ := attrBytes(oidSigningTime, vTime)
	aMD, _ := attrBytes(oidMessageDigest, vDigest)
	aPlist, _ := attrBytes(oidCDDigestsPlist, vPlist)
	rawSeqs := make([][]byte, 0, len(seqAttrs))
	for _, s := range seqAttrs {
		rawSeqs = append(rawSeqs, s.FullBytes)
	}
	aCDs, _ := attrBytes(oidCDDigests, rawSeqs...)

	attrs := [][]byte{aCT, aTime, aMD, aPlist, aCDs}
	// DER SET OF requires lexicographical sorting by encoded byte slice.
	sort.Slice(attrs, func(i, j int) bool { return string(attrs[i]) < string(attrs[j]) })

	var setPayload []byte
	for _, a := range attrs {
		setPayload = append(setPayload, a...)
	}
	signedAttrsSET, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: setPayload})
	if err != nil {
		return nil, err
	}
	attrHash := sha256.Sum256(signedAttrsSET)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, attrHash[:])
	if err != nil {
		return nil, err
	}

	// SignerInfo
	type issuerAndSerial struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	ias := issuerAndSerial{
		Issuer:       asn1.RawValue{FullBytes: leaf.RawIssuer},
		SerialNumber: leaf.SerialNumber,
	}
	sha256Alg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Parameters: asn1.NullRawValue}
	rsaAlg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Parameters: asn1.NullRawValue}
	signedAttrsImplicit := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: setPayload}

	signerInfoStruct := struct {
		Version            int
		SID                issuerAndSerial
		DigestAlgorithm    pkix.AlgorithmIdentifier
		SignedAttrs        asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          []byte
	}{
		Version:            1,
		SID:                ias,
		DigestAlgorithm:    sha256Alg,
		SignedAttrs:        signedAttrsImplicit,
		SignatureAlgorithm: rsaAlg,
		Signature:          sigBytes,
	}
	signerInfoDER, err := asn1.Marshal(signerInfoStruct)
	if err != nil {
		return nil, err
	}

	// Certificates [0] IMPLICIT SET OF Certificate (leaf first, then chain)
	var certBytes []byte
	certBytes = append(certBytes, leaf.Raw...)
	for _, c := range chain {
		certBytes = append(certBytes, c.Raw...)
	}

	digestSet, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      mustMarshal(sha256Alg),
	})
	encapInfo, _ := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
	}{ContentType: oidData})
	certsField, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certBytes})
	signerInfosSet, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: signerInfoDER})

	var sdInner []byte
	sdInner = append(sdInner, mustMarshal(1)...)
	sdInner = append(sdInner, digestSet...)
	sdInner = append(sdInner, encapInfo...)
	sdInner = append(sdInner, certsField...)
	sdInner = append(sdInner, signerInfosSet...)

	sdDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: sdInner})
	if err != nil {
		return nil, err
	}

	ciBytes := append(mustMarshal(oidSignedData), mustMarshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER})...)
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: ciBytes})
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
