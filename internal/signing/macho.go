package signing

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	lcCodeSignature uint32 = 0x1d
	fatMagic        uint32 = 0xcafebabe
	fatMagic64      uint32 = 0xcafebabf
	fatCigam        uint32 = 0xbebafeca
	macho64MagicLE  uint32 = 0xfeedfacf
	macho32MagicLE  uint32 = 0xfeedface
)

// BinarySignOptions configures Mach-O signing for one executable or dylib.
type BinarySignOptions struct {
	Identifier       string
	TeamID           string
	IsMainExecutable bool
	InfoPlistRaw     []byte
	CodeResourcesRaw []byte
	Entitlements     map[string]any
	EntitlementsXML  []byte
	Key              *rsa.PrivateKey
	LeafCert         *x509.Certificate
	CertChain        []*x509.Certificate
}

// SignMachOFile signs a thin or universal (FAT) Mach-O file in place.
func SignMachOFile(path string, opts BinarySignOptions) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	signed, err := SignMachOBytes(raw, opts)
	if err != nil {
		return err
	}
	return os.WriteFile(path, signed, info.Mode())
}

// SignMachOBytes signs a thin or FAT Mach-O byte slice and returns the signed bytes.
func SignMachOBytes(raw []byte, opts BinarySignOptions) ([]byte, error) {
	if len(raw) < 16 {
		return nil, errors.New("signing: Mach-O file too short")
	}
	magicBE := binary.BigEndian.Uint32(raw[0:4])
	if magicBE == fatMagic || magicBE == fatMagic64 {
		return signFatMachO(raw, opts)
	}
	return signThinMachO(raw, opts)
}

func signFatMachO(raw []byte, opts BinarySignOptions) ([]byte, error) {
	r := bytes.NewReader(raw)
	ff, err := macho.NewFatFile(r)
	if err != nil {
		return nil, fmt.Errorf("signing: parse FAT Mach-O: %w", err)
	}
	defer ff.Close()

	signedSlices := make([][]byte, len(ff.Arches))
	for i, arch := range ff.Arches {
		sliceEnd := int(arch.Offset) + int(arch.Size)
		if sliceEnd > len(raw) {
			return nil, errors.New("signing: FAT slice out of bounds")
		}
		signedSlice, err := signThinMachO(raw[arch.Offset:sliceEnd], opts)
		if err != nil {
			return nil, fmt.Errorf("signing: FAT arch %v: %w", arch.Cpu, err)
		}
		signedSlices[i] = signedSlice
	}

	// Rebuild FAT header (standard 32-bit fat_header + fat_arch entries aligned on 16KB boundaries).
	const sliceAlign = 16384
	hdrSize := 8 + len(ff.Arches)*20
	offset := alignUp(hdrSize, sliceAlign)
	total := offset
	for _, s := range signedSlices {
		total += len(s)
		total = alignUp(total, sliceAlign)
	}
	// Trim trailing alignment after last slice.
	lastOffset := offset
	for i := 0; i < len(signedSlices)-1; i++ {
		lastOffset = alignUp(lastOffset+len(signedSlices[i]), sliceAlign)
	}
	out := make([]byte, lastOffset+len(signedSlices[len(signedSlices)-1]))
	binary.BigEndian.PutUint32(out[0:4], fatMagic)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(ff.Arches)))

	cur := offset
	for i, arch := range ff.Arches {
		idx := 8 + i*20
		binary.BigEndian.PutUint32(out[idx:idx+4], uint32(arch.Cpu))
		binary.BigEndian.PutUint32(out[idx+4:idx+8], uint32(arch.SubCpu))
		binary.BigEndian.PutUint32(out[idx+8:idx+12], uint32(cur))
		binary.BigEndian.PutUint32(out[idx+12:idx+16], uint32(len(signedSlices[i])))
		binary.BigEndian.PutUint32(out[idx+16:idx+20], 14) // 2^14 = 16384
		copy(out[cur:], signedSlices[i])
		cur = alignUp(cur+len(signedSlices[i]), sliceAlign)
	}
	return out, nil
}

func signThinMachO(raw []byte, opts BinarySignOptions) ([]byte, error) {
	mf, err := macho.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("signing: parse thin Mach-O: %w", err)
	}
	defer mf.Close()

	bo := mf.ByteOrder
	is64 := mf.Magic == macho.Magic64
	hdrSize := 28
	if is64 {
		hdrSize = 32
	}

	type parsedCmd struct {
		cmd     uint32
		cmdSize uint32
		raw     []byte
		segName string
		fileOff uint64
		fileSz  uint64
	}

	var cmds []parsedCmd
	var hasCodeSig bool
	var sigOff uint64
	var linkeditIdx = -1
	var textBase, textLimit uint64
	var minSectionFileOff = uint64(len(raw))

	off := hdrSize
	for i := uint32(0); i < mf.Ncmd; i++ {
		if off+8 > len(raw) {
			return nil, errors.New("signing: load command out of bounds")
		}
		cmd := bo.Uint32(raw[off : off+4])
		sz := bo.Uint32(raw[off+4 : off+8])
		if sz < 8 || off+int(sz) > len(raw) {
			return nil, errors.New("signing: invalid load command size")
		}
		cmdBytes := append([]byte(nil), raw[off:off+int(sz)]...)
		pc := parsedCmd{cmd: cmd, cmdSize: sz, raw: cmdBytes}

		switch cmd {
		case uint32(macho.LoadCmdSegment):
			pc.segName = cString(cmdBytes[8:24])
			pc.fileOff = uint64(bo.Uint32(cmdBytes[32:36]))
			pc.fileSz = uint64(bo.Uint32(cmdBytes[36:40]))
			nsects := bo.Uint32(cmdBytes[48:52])
			for s := uint32(0); s < nsects; s++ {
				soff := 56 + int(s)*68
				if soff+44 <= len(cmdBytes) {
					sectOff := uint64(bo.Uint32(cmdBytes[soff+40 : soff+44]))
					if sectOff > 0 && sectOff < minSectionFileOff {
						minSectionFileOff = sectOff
					}
				}
			}
		case uint32(macho.LoadCmdSegment64):
			pc.segName = cString(cmdBytes[8:24])
			pc.fileOff = bo.Uint64(cmdBytes[40:48])
			pc.fileSz = bo.Uint64(cmdBytes[48:56])
			nsects := bo.Uint32(cmdBytes[64:68])
			for s := uint32(0); s < nsects; s++ {
				soff := 72 + int(s)*80
				if soff+52 <= len(cmdBytes) {
					sectOff := bo.Uint64(cmdBytes[soff+48 : soff+56])
					if sectOff > 0 && sectOff < minSectionFileOff {
						minSectionFileOff = sectOff
					}
				}
			}
		case lcCodeSignature:
			hasCodeSig = true
			sigOff = uint64(bo.Uint32(cmdBytes[8:12]))
		}

		if pc.segName == "__TEXT" {
			textBase = pc.fileOff
			textLimit = pc.fileSz
		}
		if pc.segName == "__LINKEDIT" {
			linkeditIdx = len(cmds)
		}
		cmds = append(cmds, pc)
		off += int(sz)
	}
	if linkeditIdx < 0 {
		return nil, errors.New("signing: Mach-O missing __LINKEDIT segment")
	}

	linkedit := cmds[linkeditIdx]
	codeLimit := linkedit.fileOff + linkedit.fileSz
	if hasCodeSig && sigOff >= linkedit.fileOff && sigOff < codeLimit {
		codeLimit = sigOff
	}
	if codeLimit > uint64(len(raw)) {
		codeLimit = uint64(len(raw))
	}

	// Pad codeLimit to 16-byte boundary before embedding signature SuperBlob.
	sigStart := alignUp64(codeLimit, 16)

	// Prepare special slots
	specials := map[uint32][]byte{}
	if len(opts.InfoPlistRaw) > 0 {
		specials[csSlotInfo] = opts.InfoPlistRaw
	}
	if len(opts.CodeResourcesRaw) > 0 {
		specials[csSlotResourceDir] = opts.CodeResourcesRaw
	}
	if opts.IsMainExecutable && len(opts.EntitlementsXML) > 0 {
		specials[csSlotEntitlements] = wrapBlob(csMagicEntitlements, opts.EntitlementsXML)
		if der, err := encodeDEREntitlements(opts.Entitlements); err == nil {
			specials[csSlotEntitlementsDR] = wrapBlob(csMagicEntitlementsDR, der)
		}
	}
	reqBlob := buildDesignatedRequirement(opts.Identifier, opts.LeafCert)
	specials[csSlotRequirements] = reqBlob

	execFlags := uint64(0)
	if opts.IsMainExecutable {
		execFlags = entitlementsToExecSegFlags(opts.Entitlements, true)
	}

	var flags uint32
	if opts.Key == nil || opts.LeafCert == nil {
		flags = csFlagAdhoc
	}

	// Probe signature superblob size with dummy page hashes (no out allocation, no page reads).
	cdP := cdParams{
		ident:        opts.Identifier,
		teamID:       opts.TeamID,
		flags:        flags,
		codeLimit:    sigStart,
		execSegBase:  textBase,
		execSegLimit: textLimit,
		execSegFlags: execFlags,
		platform:     0,
		specialSlots: specials,
	}
	probeSHA1, probeSHA256 := buildCodeDirectories(cdP, false)
	probeSlots := make([]slotBlob, 0, 6)
	probeSlots = append(probeSlots, slotBlob{slot: csSlotCodeDirectory, data: probeSHA1})
	if b, ok := specials[csSlotRequirements]; ok {
		probeSlots = append(probeSlots, slotBlob{slot: csSlotRequirements, data: b})
	}
	if b, ok := specials[csSlotEntitlements]; ok {
		probeSlots = append(probeSlots, slotBlob{slot: csSlotEntitlements, data: b})
	}
	if b, ok := specials[csSlotEntitlementsDR]; ok {
		probeSlots = append(probeSlots, slotBlob{slot: csSlotEntitlementsDR, data: b})
	}
	probeSlots = append(probeSlots, slotBlob{slot: csSlotAltCD0, data: probeSHA256})

	var cmsDER []byte
	if opts.Key != nil && opts.LeafCert != nil {
		var cmsErr error
		cmsDER, cmsErr = buildCMSSignature(
			opts.Key,
			opts.LeafCert,
			opts.CertChain,
			probeSHA1,
			[][]byte{probeSHA1, probeSHA256},
			[]uint8{csHashSHA1, csHashSHA256},
		)
		if cmsErr != nil {
			return nil, cmsErr
		}
	}
	probeSlots = append(probeSlots, slotBlob{slot: csSlotSignature, data: wrapBlob(csMagicBlobWrapper, cmsDER)})
	sigDataLen := len(wrapSuperBlob(csMagicEmbeddedSig, probeSlots))

	newNcmd := mf.Ncmd
	newSizeOfCmds := mf.Cmdsz
	if !hasCodeSig {
		newNcmd++
		newSizeOfCmds += 16
		if uint64(hdrSize)+uint64(newSizeOfCmds) > minSectionFileOff {
			return nil, errors.New("signing: insufficient header padding for LC_CODE_SIGNATURE")
		}
	}

	newLinkeditFilesize := (sigStart - linkedit.fileOff) + uint64(sigDataLen)
	newLinkeditVmsize := alignUp64(newLinkeditFilesize, 16384)

	out := make([]byte, sigStart+uint64(sigDataLen))
	copy(out[:codeLimit], raw[:codeLimit])

	// Patch Mach-O header ncmds/sizeofcmds
	bo.PutUint32(out[16:20], newNcmd)
	bo.PutUint32(out[20:24], newSizeOfCmds)

	// Rewrite load commands
	cmdCursor := hdrSize
	for _, pc := range cmds {
		buf := append([]byte(nil), pc.raw...)
		switch pc.cmd {
		case uint32(macho.LoadCmdSegment):
			if pc.segName == "__LINKEDIT" {
				bo.PutUint32(buf[28:32], uint32(newLinkeditVmsize))
				bo.PutUint32(buf[36:40], uint32(newLinkeditFilesize))
			}
		case uint32(macho.LoadCmdSegment64):
			if pc.segName == "__LINKEDIT" {
				bo.PutUint64(buf[32:40], newLinkeditVmsize)
				bo.PutUint64(buf[48:56], newLinkeditFilesize)
			}
		case lcCodeSignature:
			bo.PutUint32(buf[8:12], uint32(sigStart))
			bo.PutUint32(buf[12:16], uint32(sigDataLen))
		}
		copy(out[cmdCursor:], buf)
		cmdCursor += int(pc.cmdSize)
	}
	if !hasCodeSig {
		var lc [16]byte
		bo.PutUint32(lc[0:4], lcCodeSignature)
		bo.PutUint32(lc[4:8], 16)
		bo.PutUint32(lc[8:12], uint32(sigStart))
		bo.PutUint32(lc[12:16], uint32(sigDataLen))
		copy(out[cmdCursor:], lc[:])
	}

	cdP.codeBytes = out[:sigStart]
	cdSHA1, cdSHA256 := buildCodeDirectories(cdP, true)

	slots := make([]slotBlob, 0, 6)
	slots = append(slots, slotBlob{slot: csSlotCodeDirectory, data: cdSHA1})
	if b, ok := specials[csSlotRequirements]; ok {
		slots = append(slots, slotBlob{slot: csSlotRequirements, data: b})
	}
	if b, ok := specials[csSlotEntitlements]; ok {
		slots = append(slots, slotBlob{slot: csSlotEntitlements, data: b})
	}
	if b, ok := specials[csSlotEntitlementsDR]; ok {
		slots = append(slots, slotBlob{slot: csSlotEntitlementsDR, data: b})
	}
	slots = append(slots, slotBlob{slot: csSlotAltCD0, data: cdSHA256})

	if opts.Key != nil && opts.LeafCert != nil {
		var cmsErr error
		cmsDER, cmsErr = buildCMSSignature(
			opts.Key,
			opts.LeafCert,
			opts.CertChain,
			cdSHA1,
			[][]byte{cdSHA1, cdSHA256},
			[]uint8{csHashSHA1, csHashSHA256},
		)
		if cmsErr != nil {
			return nil, cmsErr
		}
	}
	slots = append(slots, slotBlob{slot: csSlotSignature, data: wrapBlob(csMagicBlobWrapper, cmsDER)})

	superBlob := wrapSuperBlob(csMagicEmbeddedSig, slots)
	if len(superBlob) != sigDataLen {
		return nil, fmt.Errorf("signing: superblob length mismatch (%d != %d)", len(superBlob), sigDataLen)
	}
	copy(out[sigStart:], superBlob)
	return out, nil
}
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func alignUp(v, align int) int {
	rem := v % align
	if rem == 0 {
		return v
	}
	return v + align - rem
}

func alignUp64(v, align uint64) uint64 {
	rem := v % align
	if rem == 0 {
		return v
	}
	return v + align - rem
}
