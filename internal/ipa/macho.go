package ipa

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	mhMagic32      = 0xFEEDFACE
	mhMagic64      = 0xFEEDFACF
	fatMagic       = 0xCAFEBABE
	lcEncryption   = 0x21
	lcEncryption64 = 0x2C
	lcCodeSign     = 0x1D
)

func parseMachO(path string, prefix []byte) ([]MachO, error) {
	if len(prefix) < 8 {
		return nil, fmt.Errorf("short header")
	}
	switch binary.BigEndian.Uint32(prefix[:4]) {
	case fatMagic:
		return parseFat(path, prefix)
	default:
		slice, err := parseSlice(path, prefix)
		if err != nil {
			return nil, err
		}
		return []MachO{slice}, nil
	}
}

func parseFat(path string, prefix []byte) ([]MachO, error) {
	if len(prefix) < 8 {
		return nil, fmt.Errorf("short fat header")
	}
	n := binary.BigEndian.Uint32(prefix[4:8])
	if n == 0 || n > 8 || len(prefix) < int(8+n*20) {
		return nil, fmt.Errorf("incomplete fat header")
	}
	var out []MachO
	for i := uint32(0); i < n; i++ {
		at := 8 + int(i)*20
		cpu := binary.BigEndian.Uint32(prefix[at : at+4])
		off := binary.BigEndian.Uint32(prefix[at+8 : at+12])
		size := binary.BigEndian.Uint32(prefix[at+12 : at+16])
		end := int(off + size)
		if int(off) < 0 || end > len(prefix) || end < int(off) {
			return nil, fmt.Errorf("slice outside inspected prefix")
		}
		slice, err := parseSlice(path, prefix[off:end])
		if err != nil {
			return nil, err
		}
		slice.Arch = cpuName(cpu)
		out = append(out, slice)
	}
	return out, nil
}

func parseSlice(path string, data []byte) (MachO, error) {
	r := bytes.NewReader(data)
	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return MachO{}, err
	}
	var order binary.ByteOrder
	width := 32
	switch magic {
	case mhMagic64:
		order, width = binary.LittleEndian, 64
	case mhMagic32:
		order = binary.LittleEndian
	case swap32(mhMagic64):
		order, width = binary.BigEndian, 64
	case swap32(mhMagic32):
		order = binary.BigEndian
	default:
		return MachO{}, fmt.Errorf("not mach-o")
	}
	var header struct {
		CPU   uint32
		Sub   uint32
		Type  uint32
		NCmd  uint32
		Size  uint32
		Flags uint32
	}
	if err := binary.Read(r, order, &header); err != nil {
		return MachO{}, err
	}
	if width == 64 {
		if _, err := r.Seek(4, io.SeekCurrent); err != nil {
			return MachO{}, err
		}
	}
	out := MachO{Path: path, Arch: cpuName(header.CPU)}
	for i := uint32(0); i < header.NCmd && i < 256; i++ {
		var cmd, size uint32
		if err := binary.Read(r, order, &cmd); err != nil {
			return MachO{}, err
		}
		if err := binary.Read(r, order, &size); err != nil {
			return MachO{}, err
		}
		if size < 8 || int64(size) > int64(r.Len())+8 {
			return MachO{}, fmt.Errorf("command outside prefix")
		}
		body := make([]byte, size-8)
		if _, err := io.ReadFull(r, body); err != nil {
			return MachO{}, err
		}
		switch cmd {
		case lcEncryption, lcEncryption64, lcEncryption | 0x80000000, lcEncryption64 | 0x80000000:
			if len(body) < 16 {
				return MachO{}, fmt.Errorf("short encryption command")
			}
			id := int(order.Uint32(body[12:16]))
			out.CryptID = &id
			out.Encrypted = id != 0
		case lcCodeSign, lcCodeSign | 0x80000000:
			out.Signed = true
		}
	}
	return out, nil
}

func swap32(v uint32) uint32 { return v<<24 | v>>24 | v<<8&0x00FF0000 | v>>8&0x0000FF00 }

func cpuName(cpu uint32) string {
	switch cpu {
	case uint32(macho.CpuArm64):
		return "arm64"
	case uint32(macho.CpuArm):
		return "arm"
	case uint32(macho.CpuAmd64):
		return "amd64"
	default:
		return fmt.Sprintf("cpu-%d", cpu)
	}
}
