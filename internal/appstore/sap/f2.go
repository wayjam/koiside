package sap

import (
	"encoding/binary"
	"errors"
)

// DeriveF2 computes the 16-byte F2 key block from the handshake outputs.
func DeriveF2(key, input []byte, tables *Tables) ([]byte, error) {
	if len(key) != 16 || len(input) != 16 {
		return nil, errors.New("sap: invalid SAP F2 inputs")
	}
	f2 := tables.F2
	var encoded [16]byte
	for i := range 16 {
		encoded[i] = f2[256*i+int(key[i])]
	}
	words := make([]uint32, 4, 4+len(tables.raw.Expansion))
	for i := range 4 {
		words[i] = binary.BigEndian.Uint32(encoded[4*i : 4*i+4])
	}
	for _, step := range tables.raw.Expansion {
		var word uint32
		for _, idx := range step.Selection {
			word ^= words[idx]
		}
		word = ((word << 8) | (word >> 24)) ^ step.Whitening
		var substituted uint32
		for pos := range 4 {
			shift := uint(24 - 8*pos)
			substituted |= uint32(f2[4096+256*pos+int((word>>shift)&0xff)]) << shift
		}
		words = append(words, substituted)
	}

	additions := make([][16]byte, len(tables.raw.KeySelections))
	for r, row := range tables.raw.KeySelections {
		for c, sel := range row {
			var word uint32
			for _, idx := range sel.Words {
				word ^= words[idx]
			}
			b := byte((word >> sel.Shift) & 0xff)
			if sel.Linear >= 0 {
				b = f2[17408+256*sel.Linear+int(b)]
			}
			additions[r][c] = b ^ sel.Whitening
		}
	}

	state := additions[0]
	for pos := range 16 {
		state[tables.raw.EntryPositions[pos]] ^= f2[5120+256*pos+int(input[pos])]
	}

	for round, row := range tables.raw.MainRouting {
		next := additions[round+1]
		for pos, routing := range row {
			off := 13312 + 4*(256*routing.Table+int(state[pos]))
			word := binary.LittleEndian.Uint32(f2[off : off+4])
			for i, dest := range routing.Destinations {
				next[dest] ^= byte((word >> uint(24-8*i)) & 0xff)
			}
		}
		state = next
	}

	out := additions[10]
	for pos := range 16 {
		out[tables.raw.FinalPositions[pos]] ^= f2[9216+256*pos+int(state[pos])]
	}
	res := make([]byte, 16)
	for i := range 16 {
		res[i] = out[i] ^ 0x2d
	}
	return res, nil
}
