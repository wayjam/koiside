package sap

import "errors"

// CreateCipher builds the 16-byte block transform used to tag SAP request hashes.
func CreateCipher(input []byte, tables *Tables) (func(block []byte) ([]byte, error), error) {
	source, err := prepareSource(input, tables)
	if err != nil {
		return nil, err
	}
	m := &source.material
	pairWord := func(at, mask int) uint32 {
		var word uint32
		for b := range 4 {
			word |= uint32(m[at+b]^m[0x120+((mask+b)%16)]) << (8 * b)
		}
		return word
	}

	initial := source.initialCache
	terminal := source.terminalCache
	for row, slot := range initialOrder {
		if initial[slot] == 0 {
			initial[slot] = pairWord(0x180+4*row, 4*(row%4)) ^ 0xe62818fc
		}
	}
	for row, slot := range terminalOrder {
		if terminal[slot] == 0 {
			offset := 8
			if row < 5 {
				offset = 0
			} else if row < 13 {
				offset = 4
			}
			terminal[slot] = pairWord(0x130+4*row+offset, 4*row+offset) ^ 0xaf615514
		}
	}

	var initialField [16]byte
	for i := range 16 {
		left := (3*i + 7) % 16
		right := (11*i + 2) % 16
		a := m[0x1e0+left] ^ m[0x70+left]
		b := m[0x20+right] ^ m[0x70+right]
		initialField[i] = (a - b) ^ 0x2d
	}

	seeds := [7]byte{
		m[0x1f2] ^ m[0x72],
		m[0x1f7] ^ m[0x1e7],
		0x24,
		m[0x1eb] ^ m[0x2b],
		m[0x75] ^ m[0x1f5],
		0x11,
		m[0x23] ^ m[0x73],
	}

	var rawWords [9][4]uint32
	for row := range 9 {
		var physical [4]uint32
		for col := range 4 {
			idx := 4*row + 36*col
			physical[col] = pairWord(0x130+idx, idx) + 0x2186d6ff
		}
		rawWords[8-row] = [4]uint32{physical[1], physical[3], physical[0], physical[2]}
	}

	pairs := [16][2]int{
		{0, 1}, {8, 9}, {22, 23}, {28, 29},
		{20, 21}, {30, 31}, {24, 25}, {14, 15},
		{2, 3}, {12, 13}, {6, 7}, {16, 17},
		{4, 5}, {26, 27}, {18, 19}, {10, 11},
	}
	roundOffsets := [9]int{0x100, 0x30, 0xa0, 0x80, 0x50, 0, 0xc0, 0x1c0, 0x200}
	var roundKeys [9][16]byte
	for r, offset := range roundOffsets {
		for lane, p := range pairs {
			roundKeys[r][lane] = m[offset+p[0]] + m[offset+p[1]]
		}
	}

	var terminalWords [16][256]uint32
	for slot := range 16 {
		mask := (m[0x1f0+slot] ^ m[0x70+slot]) + (m[0x20+slot] ^ m[0x70+slot])
		tb := &tables.Bytes[40+((79*slot)%144)]
		for i := range 256 {
			terminalWords[slot][i] = source.auxiliary0[tb[i]^mask]
		}
	}

	byteCaches := make([][]byte, 16)
	for slot := range 16 {
		idx := (13 * slot) % 16
		mask := ((m[0x1e0+idx] ^ m[0x70+idx]) - (m[0x20+idx] ^ m[0x70+idx])) ^ 0xfe
		bc := make([]byte, len(source.cache2))
		tb := &tables.Bytes[184+((9*slot)%16)]
		for i, v := range source.cache2 {
			bc[i] = tb[v^mask]
		}
		byteCaches[slot] = bc
	}

	var initialTables [16][256]byte
	for slot := range 16 {
		bc := byteCaches[(5*slot)%16]
		initVal := initial[initialOrder[slot]]
		for b := range 256 {
			word := source.auxiliary1[b^0x2d] ^ initVal
			idx := int((word^0x4ca88d12)&source.projectionMask) % len(source.cache2)
			initialTables[slot][b] = bc[idx]
		}
	}

	fieldWords := [4]uint32{
		rawWords[3][2] + 0xde792901,
		rawWords[3][0] + 0xde792901,
		rawWords[3][3] + 0xde792901,
		rawWords[3][1] + 0xde792901,
	}
	fieldMods := [4]uint32{233, 239, 241, 251}
	fieldMasks := [4]byte{0xf6, 0x19, 0x50, 0x8e}
	var updatedField [16]byte
	for i := range 16 {
		mIdx := i % 4
		updatedField[i] = initialField[i] ^ tables.Masks[mIdx][fieldWords[i/4]%fieldMods[mIdx]] ^ fieldMasks[mIdx]
	}

	carryFrames := [3][4]byte{
		{initialField[0], initialField[2], initialField[11], initialField[12]},
		{updatedField[6], updatedField[1], updatedField[3], updatedField[14]},
		{updatedField[8], updatedField[9], updatedField[13], updatedField[15]},
	}

	terminalCache := make([]byte, len(source.cache3))
	for i, v := range source.cache3 {
		terminalCache[i] = v ^ byte((i>>2)&0xff) ^ 0xfa
	}

	terminalDestinations := [16]int{13, 5, 10, 2, 14, 1, 11, 8, 6, 9, 0, 15, 4, 7, 3, 12}
	coefficientOrder := [16]int{3, 1, 6, 8, 10, 4, 0, 12, 7, 2, 13, 5, 14, 15, 9, 11}
	var laneKeys [16]uint32
	for lane, dest := range terminalDestinations {
		laneKeys[lane] = terminal[coefficientOrder[lane]] ^ source.auxiliary0[updatedField[dest]^0x2d] ^ 0xaf615514
	}

	keyOrder := [16]int{12, 0, 1, 8, 5, 7, 9, 4, 2, 14, 11, 13, 3, 10, 15, 6}
	posOrder := [16]int{4, 0, 15, 8, 11, 9, 7, 12, 14, 2, 5, 3, 13, 6, 1, 10}
	roundBase := [16]int{2, 4, 8, 3, 7, 2, 6, 1, 5, 0, 4, 8, 3, 7, 2, 6}
	var nonlinear [8][16]*[256]byte
	for stage := range 8 {
		for lane, position := range posOrder {
			round := (roundBase[position] + 2*stage) % 9
			nonlinear[stage][keyOrder[lane]] = &tables.Bytes[40+16*round+position]
		}
	}

	initDests := [16]int{4, 5, 1, 13, 15, 0, 9, 8, 16, -1, 12, 10, 11, 3, 2, 14}
	carryXor := [3]byte{0x20, 0x26, 0x28}
	prevIdx := [9]int{8, 0, 0, 1, 1, 1, 4, 2, 2}
	indexSources := [16]int{15, 5, 2, 10, 11, 7, 9, 13, 4, 3, 12, 8, 16, 0, 1, 14}
	firstTables := [16]int{28, 39, 50, 61, 28, 39, 50, 61, 56, 67, 6, 17, 56, 67, 6, 17}
	columns := [17]int{1, 3, 1, 2, 3, 3, 2, 3, -1, 0, 2, 0, 0, 2, 1, 0, 1}
	shifts := [17]uint{24, 0, 8, 0, 8, 24, 24, 16, 0, 8, 8, 16, 0, 16, 0, 24, 16}
	masks := [17]byte{0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0, 0xa0, 0x2d, 0x75, 0x32, 0, 0x2d, 0xbb, 0x2d}
	termPositions := [16]int{4, 10, -1, 7, 11, 2, 0, 1, 16, 9, 3, 6, 12, 5, 15, 14}
	nextDests := [14]int{0, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nextOrder := [14]int{9, 6, 1, 0, 5, 3, 14, 7, 12, 2, 15, 11, 4, 8}
	nextInputs := [14]int{9, 16, 2, 3, 10, 15, 11, 5, 14, 7, 6, 0, 12, 1}

	return func(block []byte) ([]byte, error) {
		if len(block) != 16 {
			return nil, errors.New("sap: cipher requires a 16-byte block")
		}
		var masked [16]byte
		for i := range 16 {
			masked[i] = block[i] ^ 0x2d
		}
		var state [17]byte
		for i, dest := range initDests {
			if dest >= 0 {
				state[dest] = initialTables[i][masked[i]]
			}
		}
		state[6] = state[4] ^ state[14] ^ state[15]
		state[7] = state[6] ^ initialTables[9][masked[9]]

		var carries [3]byte
		for i, frame := range carryFrames {
			off := 4 * i
			val := (int(frame[0]^0x2d) + int(masked[off]^carryXor[i]) - int(frame[1]^0x2d)) & 255
			val ^= int(masked[off+1] ^ 0x2d)
			val = (val + int(frame[2]^0x2d) - int(masked[off+2]^0x2d)) & 255
			carries[i] = byte(((val ^ int(frame[3]^0x2d)) + int(masked[off+3]^0x2d)) & 255)
		}

		var expanded [17]byte
		for i := range 17 {
			expanded[i] = ((masked[(3+7*i)%16] ^ 0x2d) + byte(i)) ^ 0x2d
		}

		var slices [9][17]byte
		slices[0] = expanded
		slices[8] = expanded

		for stage := range 9 {
			carryIdx := 2
			if stage < 4 {
				carryIdx = 0
			} else if stage < 8 {
				carryIdx = 1
			}
			carry := carries[carryIdx]
			previous := &slices[prevIdx[stage]]
			key := &roundKeys[stage]
			accumulators := [4]uint32{
				rawWords[stage][0] + 0xde792901,
				rawWords[stage][1] + 0xde792901,
				rawWords[stage][2] + 0xde792901,
				rawWords[stage][3] + 0xde792901,
			}
			accumulators[0] ^= 0x96588d1f
			for lane := range 16 {
				idx := state[indexSources[lane]] ^ key[lane]
				if lane == 5 {
					idx ^= state[6]
				}
				accumulators[lane/4] ^= tables.Words[(firstTables[lane]-16*stage+144)%72][idx]
			}
			var mixed [17]byte
			for pos := range 17 {
				if pos != 8 {
					mixed[pos] = byte(accumulators[columns[pos]]>>shifts[pos]) ^ masks[pos]
				}
			}
			mixed[8] = previous[16] ^ previous[8] ^ byte(accumulators[0]>>16) ^ 0x75 ^ state[9] ^ key[6] ^ carry
			mixed[13] ^= mixed[8]

			if stage == 8 {
				coupled := mixed[8] ^ mixed[13]
				left := ((int(mixed[12]^0x31) + 0x6a) ^ 0x2d) - 0x80
				middle := (int(mixed[14]^0xd2) + 0x4c + left) & 255
				middle = (((middle ^ int(mixed[13])) + 1) ^ 0x7e) & 255
				mixing := byte((middle + int(mixed[15]^0x2d)) & 255)

				result := make([]byte, 16)
				for i, sel := range source.selectors {
					result[i] = seeds[sel]
				}
				for lane, pos := range termPositions {
					idx := coupled
					if pos >= 0 {
						idx = mixed[pos] ^ 0x2d
					}
					dest := terminalDestinations[lane]
					word := terminalWords[dest][idx]
					if pos < 0 {
						word ^= source.auxiliary0[coupled^mixing] ^
							source.auxiliary0[mixing] ^
							source.auxiliary0[coupled] ^
							source.auxiliary0[0]
					}
					word ^= laneKeys[lane]
					result[dest] ^= terminalCache[int(word&source.projectionMask)%len(terminalCache)]
				}
				for i := range result {
					result[i] ^= 0x2d
				}
				return result, nil
			}

			slices[stage] = mixed
			state = [17]byte{}
			for lane, dest := range nextDests {
				state[dest] = nonlinear[stage][nextOrder[lane]][mixed[nextInputs[lane]]^0x2d]
			}
			state[1] = nonlinear[stage][10][mixed[8]^mixed[13]]
			state[6] = carry ^ state[3] ^ state[4] ^ state[5]
			state[7] = state[6] ^ nonlinear[stage][13][mixed[4]^0x2d]
		}
		return nil, errors.New("sap: invalid cipher stage")
	}, nil
}
