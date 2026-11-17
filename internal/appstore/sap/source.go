package sap

import "errors"

var (
	initialOrder  = [16]int{13, 0, 11, 10, 6, 12, 15, 1, 5, 14, 2, 4, 3, 8, 9, 7}
	terminalOrder = [16]int{13, 4, 8, 9, 14, 1, 7, 15, 12, 2, 6, 0, 11, 3, 10, 5}
)

type preparedSource struct {
	material       [576]byte
	auxiliary0     [256]uint32
	auxiliary1     [256]uint32
	cache2         []byte
	cache3         []byte
	projectionMask uint32
	selectors      [16]int
	initialCache   [16]uint32
	terminalCache  [16]uint32
}

func linearTransform(value byte, basis [8]byte, constant byte) byte {
	for bit := range 8 {
		if value&(1<<bit) != 0 {
			constant ^= basis[bit]
		}
	}
	return constant
}

func prepareSource(source []byte, tables *Tables) (*preparedSource, error) {
	if len(source) != 576 {
		return nil, errors.New("sap: invalid SAP session source")
	}

	var lengths [16][11]int
	banks := [3]int{0xe0, 0xf0, 0xc0}
	moduliGroups := [3][4]int{
		{7, 27, 47, 77},
		{9, 29, 49, 79},
		{5, 25, 45, 75},
	}
	lenLUT := [4]int{3, 3, 5, 1}
	for column := range 11 {
		bank := banks[column/4]
		moduli := moduliGroups[column/4]
		for group := range 4 {
			at := 4*(column%4) + group
			val := int(source[0x30+at] ^ source[bank+at])
			for lane := range 4 {
				lengths[4*group+lane][column] = lenLUT[(val%moduli[lane])&3]
			}
		}
		cost := 0
		for row := range 16 {
			cost += lengths[row][column]
		}
		row := int(source[0x31]^source[0xc1]) & 15
		for cost > 32 {
			cost -= lengths[row][column] - 1
			lengths[row][column] = 1
			row = (row + 5) & 15
		}
	}

	var selectors [16]int
	for index := range 8 {
		val := int(source[0xe0+index] ^ source[0xf0+index])
		selectors[2*index] = val % 7
		selectors[2*index+1] = (val / 7) % 7
	}

	size := (int(source[0xfa]^source[0xca]) << 8) | int(source[0xf3]^source[0xc3])
	if size == 0 {
		return nil, errors.New("sap: invalid SAP inverse cache")
	}

	var seed uint32
	for _, pair := range [4][2]int{{0xea, 0xfa}, {0xe4, 0xf4}, {0xed, 0xfd}, {0xe6, 0xf6}} {
		seed = (seed << 8) | uint32(source[pair[0]]^source[pair[1]])
	}

	state := seed
	var states [13]uint32
	for i := range 13 {
		state = uint32((uint64(state)*uint64(state) + 1) % 0xfffffffb)
		states[i] = state
	}

	mask := uint32(1) << (seed & 7)
	for lane := 1; lane < 4; lane++ {
		mask |= uint32(1) << (8*lane + int(states[lane-1]&7))
	}
	basis := states[3:11]
	header := states[11]
	state = states[12]

	cache := make([]byte, size)
	for i := range size {
		idx := (i + 3*int(source[i%576]) + 2) % 576
		cache[i] = source[idx] ^ 0xd6
	}

	var words [256]uint32
	for index := range 256 {
		word := header ^ (state & mask)
		for bit := range 8 {
			if index&(1<<bit) != 0 {
				word ^= basis[bit]
			}
		}
		words[index] = word
		cache[int(word&^mask)%size] = byte(index) ^ 0xd6
		val := state ^ 0x63
		correction := 0
		if index != 0 && state&0x80000000 != 0 {
			correction = 512
		}
		position := (17*int(val>>4) + 3*int(val&15) + 176 + correction) % 576
		state = 0
		for b := range 4 {
			state |= uint32(source[(position+b)%576]) << (8 * b)
		}
	}

	ps := &preparedSource{
		projectionMask: ^mask,
		selectors:      selectors,
	}

	basis0 := [8]byte{0x3c, 0x44, 0x73, 0xcc, 0x50, 0xba, 0x9e, 0xee}
	basis1 := [8]byte{0x9f, 0x72, 0xe1, 0x3b, 0xdd, 0x31, 0x24, 0x8f}
	for index, word := range words {
		ps.auxiliary0[linearTransform(byte(index), basis0, 0)] = word ^ 0xd90b5d96
		ps.auxiliary1[linearTransform(byte(index), basis1, 0)] = word ^ 0xaa8095ee
	}

	ps.cache2 = make([]byte, size)
	ps.cache3 = make([]byte, size)
	basis2 := [8]byte{0xe3, 0x34, 0xda, 0x73, 0xb4, 0xa0, 0x4f, 0x2b}
	basis3 := [8]byte{0x1f, 0x35, 0x3b, 0xf7, 0xd9, 0xad, 0xd4, 0x93}
	for i, v := range cache {
		ps.cache2[i] = linearTransform(v, basis2, 0xc0)
		ps.cache3[i] = linearTransform(v, basis3, 0x47) ^ byte((i>>2)&0xff)
	}

	operand := func(row, position, length, base, column int) byte {
		var key byte
		for b := range length {
			key ^= source[base+position+b] ^
				tables.raw.PadColumns[column][(position+b)%16] ^
				tables.raw.PadRows[column][row]
		}
		return key
	}

	initBias := states[11] ^ 0xe62818fc
	pos := 0
	for row, slot := range initialOrder {
		length := lengths[row][10]
		if length != 1 {
			ps.initialCache[slot] = words[operand(row, pos, length, 0x1a0, 10)] ^ initBias
		}
		pos += length
	}

	termBias := uint32(0xaf615514)
	pos = 0
	for row, slot := range terminalOrder {
		length := lengths[row][0]
		if length != 1 {
			ps.terminalCache[slot] = words[operand(row, pos, length, 0x40, 0)] ^ termBias
		}
		pos += length
	}

	copyPairs := [14][2]int{
		{0x20, 0xf0}, {0x70, 0xe0}, {0x120, 0xd0}, {0x130, 0x220},
		{0x140, 0x110}, {0x150, 0x100}, {0x160, 0x80}, {0x170, 0x120},
		{0x180, 0x20}, {0x190, 0x90}, {0x1a0, 0x190}, {0x1b0, 0x230},
		{0x1e0, 0xc0}, {0x1f0, 0x30},
	}
	for _, cp := range copyPairs {
		copy(ps.material[cp[0]:cp[0]+16], source[cp[1]:cp[1]+16])
	}

	offsets := [16]int{2, 12, 6, 16, 0, 8, 22, 28, 4, 26, 18, 10, 20, 30, 24, 14}
	colSpecs := [9][3]int{
		{1, 0xa0, 0x200},
		{2, 0x200, 0x1c0},
		{3, 0x60, 0xc0},
		{4, 0, 0},
		{5, 0x1c0, 0x50},
		{6, 0x130, 0x80},
		{7, 0x1e0, 0xa0},
		{8, 0x170, 0x30},
		{9, 0x150, 0x100},
	}
	walk := 0
	for _, spec := range colSpecs {
		column, base, destination := spec[0], spec[1], spec[2]
		position := 0
		for row := range 16 {
			length := lengths[row][column]
			key := operand(row, position, length, base, column)
			walk = (walk + base + position) % 576
			first := source[walk]
			walk = (walk + base + position + 1) % 576
			first += source[walk]
			at := destination + offsets[row]
			ps.material[at] = first
			ps.material[at+1] = key - first
			position += length
		}
	}
	return ps, nil
}
