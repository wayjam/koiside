package sap

import "errors"

// Random is a deterministic port of ApplePackage's rng_f1.c PRNG used during SAP setup and signing.
type Random struct {
	Words  [624]uint32
	Cursor int
}

// Word twists and returns the next tempered 32-bit word.
func (r *Random) Word() uint32 {
	for index := range 624 {
		value := (r.Words[index] & 0x80000000) | (r.Words[(index+1)%624] & 0x7fffffff)
		var twist uint32
		if value&1 != 0 {
			twist = 0x9908b0df
		}
		r.Words[index] = r.Words[(index+397)%624] ^ (value >> 1) ^ twist
	}
	if r.Cursor >= 624 {
		r.Cursor = 0
	}
	value := r.Words[r.Cursor]
	r.Cursor++
	value ^= value >> 11
	value ^= (value << 7) & 0x9d2c5680
	value ^= (value << 15) & 0xefc60000
	return value ^ (value >> 18)
}

// Fill produces count non-zero whitened bytes using the PRNG stream.
func (r *Random) Fill(seed, address uint32, table *[256]byte, mask byte, count int) []byte {
	output := make([]byte, count)
	remaining := count
	for remaining > 0 {
		word := r.Word()
		for shift := uint(0); shift < 32 && remaining > 0; shift += 8 {
			hash := (seed ^ (address + uint32(remaining) - 1)) & 0x7fffffff
			hash *= 0x84edb2eb
			hash ^= hash >> 16
			hash *= 0x84edb2eb
			val := byte(((word >> shift) ^ hash ^ uint32(table[hash>>24]) ^ uint32(mask)) & 0xff)
			output[remaining-1] = val
			if val != 0 {
				remaining--
			}
		}
	}
	return output
}

// Initialize seeds the PRNG from entropy and timestamp and returns the 128-word state pool.
func (r *Random) Initialize(entropy [3]uint32, seconds, microseconds uint32, tables *Tables) ([]uint32, error) {
	if microseconds >= 1000000 {
		return nil, errors.New("sap: invalid SAP microseconds")
	}
	keys := [4]uint32{entropy[2], microseconds, seconds, entropy[1]}
	r.Words[0] = entropy[0]
	for index := 1; index < 624; index++ {
		prev := r.Words[index-1]
		r.Words[index] = 1812433253*(prev^(prev>>30)) + uint32(index)
	}
	index := 1
	key := 0
	for range 624 {
		prev := r.Words[index-1]
		r.Words[index] = (r.Words[index] ^ ((prev ^ (prev >> 30)) * 1664525)) + keys[key] + uint32(key)
		index++
		if index == 624 {
			r.Words[0] = r.Words[623]
			index = 1
		}
		key++
		if key == 4 {
			keys[0] ^= 0x200
			key = 0
		} else {
			keys[key] ^= 0x201
		}
	}
	for range 623 {
		prev := r.Words[index-1]
		r.Words[index] = (r.Words[index] ^ ((prev ^ (prev >> 30)) * 1566083941)) - uint32(index)
		index++
		if index == 624 {
			r.Words[0] = r.Words[623]
			index = 1
		}
	}
	r.Words[0] = 0x80000000
	r.Cursor = 0
	pool := make([]uint32, 128)
	for i := range 128 {
		pool[i] = r.Word()
	}
	for step := 0; step < 64; step += 4 {
		pool[step] |= (^pool[pool[step]&62]) << 16
	}
	r.Fill(pool[12], 0x7ff9b0, &tables.raw.InitializeWhiten, 0x35, 1024)
	return pool, nil
}

// F1 derives the 256-byte F1 block for the SAP signature blob.
func (r *Random) F1(seed, address uint32, tables *Tables) []byte {
	m1 := r.Fill(seed, address, &tables.raw.F1Whiten, 0x27, 60)
	m2 := r.Fill(seed, address+0xaa, &tables.raw.F1Whiten, 0x27, 18)

	var pre [256]byte
	copy(pre[:], tables.raw.F1Template[:])
	copy(pre[68:128], m1)
	copy(pre[238:256], m2)

	output := make([]byte, 256)
	for half := range 2 {
		low := make([]byte, 64)
		high := make([]byte, 64)
		copy(low, pre[half*128:half*128+64])
		copy(high, pre[half*128+64:half*128+128])
		for range 7 {
			var state [80]byte
			copy(state[:64], high)
			copy(state[64:], tables.raw.F1RC[:])
			for i := range 80 {
				state[i] = (state[i] ^ 0x2d) + byte(i)
			}
			for i := range 80 {
				state[i] = tables.raw.F1G[0][state[i]] + 0x25 + byte(i)
			}
			for _, constant := range [4]byte{0x5d, 0xae, 0xff, 0x50} {
				for i := range 80 {
					state[i] ^= constant + byte(i) +
						tables.raw.F1G[1][state[(i+75)%80]] +
						tables.raw.F1G[2][state[(i+55)%80]]
				}
			}
			for i := range 80 {
				state[i] = tables.raw.F1G[3][state[i]] + 0xc4 + byte(i)
			}
			next := make([]byte, 64)
			for i := range 64 {
				next[i] = low[i] ^ state[i]
			}
			low = high
			high = next
		}
		for i := range 64 {
			output[half*128+i] = low[i] ^ 0x2d
			output[half*128+64+i] = high[i] ^ 0x2d
		}
	}
	return output
}
