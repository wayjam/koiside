package sap

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
)

// Session holds the completed SAP key exchange state needed to construct a Signer.
type Session struct {
	Source    []byte
	F2Input1  []byte
	F2Input2  []byte
	F2Tail    []byte
	F3        []byte
	Random    *Random
	Seed30    uint32
	Seed54    uint32
	F1Address uint32
	IVAddress uint32
}

// Handshake represents an in-progress SAP setup exchange with Apple.
type Handshake struct {
	Request      []byte
	responseKey  []byte
	responseEcho []byte
	material     []byte
	random       *Random
	seed30       uint32
	seed54       uint32
}

// CreateHandshake builds a SAP setup request for the RSA-2048 certificate container.
// Pass nil for entropy/seconds/microseconds in production to use crypto/rand and current wall time.
func CreateHandshake(certificate []byte, entropy *[3]uint32, seconds, microseconds *uint32) (*Handshake, error) {
	tables, err := LoadTables()
	if err != nil {
		return nil, err
	}
	pubKey, err := ReadCertificate(certificate)
	if err != nil {
		return nil, err
	}

	var ent [3]uint32
	if entropy != nil {
		ent = *entropy
	} else {
		var buf [12]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, err
		}
		ent[0] = binary.LittleEndian.Uint32(buf[0:4])
		ent[1] = binary.LittleEndian.Uint32(buf[4:8])
		ent[2] = binary.LittleEndian.Uint32(buf[8:12])
	}

	now := time.Now()
	var sec, usec uint32
	if seconds != nil {
		sec = *seconds
	} else {
		sec = uint32(now.Unix())
	}
	if microseconds != nil {
		usec = *microseconds
	} else {
		usec = uint32(now.Nanosecond() / 1000)
	}

	rnd := &Random{}
	pool, err := rnd.Initialize(ent, sec, usec, tables)
	if err != nil {
		return nil, err
	}
	seed30 := pool[12]
	seed54 := pool[21]

	generate := func(count int, address uint32, exchange bool) []byte {
		if exchange {
			return rnd.Fill(pool[15], address, &tables.raw.ExchangeWhiten, 0x4b, count)
		}
		return rnd.Fill(seed54, address, &tables.raw.IVWhiten, 0x12, count)
	}

	initial := generate(33, 0x7ffac0, false)
	matLen := 16 + int(initial[32]%17)
	material := make([]byte, matLen)
	for i := range matLen {
		material[i] = initial[i] ^ 0x2d
	}
	responseKey := generate(16, 0x7ffc14, true)
	responseEcho := generate(16, 0x7ffc14, true)
	encKey := generate(16, 0x7ffc14, true)
	iv := generate(16, 0x7ffc14, true)
	authKey := generate(20, 0x7ffc24, true)

	padding := make([]byte, 11)
	for i := range 11 {
		v := uint32(0x7ff812 - i)
		padding[i] = byte(((v ^ 0xba) * (v + 0x11)) ^ 0x2d)
	}

	plaintext := make([]byte, 0, 1+4+16+16+11)
	plaintext = append(plaintext, 2)
	plaintext = binary.BigEndian.AppendUint32(plaintext, 1)
	plaintext = append(plaintext, responseKey...)
	plaintext = append(plaintext, responseEcho...)
	plaintext = append(plaintext, padding...)

	keyMessage := make([]byte, 0, len(encKey)+len(authKey))
	keyMessage = append(keyMessage, encKey...)
	keyMessage = append(keyMessage, authKey...)

	keyBlock, err := RSAOAEP(keyMessage, generate(20, 0x7ff4e4, false), pubKey.Modulus, pubKey.Exponent)
	if err != nil {
		return nil, err
	}
	encrypted, err := AESCBCNoPad(plaintext, encKey, iv, true)
	if err != nil {
		return nil, err
	}
	mac := HMACSHA1(authKey, encrypted)

	req := make([]byte, 0, 2+len(pubKey.Serial)+len(keyBlock)+len(iv)+4+len(encrypted)+len(mac))
	req = append(req, 1, byte(len(pubKey.Serial)))
	req = append(req, pubKey.Serial...)
	req = append(req, keyBlock...)
	req = append(req, iv...)
	req = binary.BigEndian.AppendUint32(req, uint32(len(encrypted)))
	req = append(req, encrypted...)
	req = append(req, mac...)

	return &Handshake{
		Request:      req,
		responseKey:  responseKey,
		responseEcho: responseEcho,
		material:     material,
		random:       rnd,
		seed30:       seed30,
		seed54:       seed54,
	}, nil
}

// Complete verifies and decrypts Apple's SAP setup reply into a Session.
func (h *Handshake) Complete(reply []byte) (*Session, error) {
	if len(reply) < 21 || len(reply) > 1048576 || reply[0] != 2 {
		return nil, errors.New("sap: invalid SAP setup response")
	}
	length := int(binary.BigEndian.Uint32(reply[17:21]))
	if length == 0 || length%16 != 0 || length > len(reply)-21-25 {
		return nil, errors.New("sap: invalid SAP setup ciphertext length")
	}
	recordOffset := 21 + length
	if recordOffset+25 > len(reply) {
		return nil, errors.New("sap: invalid SAP signature record")
	}
	recordLength := uint64(binary.BigEndian.Uint32(reply[recordOffset+21:recordOffset+25])) + 25
	if recordLength > 16*1024*1024 || recordLength > uint64(len(reply)-recordOffset) {
		return nil, errors.New("sap: invalid SAP signature record")
	}

	plaintext, err := AESCBCNoPad(reply[21:recordOffset], h.responseKey, reply[1:17], false)
	if err != nil {
		return nil, err
	}

	expected := [6]int{16, 16, 16, 576, 576, 16}
	var fields [6][]byte
	offset := 0
	for i, want := range expected {
		if offset+4 > len(plaintext) {
			return nil, errors.New("sap: truncated SAP decrypted record")
		}
		count := int(binary.BigEndian.Uint32(plaintext[offset : offset+4]))
		offset += 4
		if count != want || count > len(plaintext)-offset {
			return nil, errors.New("sap: invalid decrypted SAP field")
		}
		fields[i] = plaintext[offset : offset+count]
		offset += count
	}

	if subtle.ConstantTimeCompare(fields[5], h.responseEcho) != 1 {
		return nil, errors.New("sap: reply belongs to another exchange")
	}

	f2Input1 := make([]byte, 16)
	for i := range 16 {
		f2Input1[i] = fields[2][i] + 0x2d
	}
	f2Input2 := make([]byte, 16)
	copy(f2Input2, h.material[:16])
	f2Tail := make([]byte, len(h.material)-16)
	for i, b := range h.material[16:] {
		f2Tail[i] = b ^ 0x2d
	}
	f3 := make([]byte, int(recordLength))
	copy(f3, reply[recordOffset:recordOffset+int(recordLength)])
	source := make([]byte, 576)
	copy(source, fields[4])

	f1Addr := uint32(0x604)
	if len(h.material) > 28 {
		f1Addr += 16
	}

	return &Session{
		Source:    source,
		F2Input1:  f2Input1,
		F2Input2:  f2Input2,
		F2Tail:    f2Tail,
		F3:        f3,
		Random:    h.random,
		Seed30:    h.seed30,
		Seed54:    h.seed54,
		F1Address: f1Addr,
		IVAddress: 0x7fed90,
	}, nil
}
