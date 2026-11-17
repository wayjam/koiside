package sap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"math/big"
)

type derNode struct {
	tag   byte
	start int
	end   int
}

func parseDER(data []byte, at, limit int) (derNode, error) {
	if at >= limit {
		return derNode{}, errors.New("sap: truncated SAP certificate")
	}
	tag := data[at]
	at++
	if at >= limit {
		return derNode{}, errors.New("sap: truncated SAP certificate")
	}
	length := int(data[at])
	at++
	if length&0x80 != 0 {
		count := length & 0x7f
		if count < 1 || count > 4 || at+count > limit {
			return derNode{}, errors.New("sap: invalid SAP certificate length")
		}
		length = 0
		for range count {
			length = length*256 + int(data[at])
			at++
		}
	}
	if at > limit || length < 0 || at+length > limit {
		return derNode{}, errors.New("sap: truncated SAP certificate")
	}
	return derNode{tag: tag, start: at, end: at + length}, nil
}

func derChildren(data []byte, node derNode) ([]derNode, error) {
	var result []derNode
	for at := node.start; at < node.end; {
		child, err := parseDER(data, at, node.end)
		if err != nil {
			return nil, err
		}
		result = append(result, child)
		at = child.end
	}
	return result, nil
}

func derInteger(data []byte, node derNode) ([]byte, error) {
	if node.tag != 2 || node.start == node.end || data[node.start]&0x80 != 0 {
		return nil, errors.New("sap: invalid SAP RSA integer")
	}
	start := node.start
	for start+1 < node.end && data[start] == 0 {
		start++
	}
	out := make([]byte, node.end-start)
	copy(out, data[start:node.end])
	return out, nil
}

// Certificate holds the RSA-2048 public key and wire serial extracted from an Apple SAP setup container.
type Certificate struct {
	Serial   []byte
	Modulus  []byte
	Exponent []byte
}

var rsaEncryptionOID = []byte{42, 134, 72, 134, 247, 13, 1, 1, 1}

// ReadCertificate extracts the RSA-2048 certificate from a setupCert.plist certificate blob.
func ReadCertificate(data []byte) (Certificate, error) {
	if len(data) < 512 || len(data) > 1048576 {
		return Certificate{}, errors.New("sap: invalid SAP certificate container")
	}
	var selected *Certificate
	selectedEnd := 0
	for at := 0; at < len(data)-4; at++ {
		if data[at] != 0x30 {
			continue
		}
		root, err := parseDER(data, at, len(data))
		if err != nil || root.end <= selectedEnd || root.end-at < 512 {
			continue
		}
		cert, err := derChildren(data, root)
		if err != nil || len(cert) != 3 || cert[0].tag != 0x30 || cert[1].tag != 0x30 || cert[2].tag != 3 {
			continue
		}
		fields, err := derChildren(data, cert[0])
		if err != nil || len(fields) < 7 {
			continue
		}
		version := 0
		if fields[0].tag == 0xa0 {
			version = 1
		}
		if version+5 >= len(fields) {
			continue
		}
		serial, err := derInteger(data, fields[version])
		if err != nil {
			continue
		}
		pubKey, err := derChildren(data, fields[version+5])
		if err != nil || len(pubKey) < 2 {
			continue
		}
		alg, err := derChildren(data, pubKey[0])
		if err != nil || len(alg) < 1 || alg[0].tag != 6 {
			continue
		}
		oid := data[alg[0].start:alg[0].end]
		if !bytesEqual(oid, rsaEncryptionOID) || pubKey[1].tag != 3 || data[pubKey[1].start] != 0 {
			continue
		}
		inner, err := parseDER(data, pubKey[1].start+1, pubKey[1].end)
		if err != nil {
			continue
		}
		key, err := derChildren(data, inner)
		if err != nil || len(key) != 2 {
			continue
		}
		modulus, err := derInteger(data, key[0])
		if err != nil {
			continue
		}
		exponent, err := derInteger(data, key[1])
		if err != nil {
			continue
		}
		expBig := new(big.Int).SetBytes(exponent)
		if len(serial) > 127 || len(modulus) != 256 || modulus[0] < 128 ||
			expBig.Cmp(big.NewInt(3)) < 0 || exponent[len(exponent)-1]&1 == 0 {
			continue
		}
		wireSerial := serial
		if serial[0]&0x80 != 0 {
			wireSerial = append([]byte{0}, serial...)
		}
		if len(wireSerial) > 127 {
			continue
		}
		selected = &Certificate{Serial: wireSerial, Modulus: modulus, Exponent: exponent}
		selectedEnd = root.end
	}
	if selected == nil {
		return Certificate{}, errors.New("sap: container has no RSA-2048 certificate")
	}
	return *selected, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RSAOAEP performs deterministic SHA-1 RSA-OAEP encryption with the caller-provided 20-byte seed.
func RSAOAEP(message, seed, modulus, exponent []byte) ([]byte, error) {
	if len(message) > 214 || len(seed) != 20 || len(modulus) != 256 {
		return nil, errors.New("sap: invalid SAP RSA inputs")
	}
	emptyHash := sha1.Sum(nil)
	database := make([]byte, 0, 235)
	database = append(database, emptyHash[:]...)
	database = append(database, make([]byte, 214-len(message))...)
	database = append(database, 1)
	database = append(database, message...)

	dbMask := mgf1SHA1(seed, 235)
	maskedDB := xorBytes(database, dbMask)
	seedMask := mgf1SHA1(maskedDB, 20)
	maskedSeed := xorBytes(seed, seedMask)

	encoded := make([]byte, 0, 256)
	encoded = append(encoded, 0)
	encoded = append(encoded, maskedSeed...)
	encoded = append(encoded, maskedDB...)

	n := new(big.Int).SetBytes(modulus)
	base := new(big.Int).SetBytes(encoded)
	power := new(big.Int).SetBytes(exponent)
	if base.Cmp(n) >= 0 || power.Cmp(big.NewInt(3)) < 0 || power.Bit(0) == 0 {
		return nil, errors.New("sap: invalid SAP RSA key")
	}
	res := new(big.Int).Exp(base, power, n)
	out := make([]byte, 256)
	resBytes := res.Bytes()
	copy(out[256-len(resBytes):], resBytes)
	return out, nil
}

func mgf1SHA1(seed []byte, length int) []byte {
	out := make([]byte, 0, length+20)
	var counter [4]byte
	buf := make([]byte, len(seed)+4)
	copy(buf, seed)
	for i := 0; len(out) < length; i++ {
		binary.BigEndian.PutUint32(counter[:], uint32(i))
		copy(buf[len(seed):], counter[:])
		sum := sha1.Sum(buf)
		out = append(out, sum[:]...)
	}
	return out[:length]
}

// AESCBCNoPad encrypts or decrypts whole 16-byte blocks with AES-128-CBC and no padding.
func AESCBCNoPad(data, key, iv []byte, encrypt bool) ([]byte, error) {
	if len(key) != 16 || len(iv) != 16 || len(data) == 0 || len(data)%16 != 0 || len(data) > 1048576 {
		return nil, errors.New("sap: invalid SAP AES blocks")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	if encrypt {
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	} else {
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	}
	return out, nil
}

// HMACSHA1 computes HMAC-SHA1 over message with key.
func HMACSHA1(key, message []byte) []byte {
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func xorBytes(left, right []byte) []byte {
	out := make([]byte, len(left))
	for i := range left {
		out[i] = left[i] ^ right[i]
	}
	return out
}
