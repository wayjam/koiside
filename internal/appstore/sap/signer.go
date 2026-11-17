package sap

import (
	"crypto/sha1"
	"encoding/binary"
	"sync"
)

// Signer produces X-Apple-ActionSignature payloads for Store requests.
type Signer interface {
	Sign(body []byte) ([]byte, error)
}

type sessionSigner struct {
	mu       sync.Mutex
	session  *Session
	tables   *Tables
	platform uint32
	encrypt  func([]byte) ([]byte, error)
	f2       []byte
	blob     []byte
}

// CreateSigner builds a thread-safe SAP Signer from a completed SAP Session.
func CreateSigner(session *Session, platform uint32) (Signer, error) {
	tables, err := LoadTables()
	if err != nil {
		return nil, err
	}
	encrypt, err := CreateCipher(session.Source, tables)
	if err != nil {
		return nil, err
	}
	f2Head, err := DeriveF2(session.F2Input1, session.F2Input2, tables)
	if err != nil {
		return nil, err
	}
	f2 := make([]byte, 0, len(f2Head)+len(session.F2Tail))
	f2 = append(f2, f2Head...)
	f2 = append(f2, session.F2Tail...)

	return &sessionSigner{
		session:  session,
		tables:   tables,
		platform: platform,
		encrypt:  encrypt,
		f2:       f2,
	}, nil
}

func (s *sessionSigner) Sign(body []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.blob == nil {
		f1 := s.session.Random.F1(s.session.Seed30, s.session.F1Address, s.tables)
		b := make([]byte, 0, 1+4+4+256+4+len(s.f2)+4+len(s.session.F3)+16)
		b = append(b, 3)
		b = binary.BigEndian.AppendUint32(b, s.platform)
		b = binary.BigEndian.AppendUint32(b, 256)
		b = append(b, f1...)
		b = binary.BigEndian.AppendUint32(b, uint32(len(s.f2)))
		b = append(b, s.f2...)
		b = binary.BigEndian.AppendUint32(b, uint32(len(s.session.F3)))
		b = append(b, s.session.F3...)
		pad := (16 - (len(b) % 16)) % 16
		if pad > 0 {
			b = append(b, make([]byte, pad)...)
		}
		s.blob = b
	}

	iv := s.session.Random.Fill(s.session.Seed54, s.session.IVAddress, &s.tables.raw.IVWhiten, 0x12, 16)

	h := sha1.New()
	_, _ = h.Write(s.blob)
	_, _ = h.Write(body)
	hash := h.Sum(nil)

	first, err := s.encrypt(xorBytes(iv, hash[:16]))
	if err != nil {
		return nil, err
	}
	var tail [16]byte
	copy(tail[:4], hash[16:20])
	tag, err := s.encrypt(xorBytes(first, tail[:]))
	if err != nil {
		return nil, err
	}

	sig := make([]byte, 0, 1+16+16+4+len(s.blob))
	sig = append(sig, 2)
	sig = append(sig, iv...)
	sig = append(sig, tag...)
	sig = binary.BigEndian.AppendUint32(sig, uint32(len(s.blob)))
	sig = append(sig, s.blob...)
	return sig, nil
}
