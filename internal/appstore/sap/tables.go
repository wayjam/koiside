package sap

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

//go:embed tables.json
var tablesJSON []byte

type encodedPool struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Base64 string `json:"base64"`
}

type expansionStep struct {
	Selection []int  `json:"selection"`
	Whitening uint32 `json:"whitening"`
}

type keySelection struct {
	Words     []int `json:"words"`
	Shift     uint  `json:"shift"`
	Linear    int   `json:"linear"`
	Whitening byte  `json:"whitening"`
}

type routingEntry struct {
	Table        int   `json:"table"`
	Destinations []int `json:"destinations"`
}

type rawTablesJSON struct {
	ExchangeWhiten   [256]byte        `json:"EXCHANGE_WHITEN"`
	InitializeWhiten [256]byte        `json:"INITIALIZE_WHITEN"`
	IVWhiten         [256]byte        `json:"IV_WHITEN"`
	F1Whiten         [256]byte        `json:"F1_WHITEN"`
	F1RC             [16]byte         `json:"F1_RC"`
	F1Template       [256]byte        `json:"F1_TEMPLATE"`
	F1G              [4][256]byte     `json:"F1_G"`
	PadColumns       [11][16]byte     `json:"padColumns"`
	PadRows          [11][16]byte     `json:"padRows"`
	EntryPositions   [16]int          `json:"entryPositions"`
	FinalPositions   [16]int          `json:"finalPositions"`
	Expansion        []expansionStep  `json:"expansion"`
	KeySelections    [][]keySelection `json:"keySelections"`
	MainRouting      [][]routingEntry `json:"mainRouting"`
	ByteTables       encodedPool      `json:"byte-tables"`
	WordTables       encodedPool      `json:"word-tables"`
	CarryMasks       encodedPool      `json:"carry-masks"`
	F2Tables         encodedPool      `json:"f2-tables"`
}

// Tables holds the validated, decoded SAP cryptographic lookup tables.
type Tables struct {
	raw   rawTablesJSON
	Bytes [200][256]byte
	Words [72][256]uint32
	Masks [4][]byte
	F2    []byte
}

var (
	tablesOnce sync.Once
	tablesInst *Tables
	tablesErr  error
)

// LoadTables decodes and verifies the embedded SAP lookup tables.
func LoadTables() (*Tables, error) {
	tablesOnce.Do(func() {
		var raw rawTablesJSON
		if err := json.Unmarshal(tablesJSON, &raw); err != nil {
			tablesErr = fmt.Errorf("sap: parse tables.json: %w", err)
			return
		}
		bytePool, err := decodePool(raw.ByteTables)
		if err != nil {
			tablesErr = err
			return
		}
		wordPool, err := decodePool(raw.WordTables)
		if err != nil {
			tablesErr = err
			return
		}
		maskPool, err := decodePool(raw.CarryMasks)
		if err != nil {
			tablesErr = err
			return
		}
		f2Pool, err := decodePool(raw.F2Tables)
		if err != nil {
			tablesErr = err
			return
		}

		t := &Tables{raw: raw, F2: f2Pool}
		if len(bytePool) != 200*256 {
			tablesErr = errors.New("sap: invalid byte-tables length")
			return
		}
		for i := range 200 {
			copy(t.Bytes[i][:], bytePool[i*256:(i+1)*256])
		}
		if len(wordPool) != 72*256*4 {
			tablesErr = errors.New("sap: invalid word-tables length")
			return
		}
		for table := range 72 {
			for idx := range 256 {
				off := 1024*table + 4*idx
				t.Words[table][idx] = binary.LittleEndian.Uint32(wordPool[off : off+4])
			}
		}
		maskLens := [4]int{233, 239, 241, 251}
		off := 0
		for i, n := range maskLens {
			if off+n > len(maskPool) {
				tablesErr = errors.New("sap: invalid carry-masks length")
				return
			}
			t.Masks[i] = maskPool[off : off+n]
			off += n
		}
		tablesInst = t
	})
	return tablesInst, tablesErr
}

func decodePool(pool encodedPool) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(pool.Base64)
	if err != nil {
		return nil, fmt.Errorf("sap: decode pool: %w", err)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != pool.Size || hex.EncodeToString(sum[:]) != pool.SHA256 {
		return nil, errors.New("sap: invalid SAP algorithm tables")
	}
	return raw, nil
}
