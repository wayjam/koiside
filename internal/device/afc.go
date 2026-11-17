package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

const (
	afcMagic      = "CFA6LPAA"
	afcHeaderSize = 40
	afcMaxPacket  = 64 << 20

	afcOpStatus      = 0x00000001
	afcOpData        = 0x00000002
	afcOpReadDir     = 0x00000003
	afcOpRemovePath  = 0x00000008
	afcOpMakeDir     = 0x00000009
	afcOpGetFileInfo = 0x0000000A
	afcOpFileOpen    = 0x0000000D
	afcOpFileOpenRes = 0x0000000E
	afcOpFileRead    = 0x0000000F
	afcOpFileWrite   = 0x00000010
	afcOpFileClose   = 0x00000014
	afcOpRenamePath  = 0x00000018

	afcModeReadOnly  = 0x00000001
	afcModeWriteOnly = 0x00000003 // O_WRONLY | O_CREAT | O_TRUNC in Apple AFC (rw=2, wr=3)

	afcSuccess = 0
)

// Transfer is one file placed in an app document directory. Matching hashes
// prove the bytes transferred, not that the app installed it.
type Transfer struct {
	Path   string
	SHA256 string
}

// FileStat describes one remote file/directory entry in AFC.
type FileStat struct {
	Size int64
	Type string
}

// DocEntry represents one file or directory node inside an app document container.
type DocEntry struct {
	Name     string
	Path     string
	IsDir    bool
	Size     int64
	Children []DocEntry
}

// DocumentTransfer puts one IPA into an app document directory.
type DocumentTransfer interface {
	PutIPA(source string) (Transfer, error)
}

// AFC is a file client for one already connected AFC / house_arrest service.
type AFC struct {
	conn   io.ReadWriteCloser
	packet uint64
}

// NewAFC uses an existing service connection.
func NewAFC(conn io.ReadWriteCloser) *AFC { return &AFC{conn: conn} }

// Close closes the underlying AFC connection.
func (a *AFC) Close() error {
	if a.conn == nil {
		return nil
	}
	return a.conn.Close()
}

// ReadDir lists directory entries at remote path (skipping "." and "..").
func (a *AFC) ReadDir(remotePath string) ([]string, error) {
	op, body, err := a.roundTrip(afcOpReadDir, append([]byte(remotePath), 0), nil)
	if err != nil {
		return nil, err
	}
	if op != afcOpData {
		return nil, fmt.Errorf("device: unexpected AFC ReadDir reply op %d", op)
	}
	raw := strings.Split(string(body), "\x00")
	var entries []string
	for _, entry := range raw {
		if entry == "" || entry == "." || entry == ".." {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// ReadDirTree lists a directory hierarchy recursively up to maxDepth.
func (a *AFC) ReadDirTree(remotePath string, maxDepth int) ([]DocEntry, error) {
	names, err := a.ReadDir(remotePath)
	if err != nil {
		return nil, err
	}
	entries := make([]DocEntry, 0, len(names))
	for _, name := range names {
		full := path.Join(remotePath, name)
		st, err := a.Stat(full)
		entry := DocEntry{
			Name:  name,
			Path:  full,
			IsDir: err == nil && st.Type == "S_IFDIR",
			Size:  st.Size,
		}
		if entry.IsDir && maxDepth > 0 {
			if kids, err := a.ReadDirTree(full, maxDepth-1); err == nil {
				entry.Children = kids
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, nil
}

// Stat reads metadata of remote path via AFC_OP_GET_FILE_INFO.
func (a *AFC) Stat(remotePath string) (FileStat, error) {
	op, body, err := a.roundTrip(afcOpGetFileInfo, append([]byte(remotePath), 0), nil)
	if err != nil {
		return FileStat{}, err
	}
	if op != afcOpData {
		return FileStat{}, fmt.Errorf("device: unexpected AFC Stat reply op %d", op)
	}
	parts := strings.Split(string(body), "\x00")
	var st FileStat
	for i := 0; i+1 < len(parts); i += 2 {
		switch parts[i] {
		case "st_size":
			if n, err := strconv.ParseInt(parts[i+1], 10, 64); err == nil {
				st.Size = n
			}
		case "st_ifmt":
			st.Type = parts[i+1]
		}
	}
	return st, nil
}

// ReadFile reads all bytes of remote path via FileRefOpen -> FileRefRead -> FileRefClose.
func (a *AFC) ReadFile(remotePath string) ([]byte, error) {
	handle, err := a.fileOpen(remotePath, afcModeReadOnly)
	if err != nil {
		return nil, err
	}
	defer a.fileClose(handle)

	var out bytes.Buffer
	const chunk = 512 * 1024
	for {
		req := make([]byte, 16)
		binary.LittleEndian.PutUint64(req[0:8], handle)
		binary.LittleEndian.PutUint64(req[8:16], chunk)
		op, body, err := a.roundTrip(afcOpFileRead, req, nil)
		if err != nil {
			return nil, err
		}
		if op == afcOpStatus {
			break
		}
		if op != afcOpData {
			return nil, fmt.Errorf("device: unexpected AFC FileRead op %d", op)
		}
		if len(body) == 0 {
			break
		}
		out.Write(body)
		if len(body) < chunk {
			break
		}
	}
	return out.Bytes(), nil
}

// WriteAtomic writes body to a temporary name and renames it only after the
// remote bytes hash to the same value.
func (a *AFC) WriteAtomic(remotePath string, body []byte) (Transfer, error) {
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])
	temp := remotePath + ".partial"
	if err := a.writeFile(temp, body); err != nil {
		return Transfer{}, err
	}
	remote, err := a.ReadFile(temp)
	if err != nil {
		_ = a.Remove(temp)
		return Transfer{}, err
	}
	gotSum := sha256.Sum256(remote)
	if hex.EncodeToString(gotSum[:]) != want {
		_ = a.Remove(temp)
		return Transfer{}, fmt.Errorf("device: transferred bytes differ")
	}
	if err := a.rename(temp, remotePath); err != nil {
		_ = a.Remove(temp)
		return Transfer{}, err
	}
	return Transfer{Path: remotePath, SHA256: want}, nil
}

// Remove deletes one remote path.
func (a *AFC) Remove(remotePath string) error {
	_, _, err := a.roundTrip(afcOpRemovePath, append([]byte(remotePath), 0), nil)
	return err
}

func (a *AFC) fileOpen(remotePath string, mode uint64) (uint64, error) {
	headerPayload := make([]byte, 8+len(remotePath)+1)
	binary.LittleEndian.PutUint64(headerPayload[0:8], mode)
	copy(headerPayload[8:], remotePath)
	op, body, err := a.roundTrip(afcOpFileOpen, headerPayload, nil)
	if err != nil {
		return 0, err
	}
	if op != afcOpFileOpenRes || len(body) < 8 {
		return 0, fmt.Errorf("device: unexpected AFC FileOpen reply op %d", op)
	}
	return binary.LittleEndian.Uint64(body[:8]), nil
}

func (a *AFC) fileClose(handle uint64) error {
	req := make([]byte, 8)
	binary.LittleEndian.PutUint64(req, handle)
	_, _, err := a.roundTrip(afcOpFileClose, req, nil)
	return err
}

// WriteReader streams r to remotePath in 512 KB chunks without buffering the entire file in memory.
func (a *AFC) WriteReader(remotePath string, r io.Reader, totalSize int64, onProgress func(uploaded, total int64)) error {
	handle, err := a.fileOpen(remotePath, afcModeWriteOnly)
	if err != nil {
		return err
	}
	defer a.fileClose(handle)

	req := make([]byte, 8)
	binary.LittleEndian.PutUint64(req, handle)
	const chunk = 512 * 1024
	buf := make([]byte, chunk)
	var uploaded int64
	for {
		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			if _, _, err := a.roundTrip(afcOpFileWrite, req, buf[:n]); err != nil {
				return err
			}
			uploaded += int64(n)
			if onProgress != nil {
				onProgress(uploaded, totalSize)
			}
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}

func (a *AFC) writeFile(remotePath string, body []byte) error {
	handle, err := a.fileOpen(remotePath, afcModeWriteOnly)
	if err != nil {
		return err
	}
	defer a.fileClose(handle)

	req := make([]byte, 8)
	binary.LittleEndian.PutUint64(req, handle)
	const chunk = 512 * 1024
	for offset := 0; offset < len(body) || (len(body) == 0 && offset == 0); {
		end := offset + chunk
		if end > len(body) {
			end = len(body)
		}
		if _, _, err := a.roundTrip(afcOpFileWrite, req, body[offset:end]); err != nil {
			return err
		}
		offset = end
		if len(body) == 0 {
			break
		}
	}
	return nil
}

func (a *AFC) rename(from, to string) error {
	payload := append(append([]byte(from), 0), append([]byte(to), 0)...)
	_, _, err := a.roundTrip(afcOpRenamePath, payload, nil)
	return err
}

func (a *AFC) roundTrip(operation uint64, headerPayload, dataPayload []byte) (uint64, []byte, error) {
	a.packet++
	thisLen := uint64(afcHeaderSize + len(headerPayload))
	entireLen := thisLen + uint64(len(dataPayload))
	pkt := make([]byte, entireLen)
	copy(pkt, afcMagic)
	binary.LittleEndian.PutUint64(pkt[8:], entireLen)
	binary.LittleEndian.PutUint64(pkt[16:], thisLen)
	binary.LittleEndian.PutUint64(pkt[24:], a.packet)
	binary.LittleEndian.PutUint64(pkt[32:], operation)
	copy(pkt[afcHeaderSize:], headerPayload)
	copy(pkt[thisLen:], dataPayload)

	if _, err := a.conn.Write(pkt); err != nil {
		return 0, nil, err
	}

	replyHeader := make([]byte, afcHeaderSize)
	if _, err := io.ReadFull(a.conn, replyHeader); err != nil {
		return 0, nil, err
	}
	if string(replyHeader[:8]) != afcMagic {
		return 0, nil, fmt.Errorf("device: invalid AFC reply")
	}
	total := binary.LittleEndian.Uint64(replyHeader[8:])
	if total < afcHeaderSize || total > afcMaxPacket {
		return 0, nil, fmt.Errorf("device: invalid AFC length %d", total)
	}
	body := make([]byte, total-afcHeaderSize)
	if _, err := io.ReadFull(a.conn, body); err != nil {
		return 0, nil, err
	}
	op := binary.LittleEndian.Uint64(replyHeader[32:])
	if op == afcOpStatus {
		if len(body) < 8 || binary.LittleEndian.Uint64(body[:8]) != afcSuccess {
			code := uint64(0)
			if len(body) >= 8 {
				code = binary.LittleEndian.Uint64(body[:8])
			}
			return op, body, fmt.Errorf("device: AFC operation failed (status %d)", code)
		}
		return op, body, nil
	}
	return op, body, nil
}

// SHA256 returns the hash of body.
func SHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// BytesEqual reports whether two payloads are identical.
func BytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }
