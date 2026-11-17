package appleauth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// minimal RFC 6455 client for Anisette v3 WebSocket provisioning.
type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
}

func dialWS(ctx context.Context, rawURL string, tlsCfg *tls.Config) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialer := &net.Dialer{Timeout: 20 * time.Second}
	var conn net.Conn
	if u.Scheme == "wss" {
		cfg := tlsCfg
		if cfg == nil {
			cfg = &tls.Config{}
		} else {
			cfg = cfg.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = u.Hostname()
		}
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, "tcp", host)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, err
	}

	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes[:])

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, u.Host, wsKey)
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	httpReq, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	resp, err := http.ReadResponse(br, httpReq)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("appleauth: websocket upgrade failed with HTTP %d", resp.StatusCode)
	}

	sum := sha1.Sum([]byte(wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	wantAccept := base64.StdEncoding.EncodeToString(sum[:])
	if resp.Header.Get("Sec-WebSocket-Accept") != wantAccept {
		_ = conn.Close()
		return nil, errors.New("appleauth: invalid Sec-WebSocket-Accept")
	}

	return &wsConn{conn: conn, br: br}, nil
}

func (w *wsConn) Close() error {
	_ = w.writeFrame(0x8, nil)
	return w.conn.Close()
}

func (w *wsConn) SendText(text string) error {
	return w.writeFrame(0x1, []byte(text))
}

func (w *wsConn) ReadText(ctx context.Context) (string, bool, error) {
	done := make(chan struct{})
	defer close(done)
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = w.conn.SetDeadline(time.Now())
			case <-done:
			}
		}()
	}

	var msg []byte
	for {
		fin, opcode, payload, err := w.readFrame()
		if err != nil {
			return "", false, err
		}
		switch opcode {
		case 0x8:
			return "", true, nil
		case 0x9: // ping -> pong
			_ = w.writeFrame(0xA, payload)
			continue
		case 0xA: // pong
			continue
		case 0x1, 0x0:
			msg = append(msg, payload...)
			if fin {
				return string(msg), false, nil
			}
		default:
			if fin {
				return string(msg), false, nil
			}
		}
	}
}

func (w *wsConn) writeFrame(opcode byte, payload []byte) error {
	var header [14]byte
	header[0] = 0x80 | (opcode & 0x0F)
	n := 2
	plen := len(payload)
	switch {
	case plen < 126:
		header[1] = 0x80 | byte(plen)
	case plen <= 0xFFFF:
		header[1] = 0x80 | 126
		binary.BigEndian.PutUint16(header[2:4], uint16(plen))
		n = 4
	default:
		header[1] = 0x80 | 127
		binary.BigEndian.PutUint64(header[2:10], uint64(plen))
		n = 10
	}

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	copy(header[n:n+4], mask[:])
	n += 4

	frame := make([]byte, n+plen)
	copy(frame[:n], header[:n])
	for i := range payload {
		frame[n+i] = payload[i] ^ mask[i%4]
	}
	_, err := w.conn.Write(frame)
	return err
}

func (w *wsConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(w.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > 4<<20 {
		return false, 0, nil, fmt.Errorf("appleauth: websocket frame too large (%d)", length)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(w.br, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(w.br, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, opcode, payload, nil
}
