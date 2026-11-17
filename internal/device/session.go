package device

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"howett.net/plist"
)

var (
	// ErrLocked indicates the device is locked with a passcode and cannot start a trusted session.
	ErrLocked = errors.New("device: passcode locked")
	// ErrUntrusted indicates no valid pairing record exists or the device rejected trust.
	ErrUntrusted = errors.New("device: not paired or untrusted")
)

// PairRecord holds the host/device trust credentials from usbmuxd.
// Private key bytes are never exposed in logs or string representations.
type PairRecord struct {
	HostID            string `plist:"HostID"`
	SystemBUID        string `plist:"SystemBUID"`
	HostCertificate   []byte `plist:"HostCertificate"`
	HostPrivateKey    []byte `plist:"HostPrivateKey"`
	DeviceCertificate []byte `plist:"DeviceCertificate"`
	RootCertificate   []byte `plist:"RootCertificate"`
}

func (PairRecord) String() string { return "PairRecord{redacted}" }

// ReadPairRecord asks usbmuxd for the existing pairing record of udid.
// It is read-only and never writes or modifies pairing files.
func (c *Client) ReadPairRecord(udid string) (PairRecord, error) {
	if udid == "" {
		return PairRecord{}, ErrUntrusted
	}
	reply, err := c.roundTrip(map[string]any{
		"MessageType":         "ReadPairRecord",
		"PairRecordID":        udid,
		"ClientVersionString": "koiside",
		"ProgName":            "koiside",
	})
	if err != nil {
		return PairRecord{}, err
	}
	if num := number(reply["Number"]); num > 0 {
		return PairRecord{}, fmt.Errorf("%w: usbmuxd error %d", ErrUntrusted, num)
	}
	raw, ok := reply["PairRecordData"].([]byte)
	if !ok || len(raw) == 0 {
		return PairRecord{}, ErrUntrusted
	}
	var rec PairRecord
	if _, err := plist.Unmarshal(raw, &rec); err != nil {
		return PairRecord{}, fmt.Errorf("device: decode pair record: %w", err)
	}
	if rec.HostID == "" || len(rec.HostCertificate) == 0 || len(rec.HostPrivateKey) == 0 {
		return PairRecord{}, ErrUntrusted
	}
	return rec, nil
}

func (rec PairRecord) tlsConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(rec.HostCertificate, rec.HostPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("device: parse pairing certificate: %w", err)
	}
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // Device lockdown certificates use self-signed pairing CA without matching hostnames.
		MinVersion:         tls.VersionTLS12,
	}
	if len(rec.RootCertificate) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(rec.RootCertificate) {
			cfg.RootCAs = pool
		}
	}
	return cfg, nil
}

// Session is an authenticated lockdownd connection for read-only service queries.
type Session struct {
	dial      Dialer
	deviceID  int
	conn      io.ReadWriteCloser
	sessionID string
	tlsCfg    *tls.Config
	Info      Info
}

// DialSession opens a read-only lockdownd session using the existing pairing record.
// It never writes or modifies pairing records on the host or device.
func DialSession(dial Dialer, deviceID int, udid string) (*Session, error) {
	if dial == nil {
		dial = func() (io.ReadWriteCloser, error) { return net.Dial("unix", socketPath) }
	}
	muxConn, err := dial()
	if err != nil {
		return nil, err
	}
	mux := New(muxConn)
	rec, err := mux.ReadPairRecord(udid)
	muxConn.Close()
	if err != nil {
		return nil, err
	}
	tlsCfg, err := rec.tlsConfig()
	if err != nil {
		return nil, err
	}

	conn, err := connectMuxPort(dial, deviceID, lockdownPort)
	if err != nil {
		return nil, err
	}

	info, err := queryInfo(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	reply, err := exchange(conn, map[string]any{
		"Label":      "koiside",
		"Request":    "StartSession",
		"HostID":     rec.HostID,
		"SystemBUID": rec.SystemBUID,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if errMsg := stringValue(reply["Error"]); errMsg != "" {
		conn.Close()
		switch errMsg {
		case "PasswordProtected":
			return nil, ErrLocked
		case "InvalidHostID":
			return nil, ErrUntrusted
		default:
			return nil, fmt.Errorf("device: start session: %s", errMsg)
		}
	}

	sessID := stringValue(reply["SessionID"])
	if enableSSL, _ := reply["EnableSessionSSL"].(bool); enableSSL {
		nc, ok := conn.(net.Conn)
		if !ok {
			conn.Close()
			return nil, fmt.Errorf("device: underlying connection does not support TLS")
		}
		tlsConn := tls.Client(nc, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("device: lockdown TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	// Re-query full device info over authenticated session so BuildVersion/ProductName are populated if available.
	if fullInfo, err := queryInfo(conn); err == nil {
		if fullInfo.Name != "" {
			info.Name = fullInfo.Name
		}
		if fullInfo.Version != "" {
			info.Version = fullInfo.Version
		}
		if fullInfo.Type != "" {
			info.Type = fullInfo.Type
		}
		if fullInfo.Build != "" {
			info.Build = fullInfo.Build
		}
	}

	return &Session{
		dial:      dial,
		deviceID:  deviceID,
		conn:      conn,
		sessionID: sessID,
		tlsCfg:    tlsCfg,
		Info:      info,
	}, nil
}

// Close stops the lockdown session (best effort) and closes the connection.
func (s *Session) Close() error {
	if s.conn == nil {
		return nil
	}
	if s.sessionID != "" {
		_, _ = exchange(s.conn, map[string]any{
			"Label":     "koiside",
			"Request":   "StopSession",
			"SessionID": s.sessionID,
		})
	}
	return s.conn.Close()
}

// StartService asks lockdownd to start name and returns a connected channel (wrapped in TLS when requested).
func (s *Session) StartService(name string) (io.ReadWriteCloser, error) {
	reply, err := exchange(s.conn, map[string]any{
		"Label":   "koiside",
		"Request": "StartService",
		"Service": name,
	})
	if err != nil {
		return nil, err
	}
	if errMsg := stringValue(reply["Error"]); errMsg != "" {
		if errMsg == "PasswordProtected" {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("device: start service %s: %s", name, errMsg)
	}
	port := number(reply["Port"])
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("device: service %s returned invalid port %d", name, port)
	}
	conn, err := connectMuxPort(s.dial, s.deviceID, uint16(port))
	if err != nil {
		return nil, err
	}
	if enableSSL, _ := reply["EnableServiceSSL"].(bool); enableSSL {
		nc, ok := conn.(net.Conn)
		if !ok {
			conn.Close()
			return nil, fmt.Errorf("device: service %s connection does not support TLS", name)
		}
		tlsConn := tls.Client(nc, s.tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("device: service %s TLS handshake: %w", name, err)
		}
		conn = tlsConn
	}
	return conn, nil
}

func connectMuxPort(dial Dialer, deviceID int, port uint16) (io.ReadWriteCloser, error) {
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	client := New(conn)
	reply, err := client.roundTrip(map[string]any{
		"MessageType": "Connect",
		"DeviceID":    deviceID,
		"PortNumber":  swappedPort(port),
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if num := number(reply["Number"]); num != 0 {
		conn.Close()
		return nil, fmt.Errorf("device: connect port %d rejected (%d)", port, num)
	}
	return conn, nil
}

func writePlistFrame(w io.Writer, body map[string]any) error {
	payload, err := plist.Marshal(body, plist.XMLFormat)
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	_, err = w.Write(frame)
	return err
}

func readPlistFrame(r io.Reader) (map[string]any, error) {
	length := make([]byte, 4)
	if _, err := io.ReadFull(r, length); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(length)
	if size == 0 || size > 16<<20 {
		return nil, fmt.Errorf("device: invalid plist message size %d", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	var reply map[string]any
	if _, err := plist.Unmarshal(payload, &reply); err != nil {
		return nil, err
	}
	return reply, nil
}
