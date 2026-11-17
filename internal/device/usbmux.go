// Package device discovers iPhones through the system usbmuxd socket.
// Phase one lists devices only. It does not pair, install, or remove apps.
package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"howett.net/plist"
)

// ErrUnavailable means the muxer could not be queried. It does not identify why.
var ErrUnavailable = errors.New("device: unavailable")

const (
	socketPath     = "/var/run/usbmuxd"
	plistVersion   = 1
	messagePlist   = 8
	headerSize     = 16
	maxMessageSize = 1 << 20
)

// Device is one muxer record. Fields the record does not contain stay empty
// and are unknown, not assumed.
type Device struct {
	ID             int
	UDID           string
	ConnectionType string
}

// Client speaks the plist form of the usbmuxd protocol over one connection.
type Client struct {
	conn io.ReadWriteCloser
	tag  uint32
}

// New returns a client for an already connected muxer.
func New(conn io.ReadWriteCloser) *Client { return &Client{conn: conn} }

// Close closes the muxer connection.
func (c *Client) Close() error { return c.conn.Close() }


// NewDialerConn opens the raw usbmuxd unix socket connection.
func NewDialerConn() (io.ReadWriteCloser, error) {
	return net.Dial("unix", socketPath)
}

// Dial opens the system usbmuxd socket.
func Dial() (*Client, error) {
	conn, err := NewDialerConn()
	if err != nil {
		return nil, err
	}
	return New(conn), nil
}

// List asks the muxer for currently attached devices.
func (c *Client) List() ([]Device, error) {
	reply, err := c.roundTrip(map[string]any{"MessageType": "ListDevices"})
	if err != nil {
		return nil, err
	}
	raw, _ := reply["DeviceList"].([]any)
	out := make([]Device, 0, len(raw))
	for _, item := range raw {
		record, _ := item.(map[string]any)
		props, _ := record["Properties"].(map[string]any)
		device := Device{UDID: stringValue(props["SerialNumber"]), ConnectionType: stringValue(props["ConnectionType"])}
		switch id := props["DeviceID"].(type) {
		case uint64:
			device.ID = int(id)
		case int64:
			device.ID = int(id)
		case int:
			device.ID = id
		}
		if device.ID != 0 || device.UDID != "" {
			out = append(out, device)
		}
	}
	return out, nil
}

func (c *Client) roundTrip(body map[string]any) (map[string]any, error) {
	c.tag++
	payload, err := plist.Marshal(body, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[0:], uint32(len(payload)+headerSize))
	binary.LittleEndian.PutUint32(header[4:], plistVersion)
	binary.LittleEndian.PutUint32(header[8:], messagePlist)
	binary.LittleEndian.PutUint32(header[12:], c.tag)
	if _, err := c.conn.Write(append(header, payload...)); err != nil {
		return nil, err
	}
	replyHeader := make([]byte, headerSize)
	if _, err := io.ReadFull(c.conn, replyHeader); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(replyHeader[0:4])
	if length < headerSize || length > maxMessageSize {
		return nil, fmt.Errorf("device: invalid muxer message length %d", length)
	}
	if binary.LittleEndian.Uint32(replyHeader[12:16]) != c.tag {
		return nil, fmt.Errorf("device: muxer tag mismatch")
	}
	replyBody := make([]byte, length-headerSize)
	if _, err := io.ReadFull(c.conn, replyBody); err != nil {
		return nil, err
	}
	var reply map[string]any
	if _, err := plist.Unmarshal(replyBody, &reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(bytes.TrimRight(typed, "\x00"))
	default:
		return ""
	}
}

// Watch listens for usbmuxd device attach/detach events and invokes onChange until ctx is canceled.
func Watch(ctx interface{ Done() <-chan struct{} }, onChange func()) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		client, err := Dial()
		if err != nil {
			return
		}
		reply, err := client.roundTrip(map[string]any{
			"MessageType":         "Listen",
			"ClientVersionString": "koiside",
			"ProgName":            "koiside",
		})
		if err != nil || number(reply["Number"]) != 0 {
			client.Close()
			return
		}
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = client.Close()
			case <-done:
			}
		}()
		for {
			msg, err := client.readMessage()
			if err != nil {
				break
			}
			mt := stringValue(msg["MessageType"])
			if mt == "Attached" || mt == "Detached" {
				onChange()
			}
		}
		close(done)
		client.Close()
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (c *Client) readMessage() (map[string]any, error) {
	replyHeader := make([]byte, headerSize)
	if _, err := io.ReadFull(c.conn, replyHeader); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(replyHeader[0:4])
	if length < headerSize || length > maxMessageSize {
		return nil, fmt.Errorf("device: invalid muxer message length %d", length)
	}
	replyBody := make([]byte, length-headerSize)
	if _, err := io.ReadFull(c.conn, replyBody); err != nil {
		return nil, err
	}
	var reply map[string]any
	if _, err := plist.Unmarshal(replyBody, &reply); err != nil {
		return nil, err
	}
	return reply, nil
}
