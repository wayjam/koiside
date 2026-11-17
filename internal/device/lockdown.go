package device

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"howett.net/plist"
)

const lockdownPort = 62078

// Info is the public device information lockdown returned. Empty fields were
// absent and remain unknown.
type Info struct {
	Name    string
	Version string
	Build   string
	Type    string
}

// Dialer opens one usbmuxd connection.
type Dialer func() (io.ReadWriteCloser, error)

// Query reads one device without starting a TLS session. It opens its own
// muxer connection because a successful Connect consumes that connection.
func Query(dial Dialer, deviceID int) (Info, error) {
	if dial == nil {
		dial = func() (io.ReadWriteCloser, error) { return net.Dial("unix", socketPath) }
	}
	conn, err := dial()
	if err != nil {
		return Info{}, err
	}
	defer conn.Close()
	client := New(conn)
	reply, err := client.roundTrip(map[string]any{
		"MessageType": "Connect",
		"DeviceID":    deviceID,
		"PortNumber":  swappedPort(lockdownPort),
	})
	if err != nil {
		return Info{}, err
	}
	if number(reply["Number"]) != 0 {
		return Info{}, fmt.Errorf("device: connect rejected")
	}
	return queryInfo(conn)
}

func queryInfo(conn io.ReadWriteCloser) (Info, error) {
	body, err := plist.Marshal(map[string]any{
		"Label":   "koiside",
		"Request": "GetValue",
	}, plist.XMLFormat)
	if err != nil {
		return Info{}, err
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	if _, err := conn.Write(frame); err != nil {
		return Info{}, err
	}
	length := make([]byte, 4)
	if _, err := io.ReadFull(conn, length); err != nil {
		return Info{}, err
	}
	size := binary.BigEndian.Uint32(length)
	if size == 0 || size > maxMessageSize {
		return Info{}, fmt.Errorf("device: invalid lockdown message")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return Info{}, err
	}
	var reply map[string]any
	if _, err := plist.Unmarshal(payload, &reply); err != nil {
		return Info{}, err
	}
	value, _ := reply["Value"].(map[string]any)
	return Info{
		Name:    stringValue(value["DeviceName"]),
		Version: stringValue(value["ProductVersion"]),
		Build:   stringValue(value["BuildVersion"]),
		Type:    stringValue(value["ProductType"]),
	}, nil
}

func swappedPort(port uint16) uint16 { return port<<8 | port>>8 }

func number(value any) int {
	switch typed := value.(type) {
	case uint64:
		return int(typed)
	case int64:
		return int(typed)
	case int:
		return typed
	default:
		return -1
	}
}

// Service is one lockdown service port. Zero means the reply did not include it.
type Service struct {
	Name string
	Port int
}

// StartService asks lockdown for a service port. It does not connect to that service.
func StartService(conn io.ReadWriteCloser, name string) (Service, error) {
	reply, err := exchange(conn, map[string]any{"Label": "koiside", "Request": "StartService", "Service": name})
	if err != nil {
		return Service{}, err
	}
	if reply["Error"] != nil {
		return Service{}, fmt.Errorf("device: service refused")
	}
	return Service{Name: name, Port: number(reply["Port"])}, nil
}

func exchange(conn io.ReadWriteCloser, body map[string]any) (map[string]any, error) {
	payload, err := plist.Marshal(body, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	length := make([]byte, 4)
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(length)
	if size == 0 || size > maxMessageSize {
		return nil, fmt.Errorf("device: invalid lockdown message")
	}
	replyBody := make([]byte, size)
	if _, err := io.ReadFull(conn, replyBody); err != nil {
		return nil, err
	}
	var reply map[string]any
	if _, err := plist.Unmarshal(replyBody, &reply); err != nil {
		return nil, err
	}
	return reply, nil
}
