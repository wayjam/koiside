package device

import "fmt"

const houseArrestService = "com.apple.mobile.house_arrest"

// VendDocuments opens an AFC client scoped to the Documents container of bundleID.
// The caller is responsible for closing the returned AFC client.
func (s *Session) VendDocuments(bundleID string) (*AFC, error) {
	if bundleID == "" {
		return nil, fmt.Errorf("device: empty bundle ID")
	}
	conn, err := s.StartService(houseArrestService)
	if err != nil {
		return nil, err
	}
	if err := writePlistFrame(conn, map[string]any{
		"Command":    "VendDocuments",
		"Identifier": bundleID,
	}); err != nil {
		conn.Close()
		return nil, err
	}
	reply, err := readPlistFrame(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if errMsg := stringValue(reply["Error"]); errMsg != "" {
		conn.Close()
		return nil, fmt.Errorf("device: house_arrest(%s): %s", bundleID, errMsg)
	}
	if status := stringValue(reply["Status"]); status != "Complete" {
		conn.Close()
		return nil, fmt.Errorf("device: house_arrest(%s): unexpected status %q", bundleID, status)
	}
	return NewAFC(conn), nil
}

// VendContainer opens an AFC client scoped to the full container root of bundleID.
// The caller is responsible for closing the returned AFC client.
func (s *Session) VendContainer(bundleID string) (*AFC, error) {
	if bundleID == "" {
		return nil, fmt.Errorf("device: empty bundle ID")
	}
	conn, err := s.StartService(houseArrestService)
	if err != nil {
		return nil, err
	}
	if err := writePlistFrame(conn, map[string]any{
		"Command":    "VendContainer",
		"Identifier": bundleID,
	}); err != nil {
		conn.Close()
		return nil, err
	}
	reply, err := readPlistFrame(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if errMsg := stringValue(reply["Error"]); errMsg != "" {
		conn.Close()
		return nil, fmt.Errorf("device: house_arrest(%s): %s", bundleID, errMsg)
	}
	if status := stringValue(reply["Status"]); status != "Complete" {
		conn.Close()
		return nil, fmt.Errorf("device: house_arrest(%s): unexpected status %q", bundleID, status)
	}
	return NewAFC(conn), nil
}
