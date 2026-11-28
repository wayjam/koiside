package device

import (
	"fmt"
)

const misagentService = "com.apple.misagent"

// InstallProvisioningProfile installs a provisioning profile payload via com.apple.misagent.
// The device accepts raw mobileprovision data and activates it for matching signed apps.
func (s *Session) InstallProvisioningProfile(profileData []byte) error {
	if len(profileData) == 0 {
		return fmt.Errorf("device: empty provisioning profile payload")
	}
	conn, err := s.StartService(misagentService)
	if err != nil {
		return fmt.Errorf("device: start %s: %w", misagentService, err)
	}
	defer conn.Close()

	req := map[string]any{
		"MessageType": "Install",
		"Profile":     profileData,
		"ProfileType": "Provisioning",
	}
	if err := writePlistFrame(conn, req); err != nil {
		return fmt.Errorf("device: misagent write: %w", err)
	}

	reply, err := readPlistFrame(conn)
	if err != nil {
		return fmt.Errorf("device: misagent read: %w", err)
	}

	status, ok := reply["Status"].(int64)
	if !ok {
		if n := number(reply["Status"]); n >= 0 {
			status = int64(n)
			ok = true
		}
	}
	if !ok || status != 0 {
		return fmt.Errorf("device: misagent install profile refused (status %v): %v", reply["Status"], reply["Error"])
	}
	return nil
}

// RemoveProvisioningProfile removes an installed profile by its UUID via com.apple.misagent.
func (s *Session) RemoveProvisioningProfile(profileUUID string) error {
	if profileUUID == "" {
		return fmt.Errorf("device: empty profile UUID")
	}
	conn, err := s.StartService(misagentService)
	if err != nil {
		return fmt.Errorf("device: start %s: %w", misagentService, err)
	}
	defer conn.Close()

	req := map[string]any{
		"MessageType": "Remove",
		"ProfileID":   profileUUID,
		"ProfileType": "Provisioning",
	}
	if err := writePlistFrame(conn, req); err != nil {
		return fmt.Errorf("device: misagent write: %w", err)
	}

	reply, err := readPlistFrame(conn)
	if err != nil {
		return fmt.Errorf("device: misagent read: %w", err)
	}

	status, ok := reply["Status"].(int64)
	if !ok {
		if n := number(reply["Status"]); n >= 0 {
			status = int64(n)
			ok = true
		}
	}
	if !ok || status != 0 {
		return fmt.Errorf("device: misagent remove profile refused (status %v): %v", reply["Status"], reply["Error"])
	}
	return nil
}
