package device

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

// InstallProgress reports staging upload and installation_proxy progress (0..100).
type InstallProgress func(pct int, status string)

// Mkdir creates a directory path (recursively) inside the connected AFC service.
func (a *AFC) Mkdir(remotePath string) error {
	clean := path.Clean(remotePath)
	if clean == "." || clean == "/" {
		return nil
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	cur := ""
	if strings.HasPrefix(clean, "/") {
		cur = ""
	}
	for _, p := range parts {
		if p == "" {
			continue
		}
		if cur == "" && strings.HasPrefix(clean, "/") {
			cur = "/" + p
		} else if cur == "" {
			cur = p
		} else {
			cur = cur + "/" + p
		}
		_, _, _ = a.roundTrip(afcOpMakeDir, append([]byte(cur), 0), nil)
	}
	return nil
}

// WriteFile writes raw bytes to remotePath directly using 512 KB chunks.
func (a *AFC) WriteFile(remotePath string, body []byte) error {
	return a.writeFile(remotePath, body)
}

// UploadDir recursively uploads localDir to remoteDir via AFC.
func (a *AFC) UploadDir(localDir, remoteDir string, onProgress func(uploaded, total int64)) error {
	var total int64
	_ = filepath.WalkDir(localDir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, statErr := d.Info(); statErr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	if total == 0 {
		total = 1
	}

	if err := a.Mkdir(remoteDir); err != nil {
		return err
	}

	var uploaded int64
	return filepath.WalkDir(localDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(localDir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		remotePath := path.Join(remoteDir, filepath.ToSlash(rel))
		if d.IsDir() {
			return a.Mkdir(remotePath)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := a.writeFile(remotePath, data); err != nil {
			return err
		}
		uploaded += int64(len(data))
		if onProgress != nil {
			onProgress(uploaded, total)
		}
		return nil
	})
}

// InstallAppDir uploads a signed .app directory to PublicStaging/<name> via com.apple.afc
// and triggers com.apple.mobile.installation_proxy Install.
func (s *Session) InstallAppDir(appDir string, onProgress InstallProgress) error {
	report := func(pct int, status string) {
		if onProgress != nil {
			onProgress(pct, status)
		}
	}

	report(5, "Connecting to AFC")
	afcConn, err := s.StartService("com.apple.afc")
	if err != nil {
		return fmt.Errorf("device: start com.apple.afc: %w", err)
	}
	afc := NewAFC(afcConn)
	stageDir := path.Join("PublicStaging", filepath.Base(appDir))

	report(10, "Uploading app bundle")
	uploadErr := afc.UploadDir(appDir, stageDir, func(uploaded, total int64) {
		pct := 10 + int(float64(uploaded)*60.0/float64(total))
		if pct > 70 {
			pct = 70
		}
		report(pct, "Uploading app bundle")
	})
	_ = afc.Close()
	if uploadErr != nil {
		return fmt.Errorf("device: upload to %s: %w", stageDir, uploadErr)
	}

	report(72, "Connecting to installation_proxy")
	instConn, err := s.StartService("com.apple.mobile.installation_proxy")
	if err != nil {
		return fmt.Errorf("device: start installation_proxy: %w", err)
	}
	defer instConn.Close()

	return InstallStagedPackage(instConn, stageDir, onProgress)
}

// InstallStagedPackage sends the Install command to installation_proxy and streams progress until Complete.
func InstallStagedPackage(conn io.ReadWriteCloser, packagePath string, onProgress InstallProgress) error {
	req := map[string]any{
		"Command":     "Install",
		"PackagePath": packagePath,
		"ClientOptions": map[string]any{
			"PackageType": "Developer",
		},
	}
	if err := writePlistFrame(conn, req); err != nil {
		return err
	}
	for {
		reply, err := readPlistFrame(conn)
		if err != nil {
			return fmt.Errorf("device: installation_proxy read: %w", err)
		}
		if errDesc, _ := reply["ErrorDescription"].(string); errDesc != "" {
			if errCode, _ := reply["Error"].(string); errCode != "" {
				return fmt.Errorf("device: install failed (%s): %s", errCode, errDesc)
			}
			return fmt.Errorf("device: install failed: %s", errDesc)
		}
		if errCode, _ := reply["Error"].(string); errCode != "" {
			return fmt.Errorf("device: install failed: %s", errCode)
		}
		status, _ := reply["Status"].(string)
		if pct, ok := numberOrZero(reply["PercentComplete"]); ok && onProgress != nil {
			scaled := 70 + (pct*30)/100
			if status == "" {
				status = "Installing"
			}
			onProgress(scaled, status)
		}
		if status == "Complete" {
			if onProgress != nil {
				onProgress(100, "Complete")
			}
			return nil
		}
	}
}

func numberOrZero(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case uint64:
		return int(x), true
	default:
		return 0, false
	}
}

// EnableWifiDebugging enables wireless lockdown debugging on the device so lockdown pairing works over Wi-Fi/tunnel.
func (s *Session) EnableWifiDebugging() error {
	reply, err := exchange(s.conn, map[string]any{
		"Label":   "koiside",
		"Request": "SetValue",
		"Domain":  "com.apple.mobile.wireless_lockdown",
		"Key":     "EnableWifiDebugging",
		"Value":   true,
	})
	if err != nil {
		return err
	}
	if errMsg := stringValue(reply["Error"]); errMsg != "" {
		return fmt.Errorf("device: enable wifi debugging: %s", errMsg)
	}
	return nil
}

// ExportLockdownPairingPlist reads the usbmuxd pairing record for udid, injects UDID,
// and serializes it as XML plist bytes (compatible with SideStore PairingFile_Lockdown.plist).
func ExportLockdownPairingPlist(dial Dialer, udid string) ([]byte, error) {
	if dial == nil {
		dial = func() (io.ReadWriteCloser, error) {
			return NewDialerConn()
		}
	}
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rec, err := New(conn).ReadPairRecord(udid)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{
		"HostID":            rec.HostID,
		"SystemBUID":        rec.SystemBUID,
		"HostCertificate":   rec.HostCertificate,
		"HostPrivateKey":    rec.HostPrivateKey,
		"DeviceCertificate": rec.DeviceCertificate,
		"RootCertificate":   rec.RootCertificate,
		"UDID":              udid,
	}
	return plist.Marshal(doc, plist.XMLFormat)
}
