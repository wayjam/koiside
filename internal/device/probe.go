package device

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Snapshot is a read-only summary of one connected device and its detected tools.
// Nil or empty fields remain unknown and are never assumed.
type Snapshot struct {
	Device               Device
	Info                 Info
	Apps                 []InstalledApp
	SideStore            *InstalledApp
	SideStoreEmbedded    bool
	LocalDevVPN          *InstalledApp
	LiveContainer        *InstalledApp
	SideStoreDocs        []string
	SideStoreTree        []DocEntry
	DocsBundleID         string
	LiveContainerApps    []LiveContainerApp
	LatestSideStoreLog   *SideStoreLogSummary
	USBVerified          bool
	DeveloperModeKnown   bool
	DeveloperModeEnabled bool
	SessionErr           error
}

// ProbeFirst discovers the first attached device via usbmuxd and performs
// read-only lockdown, installation_proxy, and house_arrest checks.
// It never writes pairing files, installs apps, or modifies files on the device.
func ProbeFirst(dial Dialer) (Snapshot, error) {
	muxConn, err := dialMux(dial)
	if err != nil {
		return Snapshot{}, err
	}
	client := New(muxConn)
	devs, err := client.List()
	muxConn.Close()
	if err != nil {
		return Snapshot{}, err
	}
	if len(devs) == 0 {
		return Snapshot{}, nil
	}

	dev := devs[0]
	snap := Snapshot{Device: dev}

	if info, err := Query(dial, dev.ID); err == nil {
		snap.Info = info
	}

	sess, err := DialSession(dial, dev.ID, dev.UDID)
	if err != nil {
		snap.SessionErr = err
		return snap, nil
	}
	defer sess.Close()

	if sess.Info.Name != "" || sess.Info.Version != "" || sess.Info.Type != "" || sess.Info.Build != "" {
		snap.Info = sess.Info
	}

	if devMode, devErr := sess.GetDeveloperModeStatus(); devErr == nil {
		snap.DeveloperModeKnown = true
		snap.DeveloperModeEnabled = devMode
	}
	apps, err := sess.ListApps()
	if err != nil {
		snap.SessionErr = err
		return snap, nil
	}
	snap.Apps = apps

	for i := range apps {
		app := apps[i]
		lowerID := strings.ToLower(app.BundleID)
		lowerName := strings.ToLower(app.Name)
		switch {
		case (strings.Contains(lowerID, "sidestore") && !strings.Contains(lowerID, "altstore")) || lowerName == "sidestore":
			if snap.SideStore == nil || len(app.BundleID) < len(snap.SideStore.BundleID) {
				copied := app
				snap.SideStore = &copied
			}
		case strings.Contains(lowerID, "localdevvpn") || lowerName == "localdevvpn":
			if snap.LocalDevVPN == nil {
				copied := app
				snap.LocalDevVPN = &copied
			}
		case strings.Contains(lowerID, "livecontainer") || lowerName == "livecontainer":
			if snap.LiveContainer == nil || len(app.BundleID) < len(snap.LiveContainer.BundleID) {
				copied := app
				snap.LiveContainer = &copied
			}
		}
	}
	if snap.LiveContainer != nil {
		for _, scheme := range snap.LiveContainer.URLSchemes {
			if strings.EqualFold(scheme, "sidestore") || strings.HasPrefix(strings.ToLower(scheme), "sidestore-") {
				snap.SideStoreEmbedded = true
				break
			}
		}
	}

	docsBundleID := ""
	if snap.SideStore != nil && snap.SideStore.BundleID != "" {
		docsBundleID = snap.SideStore.BundleID
	} else if snap.LiveContainer != nil && snap.LiveContainer.BundleID != "" {
		docsBundleID = snap.LiveContainer.BundleID
	}
	if docsBundleID != "" {
		afc, err := sess.VendDocuments(docsBundleID)
		if err == nil {
			tree, treeErr := afc.ReadDirTree("/Documents", 3)
			if treeErr == nil {
				snap.SideStoreTree = tree
				for _, node := range tree {
					snap.SideStoreDocs = append(snap.SideStoreDocs, node.Name)
				}
				snap.DocsBundleID = docsBundleID
				snap.USBVerified = true
			}
			if snap.LiveContainer != nil && docsBundleID == snap.LiveContainer.BundleID {
				if !snap.SideStoreEmbedded {
					st, err := afc.Stat("/Documents/SideStore")
					snap.SideStoreEmbedded = err == nil && st.Type == "S_IFDIR"
				}
				snap.LiveContainerApps = readLiveContainerApps(afc)
				snap.LatestSideStoreLog = readLatestSideStoreLog(afc, []string{"/Documents/SideStore/Documents/ConsoleLogs", "/Documents/ConsoleLogs"})
			} else {
				snap.LatestSideStoreLog = readLatestSideStoreLog(afc, []string{"/Documents/ConsoleLogs"})
			}
			afc.Close()
		}
	}
	if snap.LiveContainer != nil && snap.LiveContainer.BundleID != "" && snap.LiveContainer.BundleID != docsBundleID {
		if afc, err := sess.VendDocuments(snap.LiveContainer.BundleID); err == nil {
			if !snap.SideStoreEmbedded {
				st, err := afc.Stat("/Documents/SideStore")
				snap.SideStoreEmbedded = err == nil && st.Type == "S_IFDIR"
			}
			snap.LiveContainerApps = readLiveContainerApps(afc)
			if snap.LatestSideStoreLog == nil {
				snap.LatestSideStoreLog = readLatestSideStoreLog(afc, []string{"/Documents/SideStore/Documents/ConsoleLogs"})
			}
			afc.Close()
		}
	}
	return snap, nil
}

func dialMux(dial Dialer) (ioReadWriteCloser, error) {
	if dial != nil {
		return dial()
	}
	c, err := Dial()
	if err != nil {
		return nil, err
	}
	return c.conn, nil
}

type ioReadWriteCloser = interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// USBTransfer writes an IPA into a target app's /Documents directory via house_arrest + AFC.
type USBTransfer struct {
	Dial     Dialer
	DeviceID int
	UDID     string
	BundleID string
}

// PutIPA atomically transfers source IPA into /Documents/<basename> and verifies its SHA-256.
func (t USBTransfer) PutIPA(source string) (Transfer, error) {
	if t.DeviceID == 0 || t.UDID == "" || t.BundleID == "" {
		return Transfer{}, ErrUnavailable
	}
	body, err := os.ReadFile(source)
	if err != nil {
		return Transfer{}, err
	}
	sess, err := DialSession(t.Dial, t.DeviceID, t.UDID)
	if err != nil {
		return Transfer{}, err
	}
	defer sess.Close()

	afc, err := sess.VendDocuments(t.BundleID)
	if err != nil {
		return Transfer{}, err
	}
	defer afc.Close()

	base := filepath.Base(source)
	if base == "" || base == "." || base == "/" {
		return Transfer{}, fmt.Errorf("device: invalid filename %q", source)
	}
	remotePath := path.Join("/Documents", base)
	return afc.WriteAtomic(remotePath, body)
}

// RemoveDocPath deletes one file inside an app's /Documents container via house_arrest + AFC.
func RemoveDocPath(dial Dialer, deviceID int, udid, bundleID, remotePath string) error {
	if deviceID == 0 || udid == "" || bundleID == "" {
		return ErrUnavailable
	}
	clean := path.Clean(remotePath)
	if clean == "" || clean == "." || clean == "/" || clean == "/Documents" || !strings.HasPrefix(clean, "/Documents/") {
		return fmt.Errorf("device: invalid doc path %q", remotePath)
	}
	sess, err := DialSession(dial, deviceID, udid)
	if err != nil {
		return err
	}
	defer sess.Close()
	afc, err := sess.VendDocuments(bundleID)
	if err != nil {
		return err
	}
	defer afc.Close()
	return afc.Remove(clean)
}
