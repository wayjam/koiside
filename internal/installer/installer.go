// Package installer orchestrates downloading official SideStore / LiveContainer IPAs,
// desktop code signing via Apple Developer Portal, USB installation, and pairing injection.
package installer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"koiside/internal/account"
	"koiside/internal/appleauth"
	"koiside/internal/device"
	"koiside/internal/devportal"
	"koiside/internal/signing"
)

// ToolTarget identifies a supported ecosystem app to install on iPhone.
type ToolTarget string

const (
	TargetSideStore         ToolTarget = "sidestore"
	TargetSideStoreNightly  ToolTarget = "sidestore-nightly"
	TargetLiveContainerLCSS ToolTarget = "livecontainer-sidestore"
	TargetLiveContainerOnly ToolTarget = "livecontainer"
	TargetCustomIPA         ToolTarget = "custom-ipa"
)

// OfficialAsset describes a verifiable official GitHub release artifact.
type OfficialAsset struct {
	Target   ToolTarget
	Name     string
	Filename string
	URL      string
	Note     string
}

// OfficialAssetFor returns the official download source for SideStore / LiveContainer builds.
// LocalDevVPN relies on NetworkExtension (packet-tunnel-provider), which cannot be signed with a
// free Personal Team account; free users install it from the App Store while paid developers
// may import/build a local IPA via TargetCustomIPA.
func OfficialAssetFor(target ToolTarget) (OfficialAsset, bool) {
	switch target {
	case TargetSideStore:
		return OfficialAsset{
			Target:   target,
			Name:     "SideStore",
			Filename: "SideStore.ipa",
			URL:      "https://github.com/SideStore/SideStore/releases/latest/download/SideStore.ipa",
		}, true
	case TargetSideStoreNightly:
		return OfficialAsset{
			Target:   target,
			Name:     "SideStore (Nightly)",
			Filename: "SideStore-Nightly.ipa",
			URL:      "https://github.com/SideStore/SideStore/releases/download/nightly/SideStore.ipa",
		}, true
	case TargetLiveContainerLCSS:
		return OfficialAsset{
			Target:   target,
			Name:     "LiveContainer + SideStore",
			Filename: "LiveContainer+SideStore.ipa",
			URL:      "https://github.com/LiveContainer/LiveContainer/releases/download/nightly/LiveContainer+SideStore.ipa",
			Note:     "Official LiveContainer nightly bundle containing SideStore",
		}, true
	case TargetLiveContainerOnly:
		return OfficialAsset{
			Target:   target,
			Name:     "LiveContainer",
			Filename: "LiveContainer.ipa",
			URL:      "https://github.com/LiveContainer/LiveContainer/releases/download/nightly/LiveContainer.ipa",
		}, true
	default:
		return OfficialAsset{}, false
	}
}

// Progress reports stage and percentage (0..100) to the UI.
type Progress func(pct int, stage string)

// InstallRequest configures direct desktop sign + USB install + optional pairing injection.
type InstallRequest struct {
	Target      ToolTarget
	LocalIPAPath string // required for TargetCustomIPA, optional override otherwise
	CacheDir    string
	Device      device.Device
	DeviceInfo  device.Info
	Accounts    account.Manager
	OnMaxCerts  devportal.MaxCertsHandler
	OnProgress  Progress
	HTTPClient  *http.Client
	DeviceDial  device.Dialer
}

// InstallResult summarizes a completed direct install.
type InstallResult struct {
	BundleID             string
	Special              signing.SpecialApp
	PairingInjected      bool
	PairingWarning       string
	DeveloperModeKnown   bool
	DeveloperModeEnabled bool
	SignerTrusted        bool
}
// InstallDirect downloads the official IPA (if needed), signs it with the active Apple Developer
// session, uploads & installs over USB, and injects pairing files when installing SideStore / LC+SS.
func InstallDirect(ctx context.Context, req InstallRequest) (InstallResult, error) {
	report := func(pct int, stage string) {
		if req.OnProgress != nil {
			req.OnProgress(pct, stage)
		}
	}
	if req.Accounts == nil || !req.Accounts.Developer().SignedIn() {
		return InstallResult{}, errors.New("installer: Apple Developer account not signed in")
	}
	if req.Device.ID == 0 || req.Device.UDID == "" {
		return InstallResult{}, errors.New("installer: no connected iPhone selected")
	}
	portal, err := req.Accounts.DeveloperPortal()
	if err != nil {
		return InstallResult{}, err
	}
	team, ok := req.Accounts.Developer().ActiveTeam()
	if !ok {
		return InstallResult{}, errors.New("installer: no developer team available")
	}

	ipaPath := strings.TrimSpace(req.LocalIPAPath)
	if ipaPath == "" {
		asset, ok := OfficialAssetFor(req.Target)
		if !ok {
			return InstallResult{}, fmt.Errorf("installer: unsupported target %q", req.Target)
		}
		report(5, "download")
		cacheDir := req.CacheDir
		if cacheDir == "" {
			cacheDir = filepath.Join(os.TempDir(), "koiside-downloads")
		}
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return InstallResult{}, err
		}
		ipaPath = filepath.Join(cacheDir, asset.Filename)
		needDownload := true
		if st, statErr := os.Stat(ipaPath); statErr == nil && st.Size() > 1<<20 && time.Since(st.ModTime()) < 24*time.Hour {
			needDownload = false
		}
		if needDownload {
			if err := downloadFile(ctx, req.HTTPClient, asset.URL, ipaPath, func(p int) {
				report(5+(p*20)/100, "download")
			}); err != nil {
				return InstallResult{}, fmt.Errorf("installer: download %s: %w", asset.Name, err)
			}
		} else {
			report(25, "download")
		}
	}

	report(28, "certificate")
	cert, err := devportal.EnsureCertificate(
		ctx,
		portal,
		team.TeamID,
		req.Accounts.Developer().Email(),
		localMachineName(),
		req.Accounts.Storage(),
		req.OnMaxCerts,
	)
	if err != nil {
		return InstallResult{}, fmt.Errorf("installer: certificate: %w", err)
	}

	workDir, err := os.MkdirTemp("", "koiside-install-*")
	if err != nil {
		return InstallResult{}, err
	}
	defer os.RemoveAll(workDir)

	report(35, "signing")
	signed, err := signing.SignIPAWithPortal(ctx, signing.PortalSignOptions{
		InputPath:             ipaPath,
		WorkDir:               workDir,
		DeviceName:            req.DeviceInfo.Name,
		DeviceUDID:            req.Device.UDID,
		Team:                  team,
		Portal:                portal,
		Cert:                  cert,
		IncreasedMemoryLimit:  true,
		RegisterAllExtensions: false,
		OnProgress: func(pct float64, stage string) {
			report(35+int(pct*30.0), stage)
		},
	})
	if err != nil {
		return InstallResult{}, err
	}

	report(68, "usb_install")
	sess, err := device.DialSession(req.DeviceDial, req.Device.ID, req.Device.UDID)
	if err != nil {
		return InstallResult{}, err
	}
	installErr := sess.InstallAppDir(signed.AppDir, func(pct int, status string) {
		report(68+(pct*24)/100, status)
	})
	var devKnown, devEnabled, signerTrusted bool
	if installErr == nil {
		if dm, dmErr := sess.GetDeveloperModeStatus(); dmErr == nil {
			devKnown = true
			devEnabled = dm
		}
		if signed.ProfileUUID != "" {
			if trusted, tErr := sess.TrustAppSigner(signed.ProfileUUID); tErr == nil {
				signerTrusted = trusted
			}
		}
	}
	_ = sess.Close()
	if installErr != nil {
		return InstallResult{}, installErr
	}

	res := InstallResult{
		BundleID:             signed.BundleID,
		Special:              signed.Special,
		DeveloperModeKnown:   devKnown,
		DeveloperModeEnabled: devEnabled,
		SignerTrusted:        signerTrusted,
	}
	if signed.Special == signing.SpecialSideStore || signed.Special == signing.SpecialSideStoreLC {
		report(94, "pairing")
		if err := PlacePairingForDevice(req.DeviceDial, req.Device, req.DeviceInfo, req.Accounts.Storage(), signed.BundleID, signed.Special == signing.SpecialSideStoreLC); err != nil {
			res.PairingWarning = err.Error()
		} else {
			res.PairingInjected = true
		}
	}

	report(100, "complete")
	return res, nil
}

// PlacePairingForDevice generates/reuses Lockdown + RPPairing files and writes them via house_arrest/AFC.
func PlacePairingForDevice(dial device.Dialer, dev device.Device, info device.Info, storage appleauth.Storage, bundleID string, isLiveContainer bool) error {
	hostLabel := loadOrCreateHostLabel(storage, dev.UDID)
	cacheKey := "rppairing_1_1_" + dev.UDID
	var cachedRP []byte
	if storage != nil {
		cachedRP, _ = storage.Get(cacheKey)
	}

	lockdownPlist, rpPlist, rpErr := device.GenerateSideStorePairingFiles(dial, dev.ID, dev.UDID, info.Version, hostLabel, cachedRP)
	if len(lockdownPlist) == 0 && rpErr != nil {
		return rpErr
	}
	if len(rpPlist) > 0 && storage != nil {
		_ = storage.Set(cacheKey, rpPlist)
	}

	targetPaths := []string{"ALTPairingFile.mobiledevicepairing", "PairingFile_RemoteRP.plist", "PairingFile_Lockdown.plist"}
	if isLiveContainer {
		targetPaths = []string{"SideStore/Documents/ALTPairingFile.mobiledevicepairing", "SideStore/Documents/PairingFile_RemoteRP.plist"}
	}
	if err := device.PlacePairingFiles(dial, dev.ID, dev.UDID, bundleID, targetPaths, lockdownPlist, rpPlist); err != nil {
		return err
	}
	return rpErr
}

// PlacePairingToTarget places pairing files into an arbitrary detected pairing-capable app.
func PlacePairingToTarget(dial device.Dialer, dev device.Device, info device.Info, storage appleauth.Storage, target device.PairingTarget) error {
	hostLabel := loadOrCreateHostLabel(storage, dev.UDID)
	cacheKey := "rppairing_1_1_" + dev.UDID
	var cachedRP []byte
	if storage != nil {
		cachedRP, _ = storage.Get(cacheKey)
	}
	lockdownPlist, rpPlist, rpErr := device.GenerateSideStorePairingFiles(dial, dev.ID, dev.UDID, info.Version, hostLabel, cachedRP)
	if len(lockdownPlist) == 0 && rpErr != nil {
		return rpErr
	}
	if len(rpPlist) > 0 && storage != nil {
		_ = storage.Set(cacheKey, rpPlist)
	}
	if err := device.PlacePairingFiles(dial, dev.ID, dev.UDID, target.BundleID, target.Paths, lockdownPlist, rpPlist); err != nil {
		return err
	}
	return rpErr
}

// ExportPairingBytes returns the best available pairing plist for manual export (RPPairing on iOS 17.4+, else Lockdown).
func ExportPairingBytes(dial device.Dialer, dev device.Device, info device.Info, storage appleauth.Storage) ([]byte, error) {
	hostLabel := loadOrCreateHostLabel(storage, dev.UDID)
	cacheKey := "rppairing_1_1_" + dev.UDID
	var cachedRP []byte
	if storage != nil {
		cachedRP, _ = storage.Get(cacheKey)
	}
	lockdownPlist, rpPlist, rpErr := device.GenerateSideStorePairingFiles(dial, dev.ID, dev.UDID, info.Version, hostLabel, cachedRP)
	if len(rpPlist) > 0 {
		if storage != nil {
			_ = storage.Set(cacheKey, rpPlist)
		}
		return rpPlist, nil
	}
	if len(lockdownPlist) > 0 {
		return lockdownPlist, rpErr
	}
	return nil, rpErr
}

func loadOrCreateHostLabel(storage appleauth.Storage, udid string) string {
	key := "host_label_" + udid
	if storage != nil {
		if raw, err := storage.Get(key); err == nil && len(raw) > 0 {
			return string(raw)
		}
	}
	var b [3]byte
	_, _ = rand.Read(b[:])
	label := "koiside-" + hex.EncodeToString(b[:])
	if storage != nil {
		_ = storage.Set(key, []byte(label))
	}
	return label
}

func downloadFile(ctx context.Context, client *http.Client, url, dest string, onPct func(int)) error {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	total := resp.ContentLength
	var copied int64
	buf := make([]byte, 64*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				_ = f.Close()
				_ = os.Remove(tmp)
				return werr
			}
			copied += int64(n)
			if total > 0 && onPct != nil {
				onPct(int(copied * 100 / total))
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return readErr
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func localMachineName() string {
	host, err := os.Hostname()
	if err != nil {
		return "KoiSide"
	}
	host = strings.TrimSpace(strings.TrimSuffix(host, ".local"))
	var b strings.Builder
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == ' ' {
			b.WriteRune(r)
		}
	}
	clean := strings.TrimSpace(b.String())
	if clean == "" {
		return "KoiSide"
	}
	return "KoiSide (" + clean + ")"
}
