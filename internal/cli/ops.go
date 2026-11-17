package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"koiside/internal/account"
	"koiside/internal/appleauth"
	"koiside/internal/device"
	"koiside/internal/devportal"
	"koiside/internal/installer"
	"koiside/internal/ipa"
	"koiside/internal/task"
)

// Exit codes for the CLI.
const (
	ExitOK             = 0
	ExitError          = 1
	ExitUsage          = 2
	ExitActionRequired = 3
)

// ActionRequiredError indicates the operation stopped safely because a human
// step is required (Apple ID login/2FA, iPhone Trust prompt, Developer Mode, etc.).
type ActionRequiredError struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Next    string `json:"next"`
	Details any    `json:"details,omitempty"`
}

func (e *ActionRequiredError) Error() string {
	return fmt.Sprintf("action_required (%s): %s Next: %s", e.Reason, e.Message, e.Next)
}

// Deps injects runtime dependencies for CLI and MCP handlers so tests can use fakes.
type Deps struct {
	Accounts   account.Manager
	Probe      func() (device.Snapshot, error)
	Dial       device.Dialer
	CacheDir   string
	HTTPClient interface{}
}

func defaultDeps() Deps {
	cacheDir := filepath.Join(os.TempDir(), "koiside-downloads")
	if home, err := os.UserHomeDir(); err == nil {
		cacheDir = filepath.Join(home, "Library", "Application Support", "KoiSide", "downloads")
	}
	return Deps{
		Accounts: account.NewLocalManager(nil),
		Probe:    func() (device.Snapshot, error) { return device.ProbeFirst(nil) },
		CacheDir: cacheDir,
	}
}

func (d Deps) withDefaults() Deps {
	def := defaultDeps()
	if d.Accounts == nil {
		d.Accounts = def.Accounts
	}
	if d.Probe == nil {
		d.Probe = def.Probe
	}
	if d.CacheDir == "" {
		d.CacheDir = def.CacheDir
	}
	return d
}

// IPAReportResult wraps ipa.Report without raw PNG bytes so agent responses stay compact.
type IPAReportResult struct {
	Path         string          `json:"path"`
	SHA256       string          `json:"sha256"`
	BundleID     string          `json:"bundle_id"`
	DisplayName  string          `json:"display_name"`
	Version      string          `json:"version"`
	Build        string          `json:"build,omitempty"`
	HasIcon      bool            `json:"has_icon"`
	Components   []ipa.Component `json:"components"`
	MachOs       []ipa.MachO     `json:"machos"`
	Dylibs       []string        `json:"dylibs,omitempty"`
	Findings     []ipa.Finding   `json:"findings,omitempty"`
	HasSinf      bool            `json:"has_sinf,omitempty"`
	HasStoreMeta bool            `json:"has_store_meta,omitempty"`
}

func InspectIPA(path string) (IPAReportResult, error) {
	if strings.TrimSpace(path) == "" {
		return IPAReportResult{}, errors.New("ipa path is required")
	}
	rep, err := ipa.Inspect(path)
	if err != nil {
		return IPAReportResult{}, err
	}
	return IPAReportResult{
		Path:         path,
		SHA256:       rep.SHA256,
		BundleID:     rep.BundleID,
		DisplayName:  rep.DisplayName,
		Version:      rep.Version,
		Build:        rep.Build,
		HasIcon:      len(rep.IconPNG) > 0,
		Components:   rep.Components,
		MachOs:       rep.MachOs,
		Dylibs:       rep.Dylibs,
		Findings:     rep.Findings,
		HasSinf:      rep.HasSinf,
		HasStoreMeta: rep.HasStoreMeta,
	}, nil
}

type PrepareIPARequest struct {
	InputPath     string   `json:"input_path"`
	OutputPath    string   `json:"output_path,omitempty"`
	DisplayName   string   `json:"display_name,omitempty"`
	BundleID      string   `json:"bundle_id,omitempty"`
	LocalizedName string   `json:"localized_name,omitempty"`
	Remove        []string `json:"remove_components,omitempty"`
	PreviewOnly   bool     `json:"preview_only,omitempty"`
}

type PrepareIPAResult struct {
	PreviewOnly bool         `json:"preview_only"`
	InputPath   string       `json:"input_path"`
	Diff        ipa.Diff     `json:"diff"`
	Exported    *task.Record `json:"exported,omitempty"`
}

func PrepareIPA(req PrepareIPARequest) (PrepareIPAResult, error) {
	if strings.TrimSpace(req.InputPath) == "" {
		return PrepareIPAResult{}, errors.New("input_path is required")
	}
	rep, err := ipa.Inspect(req.InputPath)
	if err != nil {
		return PrepareIPAResult{}, err
	}
	change := ipa.Change{
		DisplayName:   strings.TrimSpace(req.DisplayName),
		BundleID:      strings.TrimSpace(req.BundleID),
		LocalizedName: strings.TrimSpace(req.LocalizedName),
		Remove:        req.Remove,
	}
	diff := ipa.Preview(rep, change)
	res := PrepareIPAResult{
		PreviewOnly: req.PreviewOnly,
		InputPath:   req.InputPath,
		Diff:        diff,
	}
	if req.PreviewOnly {
		return res, nil
	}
	outPath := strings.TrimSpace(req.OutputPath)
	if outPath == "" {
		return PrepareIPAResult{}, errors.New("output_path is required when preview_only is false")
	}
	rec, err := ipa.Export(req.InputPath, outPath, change)
	if err != nil {
		return PrepareIPAResult{}, err
	}
	res.Exported = &rec
	return res, nil
}

type DeviceStatusResult struct {
	Connected            bool                        `json:"connected"`
	Device               *device.Device              `json:"device,omitempty"`
	Info                 *device.Info                `json:"info,omitempty"`
	DeveloperModeKnown   bool                        `json:"developer_mode_known"`
	DeveloperModeEnabled bool                        `json:"developer_mode_enabled"`
	SideStore            *device.InstalledApp        `json:"sidestore,omitempty"`
	SideStoreEmbedded    bool                        `json:"sidestore_embedded,omitempty"`
	LocalDevVPN          *device.InstalledApp        `json:"localdevvpn,omitempty"`
	LiveContainer        *device.InstalledApp        `json:"livecontainer,omitempty"`
	USBVerified          bool                        `json:"usb_verified"`
	DocsBundleID         string                      `json:"docs_bundle_id,omitempty"`
	Docs                 []string                    `json:"docs,omitempty"`
	DocsTree             []device.DocEntry           `json:"docs_tree,omitempty"`
	LiveContainerApps    []device.LiveContainerApp   `json:"live_container_apps,omitempty"`
	LatestSideStoreLog   *device.SideStoreLogSummary `json:"latest_sidestore_log,omitempty"`
	TotalApps            int                         `json:"total_apps"`
	SideloadedApps       int                         `json:"sideloaded_apps"`
	SessionError         string                      `json:"session_error,omitempty"`
}

func GetDeviceStatus(d Deps) (DeviceStatusResult, error) {
	d = d.withDefaults()
	snap, err := d.Probe()
	if err != nil {
		return DeviceStatusResult{}, err
	}
	if snap.Device.ID == 0 && snap.Device.UDID == "" {
		return DeviceStatusResult{Connected: false}, nil
	}
	devCopy := snap.Device
	infoCopy := snap.Info
	res := DeviceStatusResult{
		Connected:            true,
		Device:               &devCopy,
		Info:                 &infoCopy,
		DeveloperModeKnown:   snap.DeveloperModeKnown,
		DeveloperModeEnabled: snap.DeveloperModeEnabled,
		SideStore:            snap.SideStore,
		SideStoreEmbedded:    snap.SideStoreEmbedded,
		LocalDevVPN:          snap.LocalDevVPN,
		LiveContainer:        snap.LiveContainer,
		DocsBundleID:         snap.DocsBundleID,
		Docs:                 snap.SideStoreDocs,
		DocsTree:             snap.SideStoreTree,
		LiveContainerApps:    snap.LiveContainerApps,
		LatestSideStoreLog:   snap.LatestSideStoreLog,
		TotalApps:            len(snap.Apps),
		SideloadedApps:       len(filterSideloadedApps(snap)),
	}
	if snap.SessionErr != nil {
		res.SessionError = snap.SessionErr.Error()
	}
	return res, nil
}

func filterSideloadedApps(snap device.Snapshot) []device.InstalledApp {
	var out []device.InstalledApp
	for _, a := range snap.Apps {
		isDev := strings.Contains(a.Signer, "Developer") || strings.Contains(a.Signer, "Development")
		sameSide := snap.SideStore != nil && snap.SideStore.TeamID != "" && a.TeamID == snap.SideStore.TeamID
		sameLC := snap.LiveContainer != nil && snap.LiveContainer.TeamID != "" && a.TeamID == snap.LiveContainer.TeamID
		if isDev || sameSide || sameLC {
			out = append(out, a)
		}
	}
	return out
}

type ListDeviceAppsResult struct {
	SideloadedOnly    bool                      `json:"sideloaded_only"`
	Apps              []device.InstalledApp     `json:"apps"`
	LiveContainerApps []device.LiveContainerApp `json:"live_container_apps,omitempty"`
}

func ListDeviceApps(d Deps, sideloadedOnly bool) (ListDeviceAppsResult, error) {
	d = d.withDefaults()
	snap, err := requireTrustedDevice(d)
	if err != nil {
		return ListDeviceAppsResult{}, err
	}
	apps := snap.Apps
	if sideloadedOnly {
		apps = filterSideloadedApps(snap)
	}
	return ListDeviceAppsResult{
		SideloadedOnly:    sideloadedOnly,
		Apps:              apps,
		LiveContainerApps: snap.LiveContainerApps,
	}, nil
}

func EnableDeveloperMode(d Deps) (map[string]any, error) {
	d = d.withDefaults()
	snap, err := requireConnectedDevice(d)
	if err != nil {
		return nil, err
	}
	sess, err := device.DialSession(d.Dial, snap.Device.ID, snap.Device.UDID)
	if err != nil {
		return nil, mapDeviceSessionErr(err)
	}
	defer sess.Close()
	if err := sess.RevealDeveloperMode(); err != nil {
		return nil, err
	}
	_ = sess.EnableDeveloperMode()
	return map[string]any{
		"status":  "revealed",
		"udid":    snap.Device.UDID,
		"message": "Developer Mode switch revealed in iPhone Settings -> Privacy & Security -> Developer Mode. Toggle on and reboot iPhone to confirm.",
	}, nil
}

type TransferResult struct {
	TargetBundleID string `json:"target_bundle_id"`
	RemotePath     string `json:"remote_path"`
	SHA256         string `json:"sha256"`
}

func TransferIPA(d Deps, ipaPath, target string) (TransferResult, error) {
	d = d.withDefaults()
	if strings.TrimSpace(ipaPath) == "" {
		return TransferResult{}, errors.New("ipa path is required")
	}
	if st, err := os.Stat(ipaPath); err != nil || st.IsDir() {
		return TransferResult{}, fmt.Errorf("ipa not found: %s", ipaPath)
	}
	snap, err := requireTrustedDevice(d)
	if err != nil {
		return TransferResult{}, err
	}
	target = strings.ToLower(strings.TrimSpace(target))
	var bundleID string
	switch target {
	case "", "auto":
		if snap.SideStore != nil && snap.SideStore.BundleID != "" {
			bundleID = snap.SideStore.BundleID
		} else if snap.LiveContainer != nil && snap.LiveContainer.BundleID != "" {
			bundleID = snap.LiveContainer.BundleID
		}
	case "sidestore":
		if snap.SideStore != nil {
			bundleID = snap.SideStore.BundleID
		}
	case "livecontainer", "lc":
		if snap.LiveContainer != nil {
			bundleID = snap.LiveContainer.BundleID
		}
	default:
		return TransferResult{}, fmt.Errorf("unknown transfer target %q (want auto, sidestore, or livecontainer)", target)
	}
	if bundleID == "" {
		return TransferResult{}, &ActionRequiredError{
			Reason:  "missing_companion_app",
			Message: "Neither SideStore nor LiveContainer was detected on the connected iPhone.",
			Next:    "Install SideStore or LiveContainer+SideStore first (e.g. `koiside install lc-ss`).",
		}
	}
	tr := device.USBTransfer{
		Dial:     d.Dial,
		DeviceID: snap.Device.ID,
		UDID:     snap.Device.UDID,
		BundleID: bundleID,
	}
	res, err := tr.PutIPA(ipaPath)
	if err != nil {
		return TransferResult{}, err
	}
	return TransferResult{
		TargetBundleID: bundleID,
		RemotePath:     res.Path,
		SHA256:         res.SHA256,
	}, nil
}

type DocsManageResult struct {
	Action       string            `json:"action"`
	DocsBundleID string            `json:"docs_bundle_id"`
	Entries      []device.DocEntry `json:"entries,omitempty"`
	DeletedPath  string            `json:"deleted_path,omitempty"`
}

func ManageDeviceDocs(d Deps, action, remotePath string) (DocsManageResult, error) {
	d = d.withDefaults()
	snap, err := requireTrustedDevice(d)
	if err != nil {
		return DocsManageResult{}, err
	}
	bundleID := snap.DocsBundleID
	if bundleID == "" {
		if snap.SideStore != nil {
			bundleID = snap.SideStore.BundleID
		} else if snap.LiveContainer != nil {
			bundleID = snap.LiveContainer.BundleID
		}
	}
	if bundleID == "" {
		return DocsManageResult{}, &ActionRequiredError{
			Reason:  "missing_companion_app",
			Message: "No accessible SideStore or LiveContainer documents container detected.",
			Next:    "Install SideStore or LiveContainer+SideStore first.",
		}
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "list", "ls":
		return DocsManageResult{
			Action:       "list",
			DocsBundleID: bundleID,
			Entries:      snap.SideStoreTree,
		}, nil
	case "delete", "rm":
		if strings.TrimSpace(remotePath) == "" {
			return DocsManageResult{}, errors.New("remote_path is required for delete")
		}
		if err := device.RemoveDocPath(d.Dial, snap.Device.ID, snap.Device.UDID, bundleID, remotePath); err != nil {
			return DocsManageResult{}, err
		}
		return DocsManageResult{
			Action:       "delete",
			DocsBundleID: bundleID,
			DeletedPath:  remotePath,
		}, nil
	default:
		return DocsManageResult{}, fmt.Errorf("unknown docs action %q (want list or delete)", action)
	}
}

type PairingResult struct {
	ExportPath string   `json:"export_path,omitempty"`
	Placed     []string `json:"placed,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

func PlacePairing(d Deps, exportPath string) (PairingResult, error) {
	d = d.withDefaults()
	snap, err := requireTrustedDevice(d)
	if err != nil {
		return PairingResult{}, err
	}
	storage := d.Accounts.Storage()
	if strings.TrimSpace(exportPath) != "" {
		raw, err := installer.ExportPairingBytes(d.Dial, snap.Device, snap.Info, storage)
		if err != nil && len(raw) == 0 {
			return PairingResult{}, err
		}
		if err := os.WriteFile(exportPath, raw, 0o600); err != nil {
			return PairingResult{}, err
		}
		var warns []string
		if err != nil {
			warns = append(warns, err.Error())
		}
		return PairingResult{ExportPath: exportPath, Warnings: warns}, nil
	}
	targets := device.DetectPairingTargets(snap.Apps)
	if len(targets) == 0 {
		return PairingResult{}, &ActionRequiredError{
			Reason:  "missing_companion_app",
			Message: "No pairing-compatible app (SideStore, LiveContainer, Feather, StikDebug, etc.) found on device.",
			Next:    "Install SideStore or LiveContainer+SideStore first.",
		}
	}
	var res PairingResult
	for _, tgt := range targets {
		if err := installer.PlacePairingToTarget(d.Dial, snap.Device, snap.Info, storage, tgt); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "pairing") && len(res.Placed) > 0 {
				res.Warnings = append(res.Warnings, tgt.Name+": "+err.Error())
				continue
			}
			res.Warnings = append(res.Warnings, tgt.Name+": "+err.Error())
		} else {
			res.Placed = append(res.Placed, tgt.Name+" ("+tgt.BundleID+")")
		}
	}
	if len(res.Placed) == 0 && len(res.Warnings) > 0 {
		return res, errors.New(strings.Join(res.Warnings, "; "))
	}
	return res, nil
}

type InstallResultJSON struct {
	Target               string `json:"target"`
	BundleID             string `json:"bundle_id"`
	PairingInjected      bool   `json:"pairing_injected"`
	PairingWarning       string `json:"pairing_warning,omitempty"`
	DeveloperModeKnown   bool   `json:"developer_mode_known"`
	DeveloperModeEnabled bool   `json:"developer_mode_enabled"`
	SignerTrusted        bool   `json:"signer_trusted"`
	Next                 string `json:"next,omitempty"`
}

func InstallIPA(ctx context.Context, d Deps, targetOrPath string, autoRevokeOldest bool, onProgress installer.Progress) (InstallResultJSON, error) {
	d = d.withDefaults()
	targetOrPath = strings.TrimSpace(targetOrPath)
	if targetOrPath == "" {
		return InstallResultJSON{}, errors.New("target or local .ipa path is required")
	}
	snap, err := requireTrustedDevice(d)
	if err != nil {
		return InstallResultJSON{}, err
	}
	if err := EnsureDeveloperSession(ctx, d.Accounts); err != nil {
		return InstallResultJSON{}, err
	}

	var target installer.ToolTarget
	var localPath string
	switch strings.ToLower(targetOrPath) {
	case "sidestore":
		target = installer.TargetSideStore
	case "sidestore-nightly":
		target = installer.TargetSideStoreNightly
	case "livecontainer-sidestore", "lc-ss", "lc+ss":
		target = installer.TargetLiveContainerLCSS
	case "livecontainer", "lc":
		target = installer.TargetLiveContainerOnly
	default:
		if st, statErr := os.Stat(targetOrPath); statErr != nil || st.IsDir() {
			return InstallResultJSON{}, fmt.Errorf("unknown target or missing IPA file: %s", targetOrPath)
		}
		target = installer.TargetCustomIPA
		localPath = targetOrPath
	}

	var maxCertsHit []devportal.DevelopmentCertificate
	res, err := installer.InstallDirect(ctx, installer.InstallRequest{
		Target:       target,
		LocalIPAPath: localPath,
		CacheDir:     d.CacheDir,
		Device:       snap.Device,
		DeviceInfo:   snap.Info,
		Accounts:     d.Accounts,
		DeviceDial:   d.Dial,
		OnProgress:   onProgress,
		OnMaxCerts: func(certs []devportal.DevelopmentCertificate) ([]string, error) {
			if autoRevokeOldest && len(certs) > 0 {
				return []string{certs[0].SerialNumber}, nil
			}
			maxCertsHit = certs
			return nil, nil
		},
	})
	if err != nil {
		if len(maxCertsHit) > 0 || errors.Is(err, devportal.ErrMaxCertificatesReached) {
			return InstallResultJSON{}, &ActionRequiredError{
				Reason:  "max_certs_reached",
				Message: "Apple Developer certificate limit reached on this team.",
				Next:    "Revoke an unused development certificate in KoiSide GUI -> Apple Account, or re-run with auto_revoke_oldest=true.",
				Details: maxCertsHit,
			}
		}
		return InstallResultJSON{}, err
	}

	next := "Open the installed app on iPhone. If Developer Mode or Developer App Trust has not been confirmed yet, approve it in iPhone Settings."
	if res.DeveloperModeKnown && !res.DeveloperModeEnabled {
		next = "Enable Settings -> Privacy & Security -> Developer Mode on iPhone and reboot, then trust your Apple ID under Settings -> General -> VPN & Device Management."
	}
	return InstallResultJSON{
		Target:               targetOrPath,
		BundleID:             res.BundleID,
		PairingInjected:      res.PairingInjected,
		PairingWarning:       res.PairingWarning,
		DeveloperModeKnown:   res.DeveloperModeKnown,
		DeveloperModeEnabled: res.DeveloperModeEnabled,
		SignerTrusted:        res.SignerTrusted,
		Next:                 next,
	}, nil
}

type CertSummary struct {
	Name         string `json:"name"`
	SerialNumber string `json:"serial_number"`
	MachineName  string `json:"machine_name"`
	Expiration   string `json:"expiration,omitempty"`
	HasLocalKey  bool   `json:"has_local_key"`
}

type AccountQuotaResult struct {
	SignedIn        bool              `json:"signed_in"`
	Email           string            `json:"email,omitempty"`
	FullName        string            `json:"full_name,omitempty"`
	AnisetteURL     string            `json:"anisette_url"`
	SavedAccounts   []string          `json:"saved_accounts,omitempty"`
	Team            *devportal.Team   `json:"team,omitempty"`
	TeamKind        string            `json:"team_kind,omitempty"`
	QuotaKnown      bool              `json:"quota_known"`
	AppIDsAvailable int64             `json:"app_ids_available"`
	AppIDsMax       int64             `json:"app_ids_max"`
	Certificates    []CertSummary     `json:"certificates,omitempty"`
	AppIDs          []devportal.AppID `json:"app_ids,omitempty"`
}

func GetAccountStatus(ctx context.Context, d Deps, includePortal bool) (AccountQuotaResult, error) {
	d = d.withDefaults()
	err := EnsureDeveloperSession(ctx, d.Accounts)
	if err != nil {
		var ar *ActionRequiredError
		if errors.As(err, &ar) && !includePortal {
			return AccountQuotaResult{
				SignedIn:      false,
				AnisetteURL:   d.Accounts.AnisetteURL(),
				SavedAccounts: d.Accounts.SavedAccounts(),
			}, nil
		}
		return AccountQuotaResult{}, err
	}
	dev := d.Accounts.Developer()
	res := AccountQuotaResult{
		SignedIn:      dev.SignedIn(),
		Email:         dev.Email(),
		FullName:      dev.FullName(),
		AnisetteURL:   d.Accounts.AnisetteURL(),
		SavedAccounts: d.Accounts.SavedAccounts(),
	}
	team, hasTeam := dev.ActiveTeam()
	if hasTeam {
		tCopy := team
		res.Team = &tCopy
		if team.IsFreePersonal() {
			res.TeamKind = "free_personal"
		} else {
			res.TeamKind = "paid"
		}
	}
	if !includePortal || !hasTeam {
		return res, nil
	}
	portal, err := d.Accounts.DeveloperPortal()
	if err != nil {
		return AccountQuotaResult{}, err
	}
	certs, err := portal.ListAllDevelopmentCerts(ctx, team.TeamID, true)
	if err != nil {
		return AccountQuotaResult{}, err
	}
	for _, c := range certs {
		exp := ""
		if !c.Expiration.IsZero() {
			exp = c.Expiration.UTC().Format("2006-01-02T15:04:05Z")
		}
		res.Certificates = append(res.Certificates, CertSummary{
			Name:         c.Name,
			SerialNumber: c.SerialNumber,
			MachineName:  c.MachineName,
			Expiration:   exp,
			HasLocalKey:  devportal.HasLocalRSAKeyForCert(dev.Email(), c, d.Accounts.Storage()),
		})
	}
	ids, err := portal.ListAppIDs(ctx, team.TeamID)
	if err != nil {
		return AccountQuotaResult{}, err
	}
	res.QuotaKnown = ids.HasAvailable
	res.AppIDsAvailable = ids.AvailableQuantity
	res.AppIDsMax = ids.MaxQuantity
	res.AppIDs = ids.AppIDs
	return res, nil
}

// EnsureDeveloperSession restores a cached Keychain SPD session (or password-less
// remembered account) without ever accepting plaintext passwords from CLI/MCP.
func EnsureDeveloperSession(ctx context.Context, mgr account.Manager) error {
	if mgr == nil {
		return &ActionRequiredError{
			Reason:  "needs_apple_signin",
			Message: "Account manager is unavailable.",
			Next:    "Open KoiSide GUI -> Apple Account and sign in first.",
		}
	}
	if mgr.Developer().SignedIn() {
		return nil
	}
	_ = mgr.RestoreDeveloperSession(ctx)
	if mgr.Developer().SignedIn() {
		return nil
	}
	if saved := mgr.SavedAccounts(); len(saved) > 0 {
		err := mgr.SignInSavedDeveloper(ctx, saved[0], nil)
		if err == nil && mgr.Developer().SignedIn() {
			return nil
		}
		if errors.Is(err, appleauth.Err2FARequired) {
			return &ActionRequiredError{
				Reason:  "needs_apple_signin",
				Message: fmt.Sprintf("Saved Apple ID %s requires interactive 2FA verification.", saved[0]),
				Next:    "Open KoiSide GUI -> Apple Account, click Sign In and complete 2FA, then retry.",
			}
		}
	}
	return &ActionRequiredError{
		Reason:  "needs_apple_signin",
		Message: "No active Apple Developer session in Keychain.",
		Next:    "Open KoiSide GUI -> Apple Account and sign in (including 2FA), then retry.",
	}
}

func requireConnectedDevice(d Deps) (device.Snapshot, error) {
	snap, err := d.Probe()
	if err != nil {
		return device.Snapshot{}, err
	}
	if snap.Device.ID == 0 && snap.Device.UDID == "" {
		return device.Snapshot{}, &ActionRequiredError{
			Reason:  "no_device",
			Message: "No iPhone detected over USB.",
			Next:    "Connect your iPhone via USB, unlock it, and retry.",
		}
	}
	return snap, nil
}

func requireTrustedDevice(d Deps) (device.Snapshot, error) {
	snap, err := requireConnectedDevice(d)
	if err != nil {
		return device.Snapshot{}, err
	}
	if snap.SessionErr != nil {
		return snap, mapDeviceSessionErr(snap.SessionErr)
	}
	return snap, nil
}

func mapDeviceSessionErr(err error) error {
	if errors.Is(err, device.ErrLocked) {
		return &ActionRequiredError{
			Reason:  "needs_device_unlock",
			Message: "iPhone is locked.",
			Next:    "Unlock your iPhone screen and retry.",
		}
	}
	if errors.Is(err, device.ErrUntrusted) {
		return &ActionRequiredError{
			Reason:  "needs_device_trust",
			Message: "iPhone has not trusted this Mac yet.",
			Next:    "Unlock your iPhone, tap 'Trust This Computer', enter your passcode, and retry.",
		}
	}
	return err
}
