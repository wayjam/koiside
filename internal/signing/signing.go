// Package signing implements pure-Go iOS code signing for .app bundles and IPAs,
// including Provisioning Profile parsing, DER entitlements, CMS PKCS#7 signatures,
// CodeResources sealing, and SideStore/LiveContainer bundle configuration.
package signing

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"

	"koiside/internal/devportal"
	"koiside/internal/ipa"
)

// Request is what a later signer needs. It carries no private key.
type Request struct {
	InputPath string
	BundleID  string
}

// Result is a signed archive or extracted .app directory. Producing one does not mean it was installed.
type Result struct {
	OutputPath  string
	AppDir      string
	BundleID    string
	ProfileUUID string
	Special     SpecialApp
}

// Service signs an archive.
type Service interface {
	Sign(ctx context.Context, req Request) (Result, error)
}

// Material is the device proof a service needs. Store SAP and SideStore
// Anisette v3 are different providers and must not be treated as one format.
type Material struct {
	Service string
}

// AnisetteProvider supplies proof material for one service.
type AnisetteProvider interface {
	Material(ctx context.Context, service string) (Material, error)
}

// SpecialApp identifies sideloading tools needing certificate/app-group/pairing injection.
type SpecialApp string

const (
	SpecialNone          SpecialApp = ""
	SpecialSideStore     SpecialApp = "SideStore"
	SpecialSideStoreLC   SpecialApp = "SideStore+LiveContainer"
	SpecialLiveContainer SpecialApp = "LiveContainer"
	SpecialAltStore      SpecialApp = "AltStore"
	SpecialStikStore     SpecialApp = "StikStore"
)

// ErrRecoveryBundleIDMismatch indicates that the normal signing identifier cannot update the installed app.
var ErrRecoveryBundleIDMismatch = errors.New("signing: recovery bundle identifier mismatch")

// PortalSignOptions configures full Developer Portal provisioning + code signing for an IPA or .app.
type PortalSignOptions struct {
	InputPath             string
	WorkDir               string
	DeviceName            string
	DeviceUDID            string
	Team                  devportal.Team
	Portal                *devportal.Session
	EnsureCertificate     func(context.Context) (*devportal.CertificateIdentity, error)
	IncreasedMemoryLimit  bool
	RegisterAllExtensions bool
	RecoveryBundleID      string // require the combined app to sign with this exact identifier
	OnProgress            func(pct float64, stage string)
}

// DetectSpecialApp checks the bundle ID and embedded frameworks for SideStore / LiveContainer / AltStore.
func DetectSpecialApp(appDir string) SpecialApp {
	mainID := readBundleIdentifier(filepath.Join(appDir, "Info.plist"))
	switch mainID {
	case "com.rileytestut.AltStore":
		return SpecialAltStore
	case "com.SideStore.SideStore":
		return SpecialSideStore
	case "app.stik.store":
		return SpecialStikStore
	}
	fwEntries, err := os.ReadDir(filepath.Join(appDir, "Frameworks"))
	if err == nil {
		for _, e := range fwEntries {
			if e.IsDir() && strings.HasSuffix(e.Name(), ".framework") {
				if readBundleIdentifier(filepath.Join(appDir, "Frameworks", e.Name(), "Info.plist")) == "com.SideStore.SideStore" {
					return SpecialSideStoreLC
				}
			}
		}
	}
	if mainID == "com.kdt.livecontainer" {
		return SpecialLiveContainer
	}
	return SpecialNone
}

// SignIPAWithPortal extracts an IPA (or uses an .app directory), registers Device/AppIDs/AppGroup,
// downloads provisioning profiles, injects SideStore/LiveContainer certificate & entitlements,
// and signs all Mach-O executables and nested frameworks/plugins.
func SignIPAWithPortal(ctx context.Context, opts PortalSignOptions) (Result, error) {
	if opts.Portal == nil || opts.EnsureCertificate == nil {
		return Result{}, errors.New("signing: portal session and certificate provider required")
	}
	report := func(pct float64, stage string) {
		if opts.OnProgress != nil {
			opts.OnProgress(pct, stage)
		}
	}

	report(0.05, "extract")
	appDir, cleanupDir, err := prepareAppDir(opts.InputPath, opts.WorkDir)
	if err != nil {
		return Result{}, err
	}
	_ = cleanupDir

	special := DetectSpecialApp(appDir)
	mainInfoPath := filepath.Join(appDir, "Info.plist")
	mainPlist, err := readPlistDict(mainInfoPath)
	if err != nil {
		return Result{}, fmt.Errorf("signing: read main Info.plist: %w", err)
	}
	origMainID, _ := mainPlist["CFBundleIdentifier"].(string)
	if origMainID == "" {
		return Result{}, errors.New("signing: missing CFBundleIdentifier in Info.plist")
	}
	appName, _ := mainPlist["CFBundleName"].(string)
	if appName == "" {
		appName, _ = mainPlist["CFBundleDisplayName"].(string)
	}
	if appName == "" {
		appName = "KoiSideApp"
	}

	newMainID := origMainID
	if !strings.HasSuffix(origMainID, "."+opts.Team.TeamID) {
		newMainID = origMainID + "." + opts.Team.TeamID
	}
	if opts.RecoveryBundleID != "" {
		if special != SpecialSideStoreLC {
			return Result{}, errors.New("signing: recovery requires the combined LiveContainer + SideStore IPA")
		}
		if newMainID != opts.RecoveryBundleID {
			return Result{}, fmt.Errorf("%w. Installed bundle ID %q differs from KoiSide's signed bundle ID %q. Use the installer that originally signed this copy", ErrRecoveryBundleIDMismatch, opts.RecoveryBundleID, newMainID)
		}
	}

	cert, err := opts.EnsureCertificate(ctx)
	if err != nil {
		return Result{}, err
	}
	if opts.DeviceUDID != "" {
		report(0.10, "register_device")
		if err := opts.Portal.EnsureDeviceRegistered(ctx, opts.Team.TeamID, opts.DeviceName, opts.DeviceUDID); err != nil {
			return Result{}, fmt.Errorf("signing: register device: %w", err)
		}
	}

	mainPlist["CFBundleIdentifier"] = newMainID
	if bgTasks, ok := mainPlist["BGTaskSchedulerPermittedIdentifiers"].([]any); ok {
		for i, item := range bgTasks {
			if s, ok := item.(string); ok && strings.Contains(s, origMainID) {
				bgTasks[i] = strings.ReplaceAll(s, origMainID, newMainID)
			}
		}
		mainPlist["BGTaskSchedulerPermittedIdentifiers"] = bgTasks
	}
	extensions := findExtensionDirs(appDir)
	for _, extDir := range extensions {
		extInfoPath := filepath.Join(extDir, "Info.plist")
		extDict, err := readPlistDict(extInfoPath)
		if err != nil {
			continue
		}
		extID, _ := extDict["CFBundleIdentifier"].(string)
		if extID != "" && strings.HasPrefix(extID, origMainID) && len(extID) > len(origMainID) {
			extDict["CFBundleIdentifier"] = newMainID + extID[len(origMainID):]
			_ = writePlistDict(extInfoPath, extDict)
		}
	}
	if err := writePlistDict(mainInfoPath, mainPlist); err != nil {
		return Result{}, err
	}

	report(0.20, "register_app_ids")
	targetIDs := []struct {
		id   string
		name string
	}{{id: newMainID, name: appName}}
	if opts.RegisterAllExtensions {
		for _, extDir := range extensions {
			extDict, err := readPlistDict(filepath.Join(extDir, "Info.plist"))
			if err != nil {
				continue
			}
			extID, _ := extDict["CFBundleIdentifier"].(string)
			extName, _ := extDict["CFBundleName"].(string)
			if extID != "" {
				targetIDs = append(targetIDs, struct {
					id   string
					name string
				}{id: extID, name: extName})
			}
		}
	}

	existingIDs, err := opts.Portal.ListAppIDs(ctx, opts.Team.TeamID)
	if err != nil {
		return Result{}, err
	}
	idByBundle := map[string]devportal.AppID{}
	for _, a := range existingIDs.AppIDs {
		idByBundle[a.Identifier] = a
	}

	var missing []struct {
		id   string
		name string
	}
	for _, t := range targetIDs {
		if _, ok := idByBundle[t.id]; !ok {
			missing = append(missing, t)
		}
	}
	if existingIDs.HasAvailable && int64(len(missing)) > existingIDs.AvailableQuantity {
		return Result{}, fmt.Errorf("signing: need %d App ID(s), but only %d available on free team", len(missing), existingIDs.AvailableQuantity)
	}
	for _, m := range missing {
		added, err := opts.Portal.AddAppID(ctx, opts.Team.TeamID, m.name, m.id)
		if err != nil {
			return Result{}, fmt.Errorf("signing: add App ID %s: %w", m.id, err)
		}
		idByBundle[added.Identifier] = added
	}

	groupID := "group." + newMainID
	if special == SpecialSideStoreLC {
		groupID = "group.com.SideStore.SideStore." + opts.Team.TeamID
	}
	appGroup, err := opts.Portal.EnsureAppGroup(ctx, opts.Team.TeamID, appName, groupID)
	if err != nil {
		return Result{}, fmt.Errorf("signing: ensure app group: %w", err)
	}

	for _, t := range targetIDs {
		aid := idByBundle[t.id]
		if err := opts.Portal.EnsureAppGroupFeature(ctx, opts.Team.TeamID, &aid); err != nil {
			return Result{}, fmt.Errorf("signing: enable app group feature for %s: %w", t.id, err)
		}
		if err := opts.Portal.AssignAppGroup(ctx, opts.Team.TeamID, appGroup.ApplicationGroup, aid.AppIDID); err != nil {
			return Result{}, fmt.Errorf("signing: assign app group for %s: %w", t.id, err)
		}
		if opts.IncreasedMemoryLimit {
			_ = opts.Portal.AddIncreasedMemoryLimit(ctx, opts.Team.TeamID, aid)
		}
	}

	report(0.35, "special_app")
	if err := applySpecialAppInjection(appDir, special, groupID, cert); err != nil {
		return Result{}, err
	}

	report(0.45, "profiles")
	mainAid := idByBundle[newMainID]
	mainProfRaw, err := opts.Portal.DownloadTeamProvisioningProfile(ctx, opts.Team.TeamID, mainAid.AppIDID)
	if err != nil {
		return Result{}, fmt.Errorf("signing: download main provisioning profile: %w", err)
	}
	mainProf, err := ParseProvisioningProfile(mainProfRaw.EncodedProfile)
	if err != nil {
		return Result{}, err
	}

	extProfiles := map[string]*ProvisioningProfile{}
	for _, extDir := range extensions {
		extID := readBundleIdentifier(filepath.Join(extDir, "Info.plist"))
		if extID == "" {
			continue
		}
		if opts.RegisterAllExtensions {
			if aid, ok := idByBundle[extID]; ok {
				prof, err := opts.Portal.DownloadTeamProvisioningProfile(ctx, opts.Team.TeamID, aid.AppIDID)
				if err == nil {
					if parsed, perr := ParseProvisioningProfile(prof.EncodedProfile); perr == nil {
						extProfiles[extID] = parsed
						continue
					}
				}
			}
		}
		extProfiles[extID] = mainProf
	}

	report(0.55, "codesign")
	if err := SignAppBundle(appDir, BundleSignConfig{
		TeamID:      opts.Team.TeamID,
		Cert:        cert,
		MainProfile: mainProf,
		ExtProfiles: extProfiles,
		Special:     special,
	}); err != nil {
		return Result{}, err
	}

	report(0.70, "signed")
	return Result{
		OutputPath:  appDir,
		AppDir:      appDir,
		BundleID:    newMainID,
		ProfileUUID: mainProf.UUID,
		Special:     special,
	}, nil
}

// BundleSignConfig configures pure-Go code signing of an extracted .app bundle.
type BundleSignConfig struct {
	TeamID      string
	Cert        *devportal.CertificateIdentity
	MainProfile *ProvisioningProfile
	ExtProfiles map[string]*ProvisioningProfile
	Special     SpecialApp
}

// SignAppBundle signs all frameworks, dynamic libraries, app extensions, and the main app bundle.
func SignAppBundle(appDir string, cfg BundleSignConfig) error {
	if cfg.Cert == nil || cfg.MainProfile == nil {
		return errors.New("signing: certificate and main provisioning profile required")
	}
	chain := CertificateChainFor(cfg.Cert.Certificate, cfg.MainProfile.Certs)

	// 1. Collect nested bundles (frameworks and .appex), deepest first so parent CodeResources hashes signed children.
	var nested []string
	_ = filepath.WalkDir(appDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() || p == appDir {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".framework") || strings.HasSuffix(d.Name(), ".appex") {
			nested = append(nested, p)
		}
		return nil
	})
	// Deepest paths first
	for i := 0; i < len(nested); i++ {
		for j := i + 1; j < len(nested); j++ {
			if len(nested[j]) > len(nested[i]) {
				nested[i], nested[j] = nested[j], nested[i]
			}
		}
	}

	// Sign standalone dylibs first
	_ = filepath.WalkDir(appDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".dylib") {
			if signErr := SignMachOFile(p, BinarySignOptions{
				Identifier: d.Name(),
				TeamID:     cfg.TeamID,
				Key:        cfg.Cert.PrivateKey,
				LeafCert:   cfg.Cert.Certificate,
				CertChain:  chain,
			}); signErr != nil {
				return signErr
			}
		}
		return nil
	})

	for _, childDir := range nested {
		infoPath := filepath.Join(childDir, "Info.plist")
		infoRaw, err := os.ReadFile(infoPath)
		if err != nil {
			continue
		}
		dict, err := readPlistDict(infoPath)
		if err != nil {
			continue
		}
		bundleID, _ := dict["CFBundleIdentifier"].(string)
		execName, _ := dict["CFBundleExecutable"].(string)
		if execName == "" {
			execName = strings.TrimSuffix(filepath.Base(childDir), filepath.Ext(childDir))
		}
		execPath := filepath.Join(childDir, execName)
		if _, err := os.Stat(execPath); err != nil {
			continue
		}

		isExt := strings.HasSuffix(childDir, ".appex")
		var prof *ProvisioningProfile
		var ent map[string]any
		var entXML []byte
		if isExt {
			prof = cfg.ExtProfiles[bundleID]
			if prof == nil {
				prof = cfg.MainProfile
			}
			_ = os.WriteFile(filepath.Join(childDir, "embedded.mobileprovision"), prof.Raw, 0o644)
			ent = cloneEntitlements(prof.Entitlements)
			if cfg.Special == SpecialSideStoreLC || cfg.Special == SpecialLiveContainer {
				if strings.HasSuffix(bundleID, "LiveProcess") {
					ent["keychain-access-groups"] = liveContainerSharedGroups(cfg.TeamID)
				}
			}
			entXML, _ = plist.Marshal(ent, plist.XMLFormat)
		}

		codeResRaw, err := BuildCodeResources(childDir, execName)
		if err != nil {
			return err
		}
		_ = os.MkdirAll(filepath.Join(childDir, "_CodeSignature"), 0o755)
		if err := os.WriteFile(filepath.Join(childDir, "_CodeSignature", "CodeResources"), codeResRaw, 0o644); err != nil {
			return err
		}

		if err := SignMachOFile(execPath, BinarySignOptions{
			Identifier:       bundleID,
			TeamID:           cfg.TeamID,
			IsMainExecutable: isExt,
			InfoPlistRaw:     infoRaw,
			CodeResourcesRaw: codeResRaw,
			Entitlements:     ent,
			EntitlementsXML:  entXML,
			Key:              cfg.Cert.PrivateKey,
			LeafCert:         cfg.Cert.Certificate,
			CertChain:        chain,
		}); err != nil {
			return fmt.Errorf("signing: sign nested %s: %w", filepath.Base(childDir), err)
		}
	}

	// 2. Embed main provisioning profile and compute main _CodeSignature/CodeResources.
	if err := os.WriteFile(filepath.Join(appDir, "embedded.mobileprovision"), cfg.MainProfile.Raw, 0o644); err != nil {
		return err
	}
	mainInfoRaw, err := os.ReadFile(filepath.Join(appDir, "Info.plist"))
	if err != nil {
		return err
	}
	mainDict, err := readPlistDict(filepath.Join(appDir, "Info.plist"))
	if err != nil {
		return err
	}
	mainID, _ := mainDict["CFBundleIdentifier"].(string)
	mainExec, _ := mainDict["CFBundleExecutable"].(string)
	if mainExec == "" {
		return errors.New("signing: main Info.plist missing CFBundleExecutable")
	}

	codeResRaw, err := BuildCodeResources(appDir, mainExec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(appDir, "_CodeSignature"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(appDir, "_CodeSignature", "CodeResources"), codeResRaw, 0o644); err != nil {
		return err
	}

	mainEnt := cloneEntitlements(cfg.MainProfile.Entitlements)
	if cfg.Special == SpecialSideStoreLC || cfg.Special == SpecialLiveContainer {
		mainEnt["keychain-access-groups"] = liveContainerSharedGroups(cfg.TeamID)
	}
	mainEntXML, err := plist.Marshal(mainEnt, plist.XMLFormat)
	if err != nil {
		return err
	}

	return SignMachOFile(filepath.Join(appDir, mainExec), BinarySignOptions{
		Identifier:       mainID,
		TeamID:           cfg.TeamID,
		IsMainExecutable: true,
		InfoPlistRaw:     mainInfoRaw,
		CodeResourcesRaw: codeResRaw,
		Entitlements:     mainEnt,
		EntitlementsXML:  mainEntXML,
		Key:              cfg.Cert.PrivateKey,
		LeafCert:         cfg.Cert.Certificate,
		CertChain:        chain,
	})
}

func applySpecialAppInjection(appDir string, special SpecialApp, groupID string, cert *devportal.CertificateIdentity) error {
	if special == SpecialNone {
		return nil
	}
	if special == SpecialSideStore || special == SpecialSideStoreLC || special == SpecialAltStore || special == SpecialStikStore {
		if special != SpecialStikStore {
			infoPath := filepath.Join(appDir, "Info.plist")
			if dict, err := readPlistDict(infoPath); err == nil {
				dict["ALTAppGroups"] = []string{groupID}
				_ = writePlistDict(infoPath, dict)
			}
			for _, extDir := range findExtensionDirs(appDir) {
				extInfo := filepath.Join(extDir, "Info.plist")
				if dict, err := readPlistDict(extInfo); err == nil {
					dict["ALTAppGroups"] = []string{groupID}
					_ = writePlistDict(extInfo, dict)
				}
			}
		}

		targetDir := appDir
		if special == SpecialSideStoreLC {
			fwEntries, _ := os.ReadDir(filepath.Join(appDir, "Frameworks"))
			for _, e := range fwEntries {
				if e.IsDir() && strings.HasSuffix(e.Name(), ".framework") {
					fwPath := filepath.Join(appDir, "Frameworks", e.Name())
					if readBundleIdentifier(filepath.Join(fwPath, "Info.plist")) == "com.SideStore.SideStore" {
						targetDir = fwPath
						break
					}
				}
			}
		}

		idKey := "ALTCertificateID"
		certFile := "ALTCertificate.p12"
		if special == SpecialStikStore {
			idKey = "MachineID"
			certFile = "Certificate.p12"
		}
		targetInfo := filepath.Join(targetDir, "Info.plist")
		if dict, err := readPlistDict(targetInfo); err == nil {
			dict[idKey] = cert.SerialNumberHex()
			_ = writePlistDict(targetInfo, dict)
		}
		p12Bytes, err := cert.ExportP12(cert.MachineID)
		if err != nil {
			return fmt.Errorf("signing: encode %s: %w", certFile, err)
		}
		if err := os.WriteFile(filepath.Join(targetDir, certFile), p12Bytes, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func liveContainerSharedGroups(teamID string) []string {
	out := make([]string, 0, 128)
	out = append(out, teamID+".com.kdt.livecontainer.shared")
	for i := 1; i < 128; i++ {
		out = append(out, fmt.Sprintf("%s.com.kdt.livecontainer.shared.%d", teamID, i))
	}
	return out
}

func prepareAppDir(inputPath, workDir string) (string, string, error) {
	st, err := os.Stat(inputPath)
	if err != nil {
		return "", "", err
	}
	if st.IsDir() && strings.HasSuffix(inputPath, ".app") {
		return inputPath, "", nil
	}
	if workDir == "" {
		workDir, err = os.MkdirTemp("", "koiside-sign-*")
		if err != nil {
			return "", "", err
		}
	} else {
		if err := os.MkdirAll(workDir, 0o755); err != nil {
			return "", workDir, err
		}
	}

	zr, err := zip.OpenReader(inputPath)
	if err != nil {
		return "", workDir, err
	}
	defer zr.Close()

	cleanWork := filepath.Clean(workDir)
	if err := ipa.ExtractZIP(&zr.Reader, cleanWork); err != nil {
		return "", workDir, fmt.Errorf("signing: safely extract IPA: %w", err)
	}

	payloadDir := filepath.Join(cleanWork, "Payload")
	entries, err := os.ReadDir(payloadDir)
	if err != nil {
		return "", workDir, fmt.Errorf("signing: missing Payload directory in %s", filepath.Base(inputPath))
	}
	var appDirs []string
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".app") {
			appDirs = append(appDirs, filepath.Join(payloadDir, e.Name()))
		}
	}
	if len(appDirs) != 1 {
		return "", workDir, fmt.Errorf("signing: expected 1 .app in Payload, found %d", len(appDirs))
	}
	return appDirs[0], workDir, nil
}

func findExtensionDirs(appDir string) []string {
	var out []string
	entries, err := os.ReadDir(filepath.Join(appDir, "PlugIns"))
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".appex") {
			out = append(out, filepath.Join(appDir, "PlugIns", e.Name()))
		}
	}
	return out
}

func readBundleIdentifier(infoPath string) string {
	d, err := readPlistDict(infoPath)
	if err != nil {
		return ""
	}
	s, _ := d["CFBundleIdentifier"].(string)
	return s
}

func readPlistDict(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d map[string]any
	if _, err := plist.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	if d == nil {
		d = map[string]any{}
	}
	return d, nil
}

func writePlistDict(path string, dict map[string]any) error {
	raw, err := plist.Marshal(dict, plist.XMLFormat)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func cloneEntitlements(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		switch typed := v.(type) {
		case []any:
			cp := make([]any, len(typed))
			copy(cp, typed)
			out[k] = cp
		default:
			out[k] = typed
		}
	}
	return out
}

// Unused import guard for x509 / bytes if stripped in future edits.
var (
	_ = bytes.Equal
	_ = x509.ParseCertificate
)
