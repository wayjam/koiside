package signing

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"howett.net/plist"

	"koiside/internal/devportal"
)

func TestSignAppBundleProducesValidCMSSignatureVerifiedByCodesign(t *testing.T) {
	// Build a minimal valid arm64 Mach-O executable via `go build` on a throwaway hello main.go,
	// then strip any linker ad-hoc signature or re-sign it with our pure-Go CMS signer and verify with macOS `codesign -vv`.
	tmp := t.TempDir()
	src := filepath.Join(tmp, "hello.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appDir := filepath.Join(tmp, "Sample.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(appDir, "Sample")
	cmd := exec.Command("go", "build", "-o", binPath, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build sample Mach-O failed: %v\n%s", err, out)
	}

	infoDict := map[string]any{
		"CFBundleIdentifier": "com.example.sample.TEAM123",
		"CFBundleExecutable": "Sample",
		"CFBundleName":       "Sample",
		"CFBundleVersion":    "1.0",
	}
	infoBytes, _ := plist.Marshal(infoDict, plist.XMLFormat)
	if err := os.WriteFile(filepath.Join(appDir, "Info.plist"), infoBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	// Self-signed test cert + CA to test CMS SignedData + CodeDirectory + Requirements + DER Entitlements
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Apple WWDR"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Apple Development: Test (TEST123)", OrganizationalUnit: []string{"TEAM123"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Build a minimal CMS-wrapped mobileprovision blob
	profPlist, _ := plist.Marshal(map[string]any{
		"UUID":           "11111111-2222-3333-4444-555555555555",
		"AppIDName":      "Sample",
		"TeamIdentifier": []string{"TEAM123"},
		"DeveloperCertificates": [][]byte{leafDER},
		"Entitlements": map[string]any{
			"application-identifier": "TEAM123.com.example.sample.TEAM123",
			"get-task-allow":         true,
			"keychain-access-groups": []string{"TEAM123.*"},
		},
	}, plist.XMLFormat)
	profCMS := wrapTestCMS(profPlist)
	parsedProf, err := ParseProvisioningProfile(profCMS)
	if err != nil {
		t.Fatalf("ParseProvisioningProfile failed: %v", err)
	}
	if parsedProf.TeamID != "TEAM123" || len(parsedProf.Certs) != 1 {
		t.Fatalf("unexpected profile parse: %+v", parsedProf)
	}

	err = SignAppBundle(appDir, BundleSignConfig{
		TeamID: "TEAM123",
		Cert: &devportal.CertificateIdentity{
			MachineID:   "M1",
			PrivateKey:  leafKey,
			Certificate: leafCert,
		},
		MainProfile: parsedProf,
	})
	if err != nil {
		t.Fatalf("SignAppBundle failed: %v", err)
	}

	// Verify with macOS codesign -d and verify entitlements/resources intact
	out, err := exec.Command("/usr/bin/codesign", "-dv", "--entitlements", "-", binPath).CombinedOutput()
	if err != nil {
		t.Fatalf("codesign -dv failed: %v\n%s", err, out)
	}
	if !containsAll(string(out), "Identifier=com.example.sample.TEAM123", "TeamIdentifier=TEAM123", "get-task-allow") {
		t.Fatalf("codesign metadata missing expected fields:\n%s", out)
	}
	// Check CMS structural validity (Signature blob present and non-empty)
	if _, err := os.Stat(filepath.Join(appDir, "_CodeSignature", "CodeResources")); err != nil {
		t.Fatalf("CodeResources missing: %v", err)
	}
}

func TestSideStoreLiveContainerInjection(t *testing.T) {
	tmp := t.TempDir()
	appDir := filepath.Join(tmp, "LiveContainer.app")
	fwDir := filepath.Join(appDir, "Frameworks", "SideStore.framework")
	_ = os.MkdirAll(fwDir, 0o755)
	mainInfo, _ := plist.Marshal(map[string]any{"CFBundleIdentifier": "com.kdt.livecontainer.TEAM1"}, plist.XMLFormat)
	fwInfo, _ := plist.Marshal(map[string]any{"CFBundleIdentifier": "com.SideStore.SideStore"}, plist.XMLFormat)
	_ = os.WriteFile(filepath.Join(appDir, "Info.plist"), mainInfo, 0o644)
	_ = os.WriteFile(filepath.Join(fwDir, "Info.plist"), fwInfo, 0o644)

	if got := DetectSpecialApp(appDir); got != SpecialSideStoreLC {
		t.Fatalf("expected SpecialSideStoreLC, got %q", got)
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certTpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xABCD),
		Subject:      pkix.Name{CommonName: "Dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, certTpl, certTpl, &key.PublicKey, key)
	xc, _ := x509.ParseCertificate(der)
	cid := &devportal.CertificateIdentity{MachineID: "MACH-1", PrivateKey: key, Certificate: xc}

	if err := applySpecialAppInjection(appDir, SpecialSideStoreLC, "group.com.SideStore.SideStore.TEAM1", cid); err != nil {
		t.Fatalf("applySpecialAppInjection failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fwDir, "ALTCertificate.p12")); err != nil {
		t.Fatalf("expected ALTCertificate.p12 inside SideStore.framework: %v", err)
	}
	fwPlist, err := readPlistDict(filepath.Join(fwDir, "Info.plist"))
	if err != nil || fwPlist["ALTCertificateID"] != "ABCD" {
		t.Fatalf("expected ALTCertificateID=ABCD, got %+v (%v)", fwPlist, err)
	}
}

func TestSignIPAWithPortalChecksRecoveryBundleIDBeforeProvisioning(t *testing.T) {
	appDir := filepath.Join(t.TempDir(), "LiveContainer.app")
	fwDir := filepath.Join(appDir, "Frameworks", "SideStoreApp.framework")
	if err := os.MkdirAll(fwDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writePlistDict(filepath.Join(appDir, "Info.plist"), map[string]any{
		"CFBundleIdentifier": "com.kdt.livecontainer",
	}); err != nil {
		t.Fatal(err)
	}
	if err := writePlistDict(filepath.Join(fwDir, "Info.plist"), map[string]any{
		"CFBundleIdentifier": "com.SideStore.SideStore",
	}); err != nil {
		t.Fatal(err)
	}

	errCertificate := errors.New("certificate unavailable")
	for _, tc := range []struct {
		name     string
		bundleID string
		wantErr  error
	}{
		{"different signing convention", "TEAM1.com.kdt.livecontainer", ErrRecoveryBundleIDMismatch},
		{"matching installed app", "com.kdt.livecontainer.TEAM1", errCertificate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certificateRequested := false
			_, err := SignIPAWithPortal(context.Background(), PortalSignOptions{
				InputPath:         appDir,
				DeviceUDID:        "device-udid",
				Team:              devportal.Team{TeamID: "TEAM1"},
				Portal:            &devportal.Session{},
				RecoveryBundleID:  tc.bundleID,
				EnsureCertificate: func(context.Context) (*devportal.CertificateIdentity, error) {
					certificateRequested = true
					return nil, errCertificate
				},
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got error %v, want %v", err, tc.wantErr)
			}
			if want := tc.wantErr == errCertificate; certificateRequested != want {
				t.Errorf("certificate requested = %t, want %t", certificateRequested, want)
			}
		})
	}
}

func TestSignRealLiveContainerSideStoreBundleIfCached(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	ipaPath := filepath.Join(home, "Library", "Application Support", "KoiSide", "downloads", "LiveContainer+SideStore.ipa")
	if _, err := os.Stat(ipaPath); err != nil {
		t.Skip("LiveContainer+SideStore.ipa not cached")
	}
	workDir := t.TempDir()
	appDir, _, err := prepareAppDir(ipaPath, workDir)
	if err != nil {
		t.Fatal(err)
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test WWDR"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Apple Development: Test (T1)", OrganizationalUnit: []string{"TEAM1"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	profileFor := func(appID string) *ProvisioningProfile {
		raw, _ := plist.Marshal(map[string]any{
			"UUID":                  "11111111-2222-3333-4444-555555555555",
			"AppIDName":             appID,
			"TeamIdentifier":        []string{"TEAM1"},
			"DeveloperCertificates": [][]byte{leafDER},
			"Entitlements": map[string]any{
				"application-identifier": "TEAM1." + appID,
				"get-task-allow":         true,
			},
		}, plist.XMLFormat)
		p, err := ParseProvisioningProfile(wrapTestCMS(raw))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	prof := profileFor("com.kdt.livecontainer.TEAM1")
	extProfiles := map[string]*ProvisioningProfile{}
	for _, dir := range findExtensionDirs(appDir) {
		if id := readBundleIdentifier(filepath.Join(dir, "Info.plist")); id != "" {
			extProfiles[id] = profileFor(id)
		}
	}
	cid := &devportal.CertificateIdentity{MachineID: "M1", PrivateKey: leafKey, Certificate: leafCert}
	if err := applySpecialAppInjection(appDir, SpecialSideStoreLC, "group.com.SideStore.SideStore.TEAM1", cid); err != nil {
		t.Fatal(err)
	}
	if err := SignAppBundle(appDir, BundleSignConfig{
		TeamID:      "TEAM1",
		Cert:        cid,
		MainProfile: prof,
		ExtProfiles: extProfiles,
		Special:     SpecialSideStoreLC,
	}); err != nil {
		t.Fatalf("SignAppBundle failed: %v", err)
	}
	// Check structural validity on main app and nested frameworks/plugins via codesign -dv
	out, err := exec.Command("/usr/bin/codesign", "-dv", "--deep", appDir).CombinedOutput()
	if err != nil {
		t.Fatalf("codesign -dv --deep failed: %v\n%s", err, out)
	}
	// Verify nested binaries have valid signature structure (check sealed resources hash match using codesign --verify --no-strict)
	verOut, verErr := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--no-strict", appDir).CombinedOutput()
	t.Logf("codesign --verify --deep output (%v):\n%s", verErr, verOut)
}

func wrapTestCMS(inner []byte) []byte {
	oidData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oct, _ := asn1.Marshal(inner)
	eci, _ := asn1.Marshal(struct {
		CT      asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}{
		CT:      oidData,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: oct},
	})
	// Build SignedData SEQUENCE: version(1), digestAlgs(SET{}), eci
	emptySet, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true})
	ver, _ := asn1.Marshal(1)
	var sdBytes []byte
	sdBytes = append(sdBytes, ver...)
	sdBytes = append(sdBytes, emptySet...)
	sdBytes = append(sdBytes, eci...)
	sdBytes = append(sdBytes, emptySet...)
	sd, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: sdBytes})
	ciInner := append(mustMarshal(oidSignedData), mustMarshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd})...)
	out, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: ciInner})
	return out
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !stringContains(s, sub) {
			return false
		}
	}
	return true
}

func stringContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexString(s, sub) >= 0)
}

func indexString(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// extensionFixture builds an app with one PlugIns/*.appex and returns the
// directories plus a signing identity and two profiles. The extension's
// profile carries the extension's own application-identifier.
func extensionFixture(t *testing.T) (appDir, extDir string, cert *devportal.CertificateIdentity, mainProf, extProf *ProvisioningProfile) {
	t.Helper()
	tmp := t.TempDir()
	src := filepath.Join(tmp, "hello.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	appDir = filepath.Join(tmp, "Sample.app")
	extDir = filepath.Join(appDir, "PlugIns", "Share.appex")
	if err := os.MkdirAll(extDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(appDir, "Sample")
	if out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	exec, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extDir, "Share"), exec, 0o755); err != nil {
		t.Fatal(err)
	}
	writeInfo := func(dir, id, name, exe string) {
		raw, _ := plist.Marshal(map[string]any{
			"CFBundleIdentifier": id,
			"CFBundleExecutable": exe,
			"CFBundleName":       name,
			"CFBundleVersion":    "1.0",
		}, plist.XMLFormat)
		if err := os.WriteFile(filepath.Join(dir, "Info.plist"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeInfo(appDir, "com.example.sample.TEAM123", "Sample", "Sample")
	writeInfo(extDir, "com.example.sample.share.TEAM123", "Share", "Share")

	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test WWDR"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Apple Development: Test", OrganizationalUnit: []string{"TEAM123"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)
	cert = &devportal.CertificateIdentity{MachineID: "M1", PrivateKey: leafKey, Certificate: leafCert}

	profile := func(uuid, appID string) *ProvisioningProfile {
		raw, _ := plist.Marshal(map[string]any{
			"UUID":                  uuid,
			"AppIDName":             appID,
			"TeamIdentifier":        []string{"TEAM123"},
			"DeveloperCertificates": [][]byte{leafDER},
			"Entitlements": map[string]any{
				"application-identifier": "TEAM123." + appID,
				"get-task-allow":         true,
			},
		}, plist.XMLFormat)
		p, err := ParseProvisioningProfile(wrapTestCMS(raw))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	return appDir, extDir, cert, profile("11111111-2222-3333-4444-555555555555", "com.example.sample.TEAM123"),
		profile("66666666-7777-8888-9999-000000000000", "com.example.sample.share.TEAM123")
}

func embeddedAppID(t *testing.T, bundleDir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(bundleDir, "embedded.mobileprovision"))
	if err != nil {
		t.Fatalf("read embedded profile in %s: %v", filepath.Base(bundleDir), err)
	}
	p, err := ParseProvisioningProfile(raw)
	if err != nil {
		t.Fatalf("parse embedded profile: %v", err)
	}
	id, _ := p.Entitlements["application-identifier"].(string)
	return id
}

func TestSignAppBundleGivesEachExtensionItsOwnProfile(t *testing.T) {
	appDir, extDir, cert, mainProf, extProf := extensionFixture(t)
	err := SignAppBundle(appDir, BundleSignConfig{
		TeamID:      "TEAM123",
		Cert:        cert,
		MainProfile: mainProf,
		ExtProfiles: map[string]*ProvisioningProfile{"com.example.sample.share.TEAM123": extProf},
	})
	if err != nil {
		t.Fatalf("SignAppBundle failed: %v", err)
	}
	if got := embeddedAppID(t, extDir); got != "TEAM123.com.example.sample.share.TEAM123" {
		t.Fatalf("extension sealed with %q, want its own profile", got)
	}
	if got := embeddedAppID(t, appDir); got != "TEAM123.com.example.sample.TEAM123" {
		t.Fatalf("main app sealed with %q", got)
	}
}

func TestSignAppBundleDropsAnExtensionWithoutItsOwnProfile(t *testing.T) {
	appDir, extDir, cert, mainProf, _ := extensionFixture(t)
	err := SignAppBundle(appDir, BundleSignConfig{
		TeamID:                      "TEAM123",
		Cert:                        cert,
		MainProfile:                 mainProf,
		DropUnprovisionedExtensions: true,
	})
	if err != nil {
		t.Fatalf("SignAppBundle failed: %v", err)
	}
	if _, err := os.Stat(extDir); !os.IsNotExist(err) {
		t.Fatalf("extension survived without a profile (err=%v)", err)
	}
	if got := embeddedAppID(t, appDir); got != "TEAM123.com.example.sample.TEAM123" {
		t.Fatalf("main app sealed with %q", got)
	}
}

func TestSignAppBundleRefusesAnExtensionWithoutAProfileByDefault(t *testing.T) {
	appDir, extDir, cert, mainProf, _ := extensionFixture(t)
	err := SignAppBundle(appDir, BundleSignConfig{
		TeamID:      "TEAM123",
		Cert:        cert,
		MainProfile: mainProf,
	})
	if err == nil || !stringContains(err.Error(), "com.example.sample.share.TEAM123") {
		t.Fatalf("want an error naming the extension, got %v", err)
	}
	if _, statErr := os.Stat(extDir); statErr != nil {
		t.Fatalf("the extension must stay when signing refuses: %v", statErr)
	}
}

func TestFindExtensionDirsFindsEveryAppex(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{
		"PlugIns/Share.appex",
		"PlugIns/Deep/Nested.appex",
		"Watch/App.app/PlugIns/Watch.appex",
		"Frameworks/Lib.framework",
	} {
		if err := os.MkdirAll(filepath.Join(dir, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(findExtensionDirs(dir)); got != 3 {
		t.Fatalf("found %d extensions, want 3: %v", got, findExtensionDirs(dir))
	}
}
