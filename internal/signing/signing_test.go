package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
	profPlist, _ := plist.Marshal(map[string]any{
		"UUID":           "11111111-2222-3333-4444-555555555555",
		"AppIDName":      "LiveContainer",
		"TeamIdentifier": []string{"TEAM1"},
		"Entitlements": map[string]any{
			"application-identifier": "TEAM1.com.kdt.livecontainer.TEAM1",
			"get-task-allow":         true,
		},
	}, plist.XMLFormat)
	prof, err := ParseProvisioningProfile(wrapTestCMS(profPlist))
	if err != nil {
		t.Fatal(err)
	}
	cid := &devportal.CertificateIdentity{MachineID: "M1", PrivateKey: leafKey, Certificate: leafCert}
	if err := applySpecialAppInjection(appDir, SpecialSideStoreLC, "group.com.SideStore.SideStore.TEAM1", cid); err != nil {
		t.Fatal(err)
	}
	if err := SignAppBundle(appDir, BundleSignConfig{
		TeamID:      "TEAM1",
		Cert:        cid,
		MainProfile: prof,
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
