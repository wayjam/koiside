package installer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"howett.net/plist"

	"koiside/internal/account"
	"koiside/internal/appleauth"
	"koiside/internal/device"
	"koiside/internal/devportal"
)

func TestRecordStoreCRUD(t *testing.T) {
	tmp := t.TempDir()
	storeFile := filepath.Join(tmp, "records.json")
	store := NewRecordStore(storeFile)

	if len(store.List()) != 0 {
		t.Fatal("expected empty store")
	}

	r1 := Record{
		InstalledID:   "com.example.app.TEAM1",
		OriginalID:    "com.example.app",
		Name:          "App1",
		TeamID:        "TEAM1",
		CertSerial:    "A1B2",
		IDs:           map[string]string{".": "com.example.app.TEAM1"},
		ProfileUUID:   "UUID-1",
		ProfileExpiry: time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second),
		InstalledAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := store.Upsert(r1); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	got, ok := store.Get("com.example.app.TEAM1")
	if !ok || got.Name != "App1" || got.CertSerial != "A1B2" {
		t.Fatalf("Get mismatch: %+v (ok=%v)", got, ok)
	}

	r1.CertSerial = "C3D4"
	if err := store.Upsert(r1); err != nil {
		t.Fatalf("Upsert update failed: %v", err)
	}
	got2, _ := store.Get("com.example.app.TEAM1")
	if got2.CertSerial != "C3D4" {
		t.Fatalf("expected updated serial C3D4, got %s", got2.CertSerial)
	}

	store2 := NewRecordStore(storeFile)
	if len(store2.List()) != 1 {
		t.Fatalf("expected 1 record after reload, got %d", len(store2.List()))
	}

	if err := store2.Delete("com.example.app.TEAM1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if len(store2.List()) != 0 {
		t.Fatal("expected empty store after delete")
	}
}

type fakeDevSession struct {
	team devportal.Team
}

func (f fakeDevSession) SignedIn() bool                     { return true }
func (f fakeDevSession) Email() string                      { return "test@example.com" }
func (f fakeDevSession) FullName() string                   { return "Tester" }
func (f fakeDevSession) Teams() []devportal.Team            { return []devportal.Team{f.team} }
func (f fakeDevSession) ActiveTeam() (devportal.Team, bool) { return f.team, true }
func (f fakeDevSession) SelectTeam(string) bool             { return true }

type fakeAccountMgr struct {
	account.Unavailable
	devSess fakeDevSession
	portal  *devportal.Session
}

func (f *fakeAccountMgr) Developer() account.DeveloperSession { return f.devSess }
func (f *fakeAccountMgr) DeveloperPortal() (*devportal.Session, error) {
	return f.portal, nil
}

type staticAnisette struct{}

func (staticAnisette) GetClientInfo(context.Context) (appleauth.ClientInfo, error) {
	return appleauth.DefaultMacClientInfo, nil
}
func (staticAnisette) GetAnisetteData(context.Context, *appleauth.GrandSlamClient) (appleauth.AnisetteData, error) {
	return appleauth.AnisetteData{MachineID: "m", OneTimePassword: "otp"}, nil
}
func (s staticAnisette) Resync(ctx context.Context, gs *appleauth.GrandSlamClient, _ string) (appleauth.AnisetteData, error) {
	return s.GetAnisetteData(ctx, gs)
}
func (staticAnisette) Reset(context.Context) error { return nil }

func wrapCMSProfile(inner []byte) []byte {
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
	emptySet, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true})
	ver, _ := asn1.Marshal(1)
	var sdBytes []byte
	sdBytes = append(sdBytes, ver...)
	sdBytes = append(sdBytes, emptySet...)
	sdBytes = append(sdBytes, eci...)
	sdBytes = append(sdBytes, emptySet...)
	sd, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: sdBytes})
	ciInner := append(mustASN1Marshal(oidSignedData), mustASN1Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd})...)
	out, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: ciInner})
	return out
}

func mustASN1Marshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestRefreshProfilesWorkflow(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	serial := big.NewInt(0x42)
	certTpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Apple Development: Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, certTpl, certTpl, &key.PublicKey, key)

	wantSerial := "42"
	wantExpiry := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)

	profDoc := map[string]any{
		"UUID":                  "TEST-UUID",
		"TeamIdentifier":        []string{"TEAM1"},
		"DeveloperCertificates": [][]byte{certDER},
		"ExpirationDate":        wantExpiry,
		"Entitlements": map[string]any{
			"application-identifier": "TEAM1.com.example.app.TEAM1",
		},
	}
	profXML, _ := plist.Marshal(profDoc, plist.XMLFormat)
	profCMS := wrapCMSProfile(profXML)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_, _ = plist.Unmarshal(body, &req)
		switch r.URL.Path {
		case "/ios/listAllDevelopmentCerts.action":
			raw, _ := plist.Marshal(map[string]any{
				"resultCode": int64(0),
				"certificates": []map[string]any{
					{
						"name":                "Apple Development: Test",
						"serialNumber":        "42",
						"certContent":         certDER,
						"certificatePlatform": "ios",
					},
				},
			}, plist.XMLFormat)
			_, _ = w.Write(raw)
		case "/ios/listAppIds.action":
			raw, _ := plist.Marshal(map[string]any{
				"resultCode": int64(0),
				"appIds": []map[string]any{
					{
						"appIdId":    "AID-1",
						"identifier": "com.example.app.TEAM1",
						"name":       "App1",
					},
				},
			}, plist.XMLFormat)
			_, _ = w.Write(raw)
		case "/ios/downloadTeamProvisioningProfile.action":
			raw, _ := plist.Marshal(map[string]any{
				"resultCode": int64(0),
				"provisioningProfile": map[string]any{
					"encodedProfile": profCMS,
				},
			}, plist.XMLFormat)
			_, _ = w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	portalSess := &devportal.Session{
		Token:    appleauth.AppToken{Token: "tok"},
		ADSID:    "adsid",
		Client:   appleauth.NewGrandSlamClientWithHTTP(srv.Client(), appleauth.DefaultMacClientInfo, ""),
		Anisette: staticAnisette{},
		BaseURL:  srv.URL,
	}

	mgr := &fakeAccountMgr{
		devSess: fakeDevSession{team: devportal.Team{TeamID: "TEAM1"}},
		portal:  portalSess,
	}

	store := NewRecordStore(filepath.Join(t.TempDir(), "records.json"))
	rec := Record{
		InstalledID:   "com.example.app.TEAM1",
		TeamID:        "TEAM1",
		CertSerial:    wantSerial,
		IDs:           map[string]string{".": "com.example.app.TEAM1"},
		ProfileExpiry: time.Now().Add(24 * time.Hour),
	}

	// 1. Team mismatch fails
	badTeamRec := rec
	badTeamRec.TeamID = "OTHER_TEAM"
	if _, err := RefreshProfiles(context.Background(), device.Device{ID: 1, UDID: "UDID-1"}, nil, mgr, badTeamRec, store, nil); err == nil {
		t.Fatal("expected error on team mismatch, got nil")
	}

	// 2. Certificate serial mismatch fails
	badCertRec := rec
	badCertRec.CertSerial = "DEADBEEF"
	if _, err := RefreshProfiles(context.Background(), device.Device{ID: 1, UDID: "UDID-1"}, nil, mgr, badCertRec, store, nil); err == nil || !strings.Contains(err.Error(), "no longer active") {
		t.Fatalf("expected cert mismatch error, got %v", err)
	}

	// 3. App ID missing from portal fails
	badAppIDRec := rec
	badAppIDRec.IDs = map[string]string{".": "com.example.missing.TEAM1"}
	if _, err := RefreshProfiles(context.Background(), device.Device{ID: 1, UDID: "UDID-1"}, nil, mgr, badAppIDRec, store, nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected missing App ID error, got %v", err)
	}

	// 4. Calling RefreshProfiles through device dialer reaches the device stage
	testDialer := func() (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("device: mock dialer reached")
	}
	_, err := RefreshProfiles(context.Background(), device.Device{ID: 1, UDID: "UDID-1"}, testDialer, mgr, rec, store, nil)
	if err == nil || !strings.Contains(err.Error(), "device:") {
		t.Fatalf("expected dialer reached after portal verification, got %v", err)
	}
}
