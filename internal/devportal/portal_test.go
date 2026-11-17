package devportal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"howett.net/plist"

	"koiside/internal/appleauth"
)

type staticAnisette struct{}

func (staticAnisette) GetClientInfo(context.Context) (appleauth.ClientInfo, error) {
	return appleauth.DefaultMacClientInfo, nil
}
func (staticAnisette) GetAnisetteData(context.Context, *appleauth.GrandSlamClient) (appleauth.AnisetteData, error) {
	return appleauth.AnisetteData{
		MachineID:              "m",
		OneTimePassword:        "otp",
		RoutingInfo:            "17106176",
		DeviceUniqueIdentifier: "dev-uuid",
		LocalUserID:            "mdlu",
	}, nil
}
func (s staticAnisette) Resync(ctx context.Context, gs *appleauth.GrandSlamClient, sim string) (appleauth.AnisetteData, error) {
	return s.GetAnisetteData(ctx, gs)
}
func (staticAnisette) Reset(context.Context) error { return nil }

func TestEnsureCertificateHandlesMaxCertsAndExportsP12(t *testing.T) {
	var revoked string
	var issuedCertDER []byte
	var issuedSerial = "1A2B3C"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_, _ = plist.Unmarshal(body, &req)
		switch r.URL.Path {
		case "/ios/listAllDevelopmentCerts.action", "/listAllDevelopmentCerts.action":
			var certs []map[string]any
			if issuedCertDER != nil {
				certs = append(certs, map[string]any{
					"name":                "Apple Development: test",
					"certificateId":       "C2",
					"serialNumber":        issuedSerial,
					"machineId":           "M2",
					"machineName":         "koiside",
					"certContent":         issuedCertDER,
					"certificatePlatform": "ios",
				})
			} else {
				certs = append(certs, map[string]any{
					"name":                "Old Cert",
					"certificateId":       "C1",
					"serialNumber":        "OLD123",
					"machineId":           "M1",
					"machineName":         "old-mac",
					"certificatePlatform": "ios",
				})
			}
			raw, _ := plist.Marshal(map[string]any{"resultCode": int64(0), "certificates": certs}, plist.XMLFormat)
			_, _ = w.Write(raw)
		case "/ios/submitDevelopmentCSR.action":
			if revoked == "" {
				raw, _ := plist.Marshal(map[string]any{
					"resultCode": int64(7460),
					"userString": "Maximum number of certificates generated",
				}, plist.XMLFormat)
				_, _ = w.Write(raw)
				return
			}
			// Sign the CSR public key into a valid X.509 cert
			csrPEM, _ := req["csrContent"].(string)
			block, _ := pem.Decode([]byte(csrPEM))
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			serialInt := new(big.Int)
			serialInt.SetString(issuedSerial, 16)
			tpl := &x509.Certificate{
				SerialNumber: serialInt,
				Subject:      pkix.Name{CommonName: "Apple Development: test"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
			}
			issuedCertDER, err = x509.CreateCertificate(rand.Reader, tpl, tpl, csr.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := plist.Marshal(map[string]any{
				"resultCode":  int64(0),
				"certRequest": map[string]any{"certRequestId": "REQ1"},
			}, plist.XMLFormat)
			_, _ = w.Write(raw)
		case "/ios/revokeDevelopmentCert.action":
			revoked, _ = req["serialNumber"].(string)
			raw, _ := plist.Marshal(map[string]any{"resultCode": int64(0)}, plist.XMLFormat)
			_, _ = w.Write(raw)
		}
	}))
	defer srv.Close()

	sess := &Session{
		Token:    appleauth.AppToken{Token: "tok"},
		ADSID:    "adsid",
		Client:   appleauth.NewGrandSlamClientWithHTTP(srv.Client(), appleauth.DefaultMacClientInfo, ""),
		Anisette: staticAnisette{},
		BaseURL:  srv.URL,
	}

	store := appleauth.NewMemoryStorage()
	id, err := EnsureCertificate(context.Background(), sess, "TEAM123", "user@example.com", "koiside", store, func(certs []DevelopmentCertificate) ([]string, error) {
		return []string{certs[0].SerialNumber}, nil
	})
	if err != nil {
		t.Fatalf("EnsureCertificate failed: %v", err)
	}
	if revoked != "OLD123" {
		t.Fatalf("expected OLD123 revoked, got %q", revoked)
	}
	if id.SerialNumberHex() != issuedSerial {
		t.Fatalf("expected serial %s, got %s", issuedSerial, id.SerialNumberHex())
	}
	p12, err := id.ExportP12(id.MachineID)
	if err != nil || len(p12) == 0 {
		t.Fatalf("ExportP12 failed: %v", err)
	}
}

func TestTeamIsFreePersonalParsing(t *testing.T) {
	cases := []struct {
		name string
		team Team
		want bool
	}{
		{
			name: "free individual with free membership",
			team: Team{TeamID: "T1", Type: "Individual", Memberships: []TeamMembership{{Name: "Xcode Free Provisioning"}}},
			want: true,
		},
		{
			name: "free individual with empty memberships",
			team: Team{TeamID: "T2", Type: "Individual"},
			want: true,
		},
		{
			name: "paid individual with developer program membership",
			team: Team{TeamID: "T3", Type: "Individual", Memberships: []TeamMembership{{Name: "Apple Developer Program"}}},
			want: false,
		},
		{
			name: "organization team",
			team: Team{TeamID: "T4", Type: "Company/Organization"},
			want: false,
		},
	}
	for _, tc := range cases {
		if got := tc.team.IsFreePersonal(); got != tc.want {
			t.Errorf("%s: IsFreePersonal()=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHasLocalRSAKeyForCert(t *testing.T) {
	store := appleauth.NewMemoryStorage()
	key, err := loadOrCreateRSAKey("user@example.com", store)
	if err != nil {
		t.Fatal(err)
	}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := DevelopmentCertificate{CertContent: der}
	if !HasLocalRSAKeyForCert("user@example.com", cert, store) {
		t.Fatal("expected matching local RSA key")
	}
	if HasLocalRSAKeyForCert("other@example.com", cert, store) {
		t.Fatal("unexpected match for other email")
	}
}
