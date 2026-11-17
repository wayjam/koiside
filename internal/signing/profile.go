package signing

import (
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"errors"
	"fmt"

	"howett.net/plist"
)

//go:embed certs/*.cer
var appleCertFS embed.FS

// AppleCA holds bundled Apple Root and WWDR intermediate certificates for CMS chain building.
func AppleCACertificates() ([]*x509.Certificate, error) {
	entries, err := appleCertFS.ReadDir("certs")
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for _, e := range entries {
		raw, err := appleCertFS.ReadFile("certs/" + e.Name())
		if err != nil {
			continue
		}
		if c, err := x509.ParseCertificate(raw); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// ProvisioningProfile holds the parsed XML plist and embedded certificates from a .mobileprovision file.
type ProvisioningProfile struct {
	Raw          []byte
	Entitlements map[string]any
	TeamID       string
	AppIDName    string
	UUID         string
	Certs        []*x509.Certificate
}

// ParseProvisioningProfile extracts the CMS-wrapped XML plist and developer certificates from a .mobileprovision blob.
func ParseProvisioningProfile(raw []byte) (*ProvisioningProfile, error) {
	if len(raw) == 0 {
		return nil, errors.New("signing: empty provisioning profile")
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(raw, &ci); err != nil {
		return nil, fmt.Errorf("signing: parse profile CMS ContentInfo: %w", err)
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo struct {
			ContentType asn1.ObjectIdentifier
			Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
		}
		Certificates asn1.RawValue `asn1:"tag:0,optional"`
		CRLs         asn1.RawValue `asn1:"tag:1,optional"`
		SignerInfos  asn1.RawValue
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("signing: parse profile SignedData: %w", err)
	}

	var plistBytes []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.Content.Bytes, &plistBytes); err != nil {
		// Handle constructed OCTET STRING or raw XML inside explicit tag
		plistBytes = sd.EncapContentInfo.Content.Bytes
	}
	var dict map[string]any
	if _, err := plist.Unmarshal(plistBytes, &dict); err != nil {
		return nil, fmt.Errorf("signing: parse profile XML plist: %w", err)
	}

	ent, _ := dict["Entitlements"].(map[string]any)
	if ent == nil {
		ent = map[string]any{}
	}
	var teamID string
	if tids, ok := dict["TeamIdentifier"].([]any); ok && len(tids) > 0 {
		teamID, _ = tids[0].(string)
	}
	uuid, _ := dict["UUID"].(string)
	name, _ := dict["AppIDName"].(string)

	var certs []*x509.Certificate
	if devs, ok := dict["DeveloperCertificates"].([]any); ok {
		for _, item := range devs {
			if b, ok := item.([]byte); ok {
				if c, err := x509.ParseCertificate(b); err == nil {
					certs = append(certs, c)
				}
			}
		}
	}
	// Also parse CMS Certificates field for chain resolution.
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var rawCert asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rawCert)
		if err != nil {
			break
		}
		if c, err := x509.ParseCertificate(rawCert.FullBytes); err == nil {
			certs = append(certs, c)
		}
	}

	return &ProvisioningProfile{
		Raw:          raw,
		Entitlements: ent,
		TeamID:       teamID,
		AppIDName:    name,
		UUID:         uuid,
		Certs:        certs,
	}, nil
}

// CertificateChainFor builds leaf -> WWDR intermediate -> Apple Root chain for CMS signing.
func CertificateChainFor(leaf *x509.Certificate, candidates []*x509.Certificate) []*x509.Certificate {
	appleCAs, _ := AppleCACertificates()
	pool := make([]*x509.Certificate, 0, len(candidates)+len(appleCAs))
	pool = append(pool, candidates...)
	pool = append(pool, appleCAs...)

	var chain []*x509.Certificate
	seen := map[string]bool{string(leaf.Raw): true}
	cur := leaf
	for i := 0; i < 6; i++ {
		if bytesEqual(cur.RawIssuer, cur.RawSubject) {
			break
		}
		var parent *x509.Certificate
		for _, cand := range pool {
			if seen[string(cand.Raw)] {
				continue
			}
			if bytesEqual(cand.RawSubject, cur.RawIssuer) {
				parent = cand
				break
			}
		}
		if parent == nil {
			break
		}
		seen[string(parent.Raw)] = true
		chain = append(chain, parent)
		cur = parent
	}
	return chain
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
