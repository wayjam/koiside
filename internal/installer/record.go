package installer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"koiside/internal/account"
	"koiside/internal/device"
	"koiside/internal/devportal"
	"koiside/internal/signing"
)

// Record tracks a signed app installed by KoiSide on a device.
// This metadata allows one-click profile renewal without re-signing or uploading.
type Record struct {
	InstalledID   string            `json:"installed_id"`
	OriginalID    string            `json:"original_id"`
	Name          string            `json:"name"`
	TeamID        string            `json:"team_id"`
	CertSerial    string            `json:"cert_serial"`
	IDs           map[string]string `json:"ids"` // bundle dir inside IPA -> registered App ID identifier
	ProfileUUID   string            `json:"profile_uuid"`
	ProfileExpiry time.Time         `json:"profile_expiry"`
	InstalledAt   time.Time         `json:"installed_at"`
	Kind          string            `json:"kind,omitempty"`
}

// RecordStore manages persistent records of apps installed on devices.
type RecordStore struct {
	mu   sync.Mutex
	path string
}

// NewRecordStore opens or initializes a store at filePath.
func NewRecordStore(filePath string) *RecordStore {
	return &RecordStore{path: filePath}
}

func (s *RecordStore) loadLocked() ([]Record, error) {
	if s.path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var records []Record
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("installer: decode records: %w", err)
	}
	return records, nil
}

func (s *RecordStore) saveLocked(records []Record) error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	temp := s.path + ".tmp"
	if err := os.WriteFile(temp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(temp, s.path)
}

// List returns all remembered install records.
func (s *RecordStore) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, _ := s.loadLocked()
	out := make([]Record, len(records))
	copy(out, records)
	return out
}

// Get finds a record by its installed bundle ID.
func (s *RecordStore) Get(installedID string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, _ := s.loadLocked()
	for _, r := range records {
		if r.InstalledID == installedID {
			return r, true
		}
	}
	return Record{}, false
}

// Upsert adds or updates a record matching installed ID.
func (s *RecordStore) Upsert(record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, _ := s.loadLocked()
	found := false
	for i, r := range records {
		if r.InstalledID == record.InstalledID {
			records[i] = record
			found = true
			break
		}
	}
	if !found {
		records = append(records, record)
	}
	return s.saveLocked(records)
}

// Delete removes a record by installed ID.
func (s *RecordStore) Delete(installedID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, _ := s.loadLocked()
	var kept []Record
	for _, r := range records {
		if r.InstalledID != installedID {
			kept = append(kept, r)
		}
	}
	return s.saveLocked(kept)
}

// RefreshResult summarizes the outcome of a profile-only renewal.
type RefreshResult struct {
	InstalledID   string
	ProfileExpiry time.Time
	ProfilesCount int
}

// RefreshProfiles downloads fresh provisioning profiles for each registered App ID in record
// and installs them directly to the device via misagent, without re-signing or uploading binaries.
func RefreshProfiles(ctx context.Context, dev device.Device, dial device.Dialer, accounts account.Manager, record Record, store *RecordStore, onProgress Progress) (RefreshResult, error) {
	report := func(pct int, stage string) {
		if onProgress != nil {
			onProgress(pct, stage)
		}
	}
	if accounts == nil || !accounts.Developer().SignedIn() {
		return RefreshResult{}, errors.New("installer: Apple Developer account not signed in")
	}
	portal, err := accounts.DeveloperPortal()
	if err != nil {
		return RefreshResult{}, err
	}
	team, ok := accounts.Developer().ActiveTeam()
	if !ok || team.TeamID != record.TeamID {
		return RefreshResult{}, fmt.Errorf("installer: active developer team does not match record team %s", record.TeamID)
	}
	if dev.ID == 0 || dev.UDID == "" {
		return RefreshResult{}, errors.New("installer: no connected iPhone selected")
	}

	report(10, "certificate")
	certs, err := portal.ListAllDevelopmentCerts(ctx, record.TeamID, true)
	if err != nil {
		return RefreshResult{}, err
	}
	var activeCert *devportal.DevelopmentCertificate
	for _, c := range certs {
		if strings.EqualFold(strings.TrimLeft(c.SerialNumber, "0"), strings.TrimLeft(record.CertSerial, "0")) {
			activeCert = &c
			break
		}
	}
	if activeCert == nil {
		return RefreshResult{}, fmt.Errorf("installer: certificate %s is no longer active in team; full resign required", record.CertSerial)
	}

	report(25, "app_ids")
	appIDsRes, err := portal.ListAppIDs(ctx, record.TeamID)
	if err != nil {
		return RefreshResult{}, err
	}
	existing := map[string]devportal.AppID{}
	for _, a := range appIDsRes.AppIDs {
		existing[a.Identifier] = a
	}

	targetIDs := record.IDs
	if len(targetIDs) == 0 {
		targetIDs = map[string]string{".": record.InstalledID}
	}

	var profilesToInstall [][]byte
	var earliestExpiry time.Time
	report(40, "profiles")
	for _, registeredID := range targetIDs {
		aid, ok := existing[registeredID]
		if !ok {
			return RefreshResult{}, fmt.Errorf("installer: App ID %s has expired; full resign required", registeredID)
		}
		profRaw, err := portal.DownloadTeamProvisioningProfile(ctx, record.TeamID, aid.AppIDID)
		if err != nil {
			return RefreshResult{}, fmt.Errorf("installer: download profile for %s: %w", registeredID, err)
		}
		parsed, err := signing.ParseProvisioningProfile(profRaw.EncodedProfile)
		if err != nil {
			return RefreshResult{}, fmt.Errorf("installer: parse profile for %s: %w", registeredID, err)
		}
		listsCert := false
		for _, c := range parsed.Certs {
			if strings.EqualFold(strings.TrimLeft(c.SerialNumber.Text(16), "0"), strings.TrimLeft(record.CertSerial, "0")) {
				listsCert = true
				break
			}
		}
		if !listsCert {
			return RefreshResult{}, fmt.Errorf("installer: profile for %s does not list active certificate %s; full resign required", registeredID, record.CertSerial)
		}
		if earliestExpiry.IsZero() || (!parsed.ExpirationDate.IsZero() && parsed.ExpirationDate.Before(earliestExpiry)) {
			earliestExpiry = parsed.ExpirationDate
		}
		profilesToInstall = append(profilesToInstall, profRaw.EncodedProfile)
	}

	report(70, "misagent")
	sess, err := device.DialSession(dial, dev.ID, dev.UDID)
	if err != nil {
		return RefreshResult{}, err
	}
	defer sess.Close()

	for i, profData := range profilesToInstall {
		if err := sess.InstallProvisioningProfile(profData); err != nil {
			return RefreshResult{}, fmt.Errorf("installer: install profile %d via misagent: %w", i+1, err)
		}
	}

	record.ProfileExpiry = earliestExpiry
	if store != nil {
		_ = store.Upsert(record)
	}

	report(100, "complete")
	return RefreshResult{
		InstalledID:   record.InstalledID,
		ProfileExpiry: earliestExpiry,
		ProfilesCount: len(profilesToInstall),
	}, nil
}
