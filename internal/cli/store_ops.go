package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"koiside/internal/account"
	"koiside/internal/appstore"
	"koiside/internal/installer"
)

// StoreStatusResult summarizes the active and saved App Store accounts.
type StoreStatusResult struct {
	SignedIn    bool                          `json:"signed_in"`
	Email       string                        `json:"email,omitempty"`
	StoreFront  string                        `json:"store_front,omitempty"`
	CountryCode string                        `json:"country_code,omitempty"`
	Pod         string                        `json:"pod,omitempty"`
	Saved       []account.StoreAccountSummary `json:"saved_accounts,omitempty"`
}

// StoreVersionsResult lists available external version IDs for an App Store app.
type StoreVersionsResult struct {
	App      appstore.Software `json:"app"`
	Versions []string          `json:"versions"`
}

// StoreDownloadResult reports a downloaded and SINF-injected IPA path.
type StoreDownloadResult struct {
	App          appstore.Software `json:"app"`
	VersionID    string            `json:"version_id,omitempty"`
	OutputPath   string            `json:"output_path"`
	SizeBytes    int64             `json:"size_bytes"`
	AlreadyOwned bool              `json:"already_owned"`
}

// StoreInstallResult summarizes downloading (if needed) and USB-installing a Store IPA.
type StoreInstallResult struct {
	BundleID     string `json:"bundle_id"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	IPAPath      string `json:"ipa_path"`
	AlreadyOwned bool   `json:"already_owned,omitempty"`
	Next         string `json:"next"`
}

// EnsureStoreSession restores an active App Store session from Keychain storage.
func EnsureStoreSession(ctx context.Context, mgr account.Manager) (appstore.Account, error) {
	if mgr == nil {
		return appstore.Account{}, &ActionRequiredError{
			Reason:  "needs_store_signin",
			Message: "Account manager is unavailable.",
			Next:    "Run 'koiside store login --email <apple_id>' or sign in via KoiSide GUI -> Apple Account.",
		}
	}
	if !mgr.Store().SignedIn() {
		_ = mgr.RestoreStoreSession(ctx)
	}
	acc, ok := mgr.Store().Account()
	if !ok {
		return appstore.Account{}, &ActionRequiredError{
			Reason:  "needs_store_signin",
			Message: "No active App Store session in Keychain.",
			Next:    "Run 'koiside store login --email <apple_id>' or sign in via KoiSide GUI -> Apple Account.",
		}
	}
	return acc, nil
}

// GetStoreStatus returns current and saved App Store account status.
func GetStoreStatus(ctx context.Context, d Deps) (StoreStatusResult, error) {
	d = d.withDefaults()
	_ = d.Accounts.RestoreStoreSession(ctx)
	st := d.Accounts.Store()
	return StoreStatusResult{
		SignedIn:    st.SignedIn(),
		Email:       st.Email(),
		StoreFront:  st.StoreFront(),
		CountryCode: st.CountryCode(),
		Pod:         st.Pod(),
		Saved:       d.Accounts.SavedStoreAccounts(),
	}, nil
}

// SearchStoreApps searches the App Store catalog.
func SearchStoreApps(ctx context.Context, d Deps, term, country, entity string, limit int) ([]appstore.Software, error) {
	d = d.withDefaults()
	if strings.TrimSpace(term) == "" {
		return nil, errors.New("search term is required")
	}
	if country == "" {
		_ = d.Accounts.RestoreStoreSession(ctx)
		if cc := d.Accounts.Store().CountryCode(); cc != "" {
			country = cc
		} else {
			country = "US"
		}
	}
	return d.Accounts.StoreClient().SearchApps(ctx, term, country, entity, limit)
}

func resolveStoreApp(ctx context.Context, d Deps, acc appstore.Account, bundleOrID, country string) (appstore.Software, error) {
	if country == "" {
		if cc, ok := appstore.StoreIDToCountry(acc.Store); ok {
			country = cc
		} else {
			country = "US"
		}
	}
	client := d.Accounts.StoreClient()
	var sw *appstore.Software
	var err error
	if isDigits(bundleOrID) {
		var id int64
		_, _ = fmt.Sscanf(bundleOrID, "%d", &id)
		sw, err = client.LookupApp(ctx, "", id, country)
	} else {
		sw, err = client.LookupApp(ctx, bundleOrID, 0, country)
	}
	if err != nil {
		return appstore.Software{}, err
	}
	if sw == nil {
		return appstore.Software{}, fmt.Errorf("app %q not found in %s App Store", bundleOrID, country)
	}
	return *sw, nil
}

// ListStoreVersions lists available historical external version IDs for bundleOrID.
func ListStoreVersions(ctx context.Context, d Deps, bundleOrID, country string) (StoreVersionsResult, error) {
	d = d.withDefaults()
	acc, err := EnsureStoreSession(ctx, d.Accounts)
	if err != nil {
		return StoreVersionsResult{}, err
	}
	sw, err := resolveStoreApp(ctx, d, acc, bundleOrID, country)
	if err != nil {
		return StoreVersionsResult{}, err
	}
	versions, cookies, err := d.Accounts.StoreClient().ListVersions(ctx, acc, sw)
	if len(cookies) > 0 {
		d.Accounts.UpdateStoreCookies(acc.Email, cookies)
	}
	if err != nil {
		return StoreVersionsResult{}, err
	}
	return StoreVersionsResult{App: sw, Versions: versions}, nil
}

// DownloadStoreApp purchases (if free & unowned), downloads, and injects SINF + iTunesMetadata into outPath.
func DownloadStoreApp(ctx context.Context, d Deps, bundleOrID, versionID, country, outPath string, allowHTTP bool, onProgress func(appstore.DownloadProgress)) (StoreDownloadResult, error) {
	d = d.withDefaults()
	acc, err := EnsureStoreSession(ctx, d.Accounts)
	if err != nil {
		return StoreDownloadResult{}, err
	}
	sw, err := resolveStoreApp(ctx, d, acc, bundleOrID, country)
	if err != nil {
		return StoreDownloadResult{}, err
	}
	client := d.Accounts.StoreClient()

	var alreadyOwned bool
	if sw.Price <= 0 {
		pRes, pErr := client.PurchaseApp(ctx, acc, sw)
		if len(pRes.UpdatedCookies) > 0 {
			acc.Cookies = pRes.UpdatedCookies
			d.Accounts.UpdateStoreCookies(acc.Email, pRes.UpdatedCookies)
		}
		if pErr == nil {
			alreadyOwned = pRes.AlreadyOwned
		}
	}

	dl, cookies, err := client.GetDownloadInfo(ctx, acc, sw, versionID)
	if len(cookies) > 0 {
		d.Accounts.UpdateStoreCookies(acc.Email, cookies)
	}
	if err != nil {
		return StoreDownloadResult{}, err
	}

	dest := strings.TrimSpace(outPath)
	if dest == "" {
		safeName := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(sw.BundleID)
		if safeName == "" {
			safeName = fmt.Sprintf("app_%d", sw.ID)
		}
		ver := dl.BundleShortVersionString
		if ver == "" {
			ver = sw.Version
		}
		dest = filepath.Join(d.CacheDir, fmt.Sprintf("%s_%s.ipa", safeName, ver))
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return StoreDownloadResult{}, err
	}

	var httpClient *http.Client
	if hc, ok := d.HTTPClient.(*http.Client); ok {
		httpClient = hc
	}
	if err := appstore.DownloadFile(ctx, dl.DownloadURL, dest, appstore.DownloadOptions{
		HTTPClient:        httpClient,
		OnProgress:        onProgress,
		AllowInsecureHTTP: allowHTTP,
	}); err != nil {
		return StoreDownloadResult{}, err
	}

	if err := appstore.InjectSinfAndMetadata(dest, dl.Sinfs, dl.ITunesMetadata); err != nil {
		_ = os.Remove(dest)
		return StoreDownloadResult{}, err
	}

	var sizeBytes int64
	if st, statErr := os.Stat(dest); statErr == nil {
		sizeBytes = st.Size()
	}

	return StoreDownloadResult{
		App:          sw,
		VersionID:    versionID,
		OutputPath:   dest,
		SizeBytes:    sizeBytes,
		AlreadyOwned: alreadyOwned,
	}, nil
}

// InstallStoreApp installs either a local SINF-injected .ipa path or downloads bundleOrID from the Store and installs over USB.
func InstallStoreApp(ctx context.Context, d Deps, targetOrPath, versionID, country string, allowHTTP bool, onProgress installer.Progress) (StoreInstallResult, error) {
	d = d.withDefaults()
	snap, err := requireTrustedDevice(d)
	if err != nil {
		return StoreInstallResult{}, err
	}

	targetOrPath = strings.TrimSpace(targetOrPath)
	if targetOrPath == "" {
		return StoreInstallResult{}, errors.New("bundle ID, track ID, or local .ipa path is required")
	}

	if st, statErr := os.Stat(targetOrPath); statErr == nil && !st.IsDir() {
		if err := installer.InstallStoreIPA(ctx, targetOrPath, snap.Device, d.Dial, onProgress); err != nil {
			return StoreInstallResult{}, err
		}
		rep, _ := InspectIPA(targetOrPath)
		return StoreInstallResult{
			BundleID: rep.BundleID,
			Name:     rep.DisplayName,
			Version:  rep.Version,
			IPAPath:  targetOrPath,
			Next:     "Launch the app on your iPhone. If iOS prompts for an Apple ID, sign in with the App Store account that owns this license.",
		}, nil
	}

	dlRes, err := DownloadStoreApp(ctx, d, targetOrPath, versionID, country, "", allowHTTP, func(p appstore.DownloadProgress) {
		if onProgress != nil && p.Total > 0 {
			pct := int(p.Downloaded * 50 / p.Total)
			onProgress(pct, "downloading")
		}
	})
	if err != nil {
		return StoreInstallResult{}, err
	}
	if err := installer.InstallStoreIPA(ctx, dlRes.OutputPath, snap.Device, d.Dial, func(pct int, stage string) {
		if onProgress != nil {
			onProgress(50+pct/2, stage)
		}
	}); err != nil {
		return StoreInstallResult{}, err
	}
	return StoreInstallResult{
		BundleID:     dlRes.App.BundleID,
		Name:         dlRes.App.Name,
		Version:      dlRes.App.Version,
		IPAPath:      dlRes.OutputPath,
		AlreadyOwned: dlRes.AlreadyOwned,
		Next:         "Launch the app on your iPhone. If iOS prompts for an Apple ID, sign in with the App Store account that owns this license.",
	}, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
