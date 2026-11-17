package appstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

var (
	numericVersionRe       = regexp.MustCompile(`^[1-9]\d*$`)
	approvedDownloadHostRe = regexp.MustCompile(`^(?:(?:p\d+-)?buy|downloaddispatch)\.itunes\.apple\.com$`)
)

// DownloadError represents a failure resolving download URLs, versions, or SINF licenses.
type DownloadError struct {
	Message string
	Code    string
}

func (e *DownloadError) Error() string { return e.Message }

// NeedsDownloadFallback reports whether an empty/unavailable Store response warrants dispatch recovery.
// Structured auth, license, or dialog errors must never be masked by fallback retries.
func NeedsDownloadFallback(dict map[string]any) bool {
	if songs, ok := dict["songList"].([]any); ok && len(songs) > 0 {
		return false
	}
	if _, ok := dict["dialog"]; ok {
		return false
	}
	if _, ok := dict["action"]; ok {
		return false
	}
	if ft := stringify(dict["failureType"]); ft != "" {
		return ft == "5002"
	}
	if status, ok := numberInt64(dict["status"]); ok && status != 0 {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(stringify(dict["customerMessage"])))
	return msg == "" || msg == "no longer available" || strings.HasSuffix(msg, " no longer available")
}

// DispatchEndpoint validates and normalizes a bag-advertised redownload or update URL.
func DispatchEndpoint(raw, kind, deviceID string) (StoreDownloadEndpoint, bool) {
	if raw == "" {
		return StoreDownloadEndpoint{}, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return StoreDownloadEndpoint{}, false
	}
	wantPath := "/r/redownload"
	if kind == "update" {
		wantPath = "/up/updateProduct"
	}
	if u.Scheme != "https" ||
		u.Host != "downloaddispatch.itunes.apple.com" ||
		u.Path != wantPath ||
		u.RawQuery != "" ||
		u.Fragment != "" ||
		u.User != nil {
		return StoreDownloadEndpoint{}, false
	}
	q := url.Values{}
	q.Set("guid", deviceID)
	u.RawQuery = q.Encode()
	return StoreDownloadEndpoint{
		Host:                 u.Hostname(),
		Path:                 u.RequestURI(),
		ExternalVersionIDKey: "appExtVrsId",
	}, true
}

// LookupLatestVersion queries Apple's public MDM catalog for the latest iOS external version ID.
// Never sends account cookies, DSID, or password tokens.
func (c *Client) LookupLatestVersion(ctx context.Context, account Account, app Software) (string, error) {
	country, ok := StoreIDToCountry(account.Store)
	if !ok {
		return "", errors.New("appstore: unknown account storefront")
	}

	host := "uclient-api.itunes.apple.com"
	scheme := "https://"
	if c != nil && c.CatalogHost != "" {
		host = c.CatalogHost
		if strings.HasPrefix(c.BagURL, "http://") {
			scheme = "http://"
		}
	}

	appKey := strconv.FormatInt(app.ID, 10)
	for _, platform := range []string{"enterprisestore", "iphone", "ipad"} {
		q := url.Values{
			"version":  {"2"},
			"id":       {appKey},
			"p":        {"mdm-lockup"},
			"caller":   {"MDM"},
			"platform": {platform},
			"cc":       {strings.ToLower(country)},
			"l":        {"en"},
		}
		resp, err := c.doAppleRequest(ctx, "GET", scheme+host+"/WebObjects/MZStorePlatform.woa/wa/lookup?"+q.Encode(), nil, nil, nil)
		if err != nil {
			return "", err
		}
		if resp.Status != http.StatusOK {
			return "", fmt.Errorf("appstore: catalog HTTP %d", resp.Status)
		}
		var payload struct {
			Results map[string]struct {
				BundleID string `json:"bundleId"`
				Offers   []struct {
					BuyParams string `json:"buyParams"`
					Version   struct {
						ExternalID any `json:"externalId"`
					} `json:"version"`
				} `json:"offers"`
			} `json:"results"`
		}
		if err := json.Unmarshal(resp.Body, &payload); err != nil {
			return "", err
		}
		item, exists := payload.Results[appKey]
		if !exists || len(item.Offers) == 0 {
			continue
		}
		if app.BundleID != "" && item.BundleID != app.BundleID {
			return "", errors.New("appstore: catalog returned a different bundle identifier")
		}
		offer := item.Offers[0]
		ver := stringifyJSONNumber(offer.Version.ExternalID)
		if ver == "" && offer.BuyParams != "" {
			if bp, err := url.ParseQuery(offer.BuyParams); err == nil {
				ver = bp.Get("appExtVrsId")
			}
		}
		if numericVersionRe.MatchString(ver) {
			return ver, nil
		}
		return "", errors.New("appstore: catalog returned no valid iOS version identifier")
	}
	return "", errors.New("appstore: app not found in account storefront catalogs")
}

// DownloadProduct fetches the product metadata, CDN URL, and SINF blobs for app (and optional versionID),
// applying AssppWeb's volumeStore -> redownload -> updateProduct recovery pipeline.
func (c *Client) DownloadProduct(ctx context.Context, account Account, app Software, versionID string) (map[string]any, []Cookie, error) {
	cookies := append([]Cookie(nil), account.Cookies...)
	useHTTPTest := c != nil && strings.HasPrefix(c.BagURL, "http://")

	send := func(endpoint StoreDownloadEndpoint, version string) (rawResponse, error) {
		payload := map[string]any{
			"creditDisplay": "",
			"guid":          account.DeviceIdentifier,
			"salableAdamId": app.ID,
			"serialNumber":  "0",
		}
		if version != "" {
			payload[endpoint.ExternalVersionIDKey] = version
		}
		body, err := plist.Marshal(payload, plist.XMLFormat)
		if err != nil {
			return rawResponse{}, err
		}

		host := endpoint.Host
		reqPath := endpoint.Path
		scheme := "https"
		if useHTTPTest {
			scheme = "http"
			if c.CatalogHost != "" {
				host = c.CatalogHost
			}
		}

		reqHeaders := map[string]string{
			"Content-Type": "application/x-apple-plist",
			"iCloud-DSID":  account.DSID,
			"X-Dsid":       account.DSID,
		}
		if account.PasswordToken != "" {
			reqHeaders["X-Token"] = account.PasswordToken
		}
		if account.Store != "" {
			sf := account.Store
			if !strings.Contains(sf, "-") {
				sf += "-1"
			}
			reqHeaders["X-Apple-Store-Front"] = sf
		}

		for range 4 {
			resp, err := c.doAppleRequest(ctx, "POST", scheme+"://"+host+reqPath, reqHeaders, body, cookies)
			if err != nil {
				return rawResponse{}, err
			}
			cookies = ExtractAndMergeCookies(resp.SetCookies, cookies)
			if !isRedirectStatus(resp.Status) {
				return resp, nil
			}
			loc := resp.Headers.Get("location")
			if loc == "" {
				return rawResponse{}, &DownloadError{Message: "appstore: missing download redirect location"}
			}
			baseURL, _ := url.Parse(scheme + "://" + host + reqPath)
			rel, err := url.Parse(loc)
			if err != nil {
				return rawResponse{}, err
			}
			resolved := baseURL.ResolveReference(rel)
			if !useHTTPTest {
				if resolved.Scheme != "https" || resolved.Port() != "" || resolved.User != nil || !approvedDownloadHostRe.MatchString(resolved.Hostname()) {
					return rawResponse{}, &DownloadError{Message: "appstore: unsafe Apple download redirect"}
				}
			}
			host = resolved.Host
			reqPath = resolved.RequestURI()
		}
		return rawResponse{}, &DownloadError{Message: "appstore: too many download redirects"}
	}

	primary := VolumeStoreEndpoint(account.Pod, account.DeviceIdentifier)
	resp, err := send(primary, versionID)
	if err != nil {
		return nil, cookies, err
	}
	dict, err := responseDict(resp, primary)
	if err != nil {
		return nil, cookies, err
	}
	if !NeedsDownloadFallback(dict) {
		if err := requireDownloadItems(dict); err != nil {
			return nil, cookies, err
		}
		return dict, cookies, nil
	}

	bag := c.FetchBag(ctx, account.DeviceIdentifier)
	pinnedVersion := versionID
	if pinnedVersion == "" {
		pinnedVersion, err = c.LookupLatestVersion(ctx, account, app)
		if err != nil {
			return nil, cookies, &DownloadError{Message: fmt.Sprintf("appstore: version lookup failed: %v", err)}
		}
	}

	redownload, ok := DispatchEndpoint(bag.RedownloadURL, "redownload", account.DeviceIdentifier)
	if !ok {
		redownload = RedownloadEndpoint(account.DeviceIdentifier)
	}
	rResp, err := send(redownload, pinnedVersion)
	if err != nil {
		return nil, cookies, err
	}
	emptyServerErr := rResp.Status == http.StatusInternalServerError && len(strings.TrimSpace(string(rResp.Body))) == 0
	if !emptyServerErr {
		dict, err = responseDict(rResp, redownload)
		if err != nil {
			if rResp.Status == http.StatusForbidden && len(strings.TrimSpace(string(rResp.Body))) == 0 {
				return nil, cookies, &DownloadError{
					Message: "appstore: Apple DownloadDispatch rejected legacy redownload/update with HTTP 403 (this account/region now requires Apple ent/download with kbsync)",
				}
			}
			return nil, cookies, err
		}
	}

	recoverable := !emptyServerErr && NeedsDownloadFallback(dict) &&
		(stringify(dict["failureType"]) != "" || stringify(dict["customerMessage"]) != "")

	if update, ok := DispatchEndpoint(bag.UpdateURL, "update", account.DeviceIdentifier); ok && (emptyServerErr || recoverable) {
		uResp, err := send(update, pinnedVersion)
		if err != nil {
			return nil, cookies, err
		}
		dict, err = responseDict(uResp, update)
		if err != nil {
			return nil, cookies, err
		}
	} else if emptyServerErr {
		if _, err := responseDict(rResp, redownload); err != nil {
			return nil, cookies, err
		}
	}
	if err := requireDownloadItems(dict); err != nil {
		return nil, cookies, err
	}
	if err := validateDownloadItem(dict, app, pinnedVersion); err != nil {
		return nil, cookies, err
	}
	return dict, cookies, nil
}

// GetDownloadInfo resolves the CDN download URL, SINF blobs, and iTunesMetadata for app.
func (c *Client) GetDownloadInfo(ctx context.Context, account Account, app Software, externalVersionID string) (DownloadOutput, []Cookie, error) {
	dict, cookies, err := c.DownloadProduct(ctx, account, app, externalVersionID)
	if err != nil {
		return DownloadOutput{}, cookies, err
	}
	songs, _ := dict["songList"].([]any)
	item, _ := songs[0].(map[string]any)
	dlURL, _ := item["URL"].(string)
	if dlURL == "" {
		return DownloadOutput{}, cookies, &DownloadError{Message: "appstore: missing download URL"}
	}
	metadata, ok := item["metadata"].(map[string]any)
	if !ok {
		return DownloadOutput{}, cookies, &DownloadError{Message: "appstore: missing product metadata"}
	}
	shortVer, _ := metadata["bundleShortVersionString"].(string)
	bundleVer := stringify(metadata["bundleVersion"])
	if shortVer == "" || bundleVer == "" {
		return DownloadOutput{}, cookies, &DownloadError{Message: "appstore: missing version metadata"}
	}

	rawSinfs, _ := item["sinfs"].([]any)
	var sinfs []Sinf
	for _, entry := range rawSinfs {
		sm, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		id, hasID := numberInt64(sm["id"])
		if !hasID {
			continue
		}
		var data []byte
		switch sv := sm["sinf"].(type) {
		case []byte:
			data = sv
		case string:
			decoded, err := base64.StdEncoding.DecodeString(sv)
			if err != nil {
				return DownloadOutput{}, cookies, &DownloadError{Message: "appstore: invalid base64 SINF"}
			}
			data = decoded
		default:
			return DownloadOutput{}, cookies, &DownloadError{Message: "appstore: invalid SINF payload type"}
		}
		if len(data) == 0 {
			continue
		}
		sinfs = append(sinfs, Sinf{ID: id, Data: data})
	}
	if len(sinfs) == 0 {
		return DownloadOutput{}, cookies, &DownloadError{Message: "appstore: response contained no SINF licenses"}
	}

	metaCopy := make(map[string]any, len(metadata)+2)
	for k, v := range metadata {
		if k == "passwordToken" {
			continue
		}
		metaCopy[k] = v
	}
	metaCopy["apple-id"] = account.Email
	metaCopy["userName"] = account.Email
	metaXML, err := plist.Marshal(metaCopy, plist.XMLFormat)
	if err != nil {
		return DownloadOutput{}, cookies, err
	}

	return DownloadOutput{
		DownloadURL:              dlURL,
		Sinfs:                    sinfs,
		BundleShortVersionString: shortVer,
		BundleVersion:            bundleVer,
		ITunesMetadata:           metaXML,
	}, cookies, nil
}

// ListVersions returns available historical external version IDs from newest to oldest.
func (c *Client) ListVersions(ctx context.Context, account Account, app Software) ([]string, []Cookie, error) {
	dict, cookies, err := c.DownloadProduct(ctx, account, app, "")
	if err != nil {
		return nil, cookies, err
	}
	songs, _ := dict["songList"].([]any)
	item, _ := songs[0].(map[string]any)
	metadata, _ := item["metadata"].(map[string]any)
	rawIDs, ok := metadata["softwareVersionExternalIdentifiers"].([]any)
	if !ok || len(rawIDs) == 0 {
		return nil, cookies, errors.New("appstore: missing version identifiers")
	}
	versions := make([]string, 0, len(rawIDs))
	for i := len(rawIDs) - 1; i >= 0; i-- {
		if s := stringify(rawIDs[i]); s != "" {
			versions = append(versions, s)
		}
	}
	if len(versions) == 0 {
		return nil, cookies, errors.New("appstore: no versions found")
	}
	return versions, cookies, nil
}

// GetVersionMetadata fetches the display version and release date for one historical external version ID.
func (c *Client) GetVersionMetadata(ctx context.Context, account Account, app Software, versionID string) (VersionMetadata, []Cookie, error) {
	dict, cookies, err := c.DownloadProduct(ctx, account, app, versionID)
	if err != nil {
		return VersionMetadata{}, cookies, err
	}
	songs, _ := dict["songList"].([]any)
	item, _ := songs[0].(map[string]any)
	metadata, _ := item["metadata"].(map[string]any)
	displayVer, _ := metadata["bundleShortVersionString"].(string)
	if displayVer == "" {
		return VersionMetadata{}, cookies, errors.New("appstore: missing bundleShortVersionString")
	}
	var releaseDate string
	switch rd := metadata["releaseDate"].(type) {
	case time.Time:
		releaseDate = rd.UTC().Format(time.RFC3339)
	case string:
		releaseDate = rd
	}
	if releaseDate == "" {
		return VersionMetadata{}, cookies, errors.New("appstore: missing releaseDate")
	}
	return VersionMetadata{
		DisplayVersion: displayVer,
		ReleaseDate:    releaseDate,
	}, cookies, nil
}

func responseDict(resp rawResponse, endpoint StoreDownloadEndpoint) (map[string]any, error) {
	if resp.Status == http.StatusOK {
		var dict map[string]any
		if _, err := plist.Unmarshal(resp.Body, &dict); err == nil && dict != nil {
			return dict, nil
		}
	}
	kind := "empty response"
	if len(strings.TrimSpace(string(resp.Body))) > 0 {
		kind = "invalid plist"
	}
	loc := endpoint.Host + strings.SplitN(endpoint.Path, "?", 2)[0]
	return nil, &DownloadError{Message: fmt.Sprintf("appstore: Apple download: HTTP %d; %s; %s", resp.Status, kind, loc)}
}

func requireDownloadItems(dict map[string]any) error {
	code := stringify(dict["failureType"])
	if code != "" {
		msg, _ := dict["customerMessage"].(string)
		if code == "2034" || code == "2042" || msg == "Your password has changed." {
			return &DownloadError{Message: "appstore: Apple ID session expired; sign in again", Code: code}
		}
		if code == "9610" {
			return &DownloadError{Message: "appstore: app license required before downloading", Code: code}
		}
		if msg == "" {
			msg = "Apple download failed"
		}
		return &DownloadError{Message: fmt.Sprintf("%s (%s)", msg, code), Code: code}
	}
	songs, _ := dict["songList"].([]any)
	if len(songs) == 0 {
		if msg, _ := dict["customerMessage"].(string); msg != "" {
			return &DownloadError{Message: msg}
		}
		return &DownloadError{Message: "appstore: no downloadable items returned"}
	}
	return nil
}

func validateDownloadItem(dict map[string]any, app Software, version string) error {
	songs, _ := dict["songList"].([]any)
	if len(songs) != 1 {
		return &DownloadError{Message: "appstore: unexpected item count in download response"}
	}
	item, _ := songs[0].(map[string]any)
	meta, _ := item["metadata"].(map[string]any)
	if meta == nil {
		return &DownloadError{Message: "appstore: unexpected item metadata in download response"}
	}
	if stringify(meta["itemId"]) != strconv.FormatInt(app.ID, 10) {
		return &DownloadError{Message: "appstore: download itemId mismatch"}
	}
	if version != "" && stringify(meta["softwareVersionExternalIdentifier"]) != version {
		return &DownloadError{Message: "appstore: download version mismatch"}
	}
	bundleID, _ := meta["softwareVersionBundleId"].(string)
	if bundleID == "" || (app.BundleID != "" && bundleID != app.BundleID) {
		return &DownloadError{Message: "appstore: download bundleID mismatch"}
	}
	return nil
}

func stringifyJSONNumber(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case json.Number:
		return x.String()
	default:
		return ""
	}
}
