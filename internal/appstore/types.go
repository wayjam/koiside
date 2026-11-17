package appstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultUserAgent matches Apple Configurator 2.17 expected by Apple Store endpoints.
const DefaultUserAgent = "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"

// Cookie represents a Store HTTP cookie persisted across Apple Store requests.
type Cookie struct {
	Name      string  `json:"name"`
	Value     string  `json:"value"`
	Path      string  `json:"path"`
	Domain    string  `json:"domain,omitempty"`
	ExpiresAt float64 `json:"expiresAt,omitempty"`
	HTTPOnly  bool    `json:"httpOnly,omitempty"`
	Secure    bool    `json:"secure,omitempty"`
}

// Account holds an authenticated Apple App Store session.
type Account struct {
	Email            string   `json:"email"`
	AppleID          string   `json:"appleId,omitempty"`
	Store            string   `json:"store"`
	FirstName        string   `json:"firstName,omitempty"`
	LastName         string   `json:"lastName,omitempty"`
	PasswordToken    string   `json:"passwordToken"`
	DSID             string   `json:"directoryServicesIdentifier"`
	Cookies          []Cookie `json:"cookies,omitempty"`
	DeviceIdentifier string   `json:"deviceIdentifier"`
	Pod              string   `json:"pod,omitempty"`
}

// Software represents an App Store application record mapped from iTunes Search/Lookup.
type Software struct {
	ID                int64    `json:"id"`
	BundleID          string   `json:"bundleID"`
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	Price             float64  `json:"price"`
	ArtistName        string   `json:"artistName"`
	SellerName        string   `json:"sellerName"`
	Description       string   `json:"description"`
	AverageUserRating float64  `json:"averageUserRating"`
	UserRatingCount   int64    `json:"userRatingCount"`
	ArtworkURL        string   `json:"artworkUrl"`
	ScreenshotURLs    []string `json:"screenshotUrls"`
	MinimumOSVersion  string   `json:"minimumOsVersion"`
	FileSizeBytes     int64    `json:"fileSizeBytes"`
	ReleaseDate       string   `json:"releaseDate"`
	ReleaseNotes      string   `json:"releaseNotes"`
	FormattedPrice    string   `json:"formattedPrice"`
	PrimaryGenreName  string   `json:"primaryGenreName"`
}

// Sinf holds one DRM license signature block returned by Apple Store download endpoints.
type Sinf struct {
	ID   int64  `json:"id"`
	Data []byte `json:"sinf"`
}

// DownloadOutput contains the public Apple CDN URL, SINF blobs, and metadata needed to assemble an IPA.
type DownloadOutput struct {
	DownloadURL              string
	Sinfs                    []Sinf
	BundleShortVersionString string
	BundleVersion            string
	ITunesMetadata           []byte // XML plist bytes (converted to binary plist on IPA injection)
}

// VersionMetadata describes one historical version of an app.
type VersionMetadata struct {
	DisplayVersion string `json:"displayVersion"`
	ReleaseDate    string `json:"releaseDate"`
}

// StoreDownloadEndpoint describes one Store product download endpoint.
type StoreDownloadEndpoint struct {
	Host                 string
	Path                 string
	ExternalVersionIDKey string
}

// Client performs App Store protocol requests over standard HTTPS without automatic redirects.
type Client struct {
	HTTPClient *http.Client
	UserAgent  string

	// Optional overrides for tests (empty uses production Apple endpoints).
	BagURL       string
	SAPCertURL   string
	SAPSetupURL  string
	SearchBase   string
	CatalogHost  string
	AuthSleep    func(ctx context.Context, d time.Duration) error
	DownloadWait time.Duration
}

// NewClient creates a default App Store protocol client that never follows redirects automatically.
func NewClient() *Client {
	return &Client{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		UserAgent: DefaultUserAgent,
	}
}

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *Client) userAgent() string {
	if c != nil && c.UserAgent != "" {
		return c.UserAgent
	}
	return DefaultUserAgent
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c != nil && c.AuthSleep != nil {
		return c.AuthSleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type rawResponse struct {
	Status     int
	Headers    http.Header
	SetCookies []string
	Body       []byte
}

func (c *Client) doAppleRequest(ctx context.Context, method, rawURL string, headers map[string]string, body []byte, cookies []Cookie) (rawResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return rawResponse{}, err
	}
	req.Header.Set("User-Agent", c.userAgent())
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if len(cookies) > 0 {
		if hdr := BuildCookieHeader(cookies, rawURL); hdr != "" {
			req.Header.Set("Cookie", hdr)
		}
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return rawResponse{}, err
	}
	defer resp.Body.Close()

	const maxBody = 8 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return rawResponse{}, err
	}
	if len(data) > maxBody {
		return rawResponse{}, errors.New("appstore: response exceeds 8 MiB limit")
	}

	return rawResponse{
		Status:     resp.StatusCode,
		Headers:    resp.Header,
		SetCookies: resp.Header.Values("Set-Cookie"),
		Body:       data,
	}, nil
}

// GenerateDeviceID returns a random 12-character lowercase hex identifier (6 bytes).
func GenerateDeviceID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%012x", time.Now().UnixNano()&0xffffffffffff)
	}
	return hex.EncodeToString(b[:])
}

// StoreAPIHost returns the pod-scoped Store API host.
func StoreAPIHost(pod string) string {
	if pod != "" {
		return "p" + pod + "-buy.itunes.apple.com"
	}
	return "p25-buy.itunes.apple.com"
}

// PurchaseAPIHost returns the pod-scoped Purchase API host.
func PurchaseAPIHost(pod string) string {
	if pod != "" {
		return "p" + pod + "-buy.itunes.apple.com"
	}
	return "buy.itunes.apple.com"
}

// VolumeStoreEndpoint returns the primary Store download endpoint for pod + deviceID.
func VolumeStoreEndpoint(pod, deviceID string) StoreDownloadEndpoint {
	return StoreDownloadEndpoint{
		Host:                 StoreAPIHost(pod),
		Path:                 "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=" + deviceID,
		ExternalVersionIDKey: "externalVersionId",
	}
}

// RedownloadEndpoint returns the fallback redownload dispatch endpoint for deviceID.
func RedownloadEndpoint(deviceID string) StoreDownloadEndpoint {
	return StoreDownloadEndpoint{
		Host:                 "downloaddispatch.itunes.apple.com",
		Path:                 "/r/redownload?guid=" + deviceID,
		ExternalVersionIDKey: "appExtVrsId",
	}
}

type flexInt64 int64

func (f *flexInt64) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	if strings.HasPrefix(s, "\"") {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		if str == "" {
			*f = 0
			return nil
		}
		n, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return err
		}
		*f = flexInt64(n)
		return nil
	}
	var n int64
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*f = flexInt64(n)
	return nil
}
