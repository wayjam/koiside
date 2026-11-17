package appstore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type itunesSearchResponse struct {
	ResultCount int               `json:"resultCount"`
	Results     []itunesRawResult `json:"results"`
}

type itunesRawResult struct {
	TrackID                   int64     `json:"trackId"`
	BundleID                  string    `json:"bundleId"`
	TrackName                 string    `json:"trackName"`
	Version                   string    `json:"version"`
	Price                     float64   `json:"price"`
	ArtistName                string    `json:"artistName"`
	SellerName                string    `json:"sellerName"`
	Description               string    `json:"description"`
	AverageUserRating         float64   `json:"averageUserRating"`
	UserRatingCount           int64     `json:"userRatingCount"`
	ArtworkURL512             string    `json:"artworkUrl512"`
	ArtworkURL100             string    `json:"artworkUrl100"`
	ScreenshotURLs            []string  `json:"screenshotUrls"`
	MinimumOSVersion          string    `json:"minimumOsVersion"`
	FileSizeBytes             flexInt64 `json:"fileSizeBytes"`
	CurrentVersionReleaseDate string    `json:"currentVersionReleaseDate"`
	ReleaseDate               string    `json:"releaseDate"`
	ReleaseNotes              string    `json:"releaseNotes"`
	FormattedPrice            string    `json:"formattedPrice"`
	PrimaryGenreName          string    `json:"primaryGenreName"`
}

func (r itunesRawResult) toSoftware() Software {
	art := r.ArtworkURL512
	if art == "" {
		art = r.ArtworkURL100
	}
	relDate := r.CurrentVersionReleaseDate
	if relDate == "" {
		relDate = r.ReleaseDate
	}
	shots := r.ScreenshotURLs
	if shots == nil {
		shots = []string{}
	}
	return Software{
		ID:                r.TrackID,
		BundleID:          r.BundleID,
		Name:              r.TrackName,
		Version:           r.Version,
		Price:             r.Price,
		ArtistName:        r.ArtistName,
		SellerName:        r.SellerName,
		Description:       r.Description,
		AverageUserRating: r.AverageUserRating,
		UserRatingCount:   r.UserRatingCount,
		ArtworkURL:        art,
		ScreenshotURLs:    shots,
		MinimumOSVersion:  r.MinimumOSVersion,
		FileSizeBytes:     int64(r.FileSizeBytes),
		ReleaseDate:       relDate,
		ReleaseNotes:      r.ReleaseNotes,
		FormattedPrice:    r.FormattedPrice,
		PrimaryGenreName:  r.PrimaryGenreName,
	}
}

func (c *Client) searchBaseURL() string {
	if c != nil && c.SearchBase != "" {
		return strings.TrimRight(c.SearchBase, "/")
	}
	return "https://itunes.apple.com"
}

// SearchApps searches the public iTunes Store catalog for iOS/iPadOS software.
func (c *Client) SearchApps(ctx context.Context, term, country, entity string, limit int) ([]Software, error) {
	if strings.TrimSpace(term) == "" {
		return nil, nil
	}
	if country == "" {
		country = "US"
	}
	if entity == "" {
		entity = "software"
	}
	if limit <= 0 {
		limit = 25
	}
	q := url.Values{
		"term":    {term},
		"country": {strings.ToUpper(country)},
		"entity":  {entity},
		"media":   {"software"},
		"limit":   {strconv.Itoa(limit)},
	}
	resp, err := c.doAppleRequest(ctx, "GET", c.searchBaseURL()+"/search?"+q.Encode(), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("appstore: search failed (HTTP %d)", resp.Status)
	}
	var parsed itunesSearchResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("appstore: decode search results: %w", err)
	}
	out := make([]Software, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		out = append(out, r.toSoftware())
	}
	return out, nil
}

// LookupApp looks up one app by bundleID or numeric App Store track ID.
func (c *Client) LookupApp(ctx context.Context, bundleID string, trackID int64, country string) (*Software, error) {
	if country == "" {
		country = "US"
	}
	q := url.Values{
		"country": {strings.ToUpper(country)},
	}
	if bundleID != "" {
		q.Set("bundleId", bundleID)
	} else if trackID > 0 {
		q.Set("id", strconv.FormatInt(trackID, 10))
	} else {
		return nil, fmt.Errorf("appstore: bundleID or trackID is required")
	}

	resp, err := c.doAppleRequest(ctx, "GET", c.searchBaseURL()+"/lookup?"+q.Encode(), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("appstore: lookup failed (HTTP %d)", resp.Status)
	}
	var parsed itunesSearchResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("appstore: decode lookup result: %w", err)
	}
	if parsed.ResultCount == 0 || len(parsed.Results) == 0 {
		return nil, nil
	}
	sw := parsed.Results[0].toSoftware()
	return &sw, nil
}
