package appstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"howett.net/plist"
)

// PurchaseError describes a Store license acquisition failure.
type PurchaseError struct {
	Message  string
	Code     string
	TermsURL string
}

func (e *PurchaseError) Error() string { return e.Message }

// PurchaseResult contains updated cookies and whether the account already owned the license.
type PurchaseResult struct {
	UpdatedCookies []Cookie
	AlreadyOwned   bool
}

// PurchaseApp acquires a free App Store license for app on account.
// Paid apps are rejected. failureType 5002 ("already licensed") succeeds with AlreadyOwned=true.
func (c *Client) PurchaseApp(ctx context.Context, account Account, app Software) (PurchaseResult, error) {
	if app.Price > 0 {
		return PurchaseResult{}, &PurchaseError{Message: "appstore: paid app purchase is not supported"}
	}
	res, err := c.purchaseWithParams(ctx, account, app, "STDQ")
	if err != nil {
		var pe *PurchaseError
		if errors.As(err, &pe) && pe.Code == "2059" {
			return c.purchaseWithParams(ctx, account, app, "GAME")
		}
		return PurchaseResult{}, err
	}
	return res, nil
}

func (c *Client) purchaseWithParams(ctx context.Context, account Account, app Software, pricingParameters string) (PurchaseResult, error) {
	host := PurchaseAPIHost(account.Pod)
	scheme := "https://"
	if c != nil && c.BagURL != "" && strings.HasPrefix(c.BagURL, "http://") {
		scheme = "http://"
		if c.CatalogHost != "" {
			host = c.CatalogHost
		}
	}
	targetURL := scheme + host + "/WebObjects/MZFinance.woa/wa/buyProduct"

	payload := map[string]any{
		"appExtVrsId":               "0",
		"hasAskedToFulfillPreorder": "true",
		"buyWithoutAuthorization":   "true",
		"hasDoneAgeCheck":           "true",
		"guid":                      account.DeviceIdentifier,
		"needDiv":                   "0",
		"origPage":                  fmt.Sprintf("Software-%d", app.ID),
		"origPageLocation":          "Buy",
		"price":                     "0",
		"pricingParameters":         pricingParameters,
		"productType":               "C",
		"salableAdamId":             app.ID,
	}
	body, err := plist.Marshal(payload, plist.XMLFormat)
	if err != nil {
		return PurchaseResult{}, err
	}

	headers := map[string]string{
		"Content-Type":        "application/x-apple-plist",
		"iCloud-DSID":         account.DSID,
		"X-Dsid":              account.DSID,
		"X-Apple-Store-Front": account.Store + "-1",
		"X-Token":             account.PasswordToken,
	}

	resp, err := c.doAppleRequest(ctx, "POST", targetURL, headers, body, account.Cookies)
	if err != nil {
		return PurchaseResult{}, err
	}
	updatedCookies := ExtractAndMergeCookies(resp.SetCookies, account.Cookies)

	if resp.Status != http.StatusOK {
		return PurchaseResult{}, &PurchaseError{Message: fmt.Sprintf("appstore: purchase failed (HTTP %d)", resp.Status)}
	}

	var dict map[string]any
	if _, err := plist.Unmarshal(resp.Body, &dict); err != nil {
		return PurchaseResult{}, &PurchaseError{Message: fmt.Sprintf("appstore: invalid purchase response: %v", err)}
	}

	if ft := stringify(dict["failureType"]); ft != "" {
		customerMsg, _ := dict["customerMessage"].(string)
		switch ft {
		case "5002":
			return PurchaseResult{UpdatedCookies: updatedCookies, AlreadyOwned: true}, nil
		case "2059":
			return PurchaseResult{}, &PurchaseError{Message: "appstore: item temporarily unavailable", Code: "2059"}
		case "2034", "2042":
			return PurchaseResult{}, &PurchaseError{Message: "appstore: Apple ID session expired; sign in again", Code: ft}
		default:
			if customerMsg == "Your password has changed." {
				return PurchaseResult{}, &PurchaseError{Message: "appstore: Apple ID session expired; sign in again", Code: ft}
			}
			if customerMsg == "Subscription Required" {
				return PurchaseResult{}, &PurchaseError{Message: "appstore: subscription required", Code: ft}
			}
			if action, ok := dict["action"].(map[string]any); ok {
				actionURL, _ := action["url"].(string)
				if actionURL == "" {
					actionURL, _ = action["URL"].(string)
				}
				if strings.HasSuffix(actionURL, "termsPage") {
					return PurchaseResult{}, &PurchaseError{
						Message:  fmt.Sprintf("appstore: Apple terms acceptance required (%s)", actionURL),
						Code:     ft,
						TermsURL: actionURL,
					}
				}
			}
			if customerMsg == "" || customerMsg == "An unknown error has occurred" || customerMsg == "An unknown error has occurred." {
				customerMsg = fmt.Sprintf("appstore: purchase failed (code %s)", ft)
			}
			return PurchaseResult{}, &PurchaseError{Message: customerMsg, Code: ft}
		}
	}

	jingleDocType, _ := dict["jingleDocType"].(string)
	status, hasStatus := numberInt64(dict["status"])
	if jingleDocType != "purchaseSuccess" || !hasStatus || status != 0 {
		return PurchaseResult{}, &PurchaseError{Message: "appstore: purchase failed"}
	}

	return PurchaseResult{UpdatedCookies: updatedCookies, AlreadyOwned: false}, nil
}

func numberInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case uint64:
		return int64(x), true
	default:
		return 0, false
	}
}
