package shell

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/i18n"
	"github.com/egoist/mygo/ui"

	"koiside/internal/ipa"
	"koiside/locales"
)

const (
	langSystem = ""
	langZhHans = "zh-Hans"
	langEn     = "en"
	langRu     = "ru"
	langJa     = "ja"
)

// effectiveLocale resolves the active BCP 47 tag for rendering.
// Explicit Model choice overrides context/app locale so both live windows and
// headless ui.Tester switches update immediately.
func (m *Model) effectiveLocale(c *ui.Context) string {
	m.mu.Lock()
	lang := m.language
	m.mu.Unlock()
	if lang != "" {
		return lang
	}
	if c != nil {
		if l := c.Locale(); l != "" {
			return l
		}
	}
	if l := i18n.Locale(); l != "" {
		return l
	}
	return langZhHans
}

func (m *Model) msg(c *ui.Context) locales.Messages {
	return locales.In(m.effectiveLocale(c))
}

func progressStageLabel(msg locales.Messages, stage string) string {
	switch strings.ToLower(stage) {
	case "preparing":
		return msg.ProgressStagePreparing()
	case "download":
		return msg.ProgressStageDownload()
	case "certificate":
		return msg.ProgressStageCertificate()
	case "signing":
		return msg.ProgressStageSigning()
	case "usb_install":
		return msg.ProgressStageUSBInstall()
	case "pairing":
		return msg.ProgressStagePairing()
	case "complete", "готово", "完了":
		return msg.ProgressStageComplete()
	case "connecting to afc":
		return msg.ProgressStageConnectAFC()
	case "uploading app bundle":
		return msg.ProgressStageUploadApp()
	case "uploading ipa":
		return msg.ProgressStageUploadIPA()
	case "connecting to installation_proxy":
		return msg.ProgressStageConnectInstallProxy()
	default:
		return stage
	}
}

// SetLanguage sets the UI language. Empty follows the system preferred languages.
func (m *Model) SetLanguage(tag string) {
	norm := ""
	if strings.TrimSpace(tag) != "" {
		norm = i18n.Normalize(tag)
		if norm == "" {
			norm = tag
		}
	}
	m.mu.Lock()
	m.language = norm
	m.mu.Unlock()
	if norm == "" {
		m.addLog("language: follow system")
	} else {
		m.addLog("language: " + norm)
	}
	if m.win != nil {
		go mygo.App.SetLocale(norm)
		m.win.Invalidate()
	}
}

func (m *Model) currentLanguage() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.language
}

func (m *Model) appearanceMode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.appearance {
	case "light", "浅色":
		return "light"
	case "dark", "深色":
		return "dark"
	default:
		return "system"
	}
}

func (m *Model) setAppearance(mode string) {
	m.mu.Lock()
	m.appearance = mode
	m.mu.Unlock()
	m.addLog("appearance: " + mode)
	if m.win != nil {
		src := mygo.ThemeSystem
		switch mode {
		case "light", "浅色":
			src = mygo.ThemeLight
		case "dark", "深色":
			src = mygo.ThemeDark
		}
		mygo.Theme.SetSource(src)
		m.win.Invalidate()
	}
}

func valueOrUnknown(msg locales.Messages, value string) string {
	if value == "" {
		return msg.LibraryUnknown()
	}
	return value
}

func statusLabel(msg locales.Messages, report ipa.Report) string {
	severity := ipa.Unknown
	for _, finding := range report.Findings {
		if finding.Severity == ipa.Block {
			return msg.SeverityBlock()
		}
		if finding.Severity == ipa.Warn {
			severity = ipa.Warn
		}
	}
	return severityLabel(msg, severity)
}

func severityLabel(msg locales.Messages, severity ipa.Severity) string {
	switch severity {
	case ipa.Block:
		return msg.SeverityBlock()
	case ipa.Warn:
		return msg.SeverityWarn()
	default:
		return msg.SeverityUnknown()
	}
}

func findingDetail(msg locales.Messages, f ipa.Finding) string {
	switch f.Code {
	case "fairplay":
		return msg.FindingFairplay()
	case "cryptid":
		return msg.FindingCryptidMissing()
	case "provenance":
		return msg.FindingProvenance()
	case "dylib":
		return msg.FindingDylib()
	case "registration-name":
		return msg.FindingRegName()
	case "resign":
		return msg.FindingResign()
	case "sidestore-id":
		return msg.FindingSideStoreID()
	case "remove":
		return msg.FindingRemove()
	case "watch":
		return msg.FindingWatch()
	case "payload":
		if strings.Contains(f.Detail, "多个") {
			return msg.FindingMultipleApps()
		}
		if strings.Contains(f.Detail, "没有找到") {
			return msg.FindingNoMainApp()
		}
	}
	return f.Detail
}

func diffFieldLabel(msg locales.Messages, field string) string {
	switch field {
	case "组件":
		return msg.DiffFieldComponent()
	case "Bundle ID":
		return msg.DiffFieldBundleID()
	case "显示名":
		return msg.DiffFieldDisplayName()
	case "本地化名":
		return msg.DiffFieldLocalizedName()
	case "Watch 伴随标识":
		return msg.DiffFieldWatchID()
	default:
		return field
	}
}

func diffActionLabel(msg locales.Messages, value string) string {
	if value == "移除" {
		return msg.DiffActionRemove()
	}
	return value
}

func componentKindLabel(msg locales.Messages, kind string) string {
	switch kind {
	case "app", "主应用":
		return msg.DiffComponentKindApp()
	case "extension":
		return msg.DiffComponentKindExt()
	case "watch":
		return msg.DiffComponentKindWatch()
	case "watch-extension":
		return msg.DiffComponentKindWatchExt()
	default:
		return kind
	}
}

func hasBlockedFairPlay(report ipa.Report) bool {
	for _, f := range report.Findings {
		if f.Code == "fairplay" && f.Severity == ipa.Block {
			return true
		}
	}
	return false
}

func formatBytes(size int64) string {
	if size <= 0 {
		return ""
	}
	const mb = 1024 * 1024
	if size >= mb {
		return fmt.Sprintf("%.1f MB", float64(size)/float64(mb))
	}
	if size >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%d B", size)
}

func friendlyError(msg locales.Messages, raw string) string {
	if raw == "" {
		return ""
	}
	low := strings.ToLower(raw)
	switch {
	case strings.Contains(low, "locked") || strings.Contains(low, "passcode"):
		return msg.ErrFriendlyLocked()
	case strings.Contains(low, "untrusted") || strings.Contains(low, "pair"):
		return msg.ErrFriendlyUntrusted()
	case strings.Contains(low, "no device") || strings.Contains(low, "usbmuxd"):
		return msg.ErrFriendlyNoDevice()
	case strings.Contains(low, "7460") || strings.Contains(low, "maximum number of certificates"):
		return msg.ErrFriendlyMaxCerts()
	case strings.Contains(low, "9120") || strings.Contains(low, "10 app id"):
		return msg.ErrFriendlyMaxAppIDs()
	case strings.Contains(low, "not signed in") || strings.Contains(low, "2fa") || strings.Contains(low, "bad password") || strings.Contains(low, "20101") || strings.Contains(low, "22406"):
		return msg.ErrFriendlyAuth()
	case strings.Contains(low, "timeout") || strings.Contains(low, "deadline") || strings.Contains(low, "eof") || strings.Contains(low, "connection refused") || strings.Contains(low, "no such host"):
		return msg.ErrFriendlyNetwork()
	default:
		return msg.ErrFriendlyUnexpected(raw)
	}
}
