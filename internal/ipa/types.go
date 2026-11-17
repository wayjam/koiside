package ipa

import "errors"

const (
	maxEntries        = 16384
	maxFileBytes      = 512 << 20
	maxArchiveBytes   = 2 << 30
	maxExpansion      = 100
	minBombCheckBytes = 1 << 20
	machoHeaderLimit  = 64 << 10
)

// ErrUnsafe is returned when an archive can escape its directory, exceed
// the size limits, or is not a readable ZIP. No partial tree is kept.
var ErrUnsafe = errors.New("ipa: unsafe archive")

// ErrExists is returned when the requested output path already exists.
var ErrExists = errors.New("ipa: output exists")

// Severity is what the check can support. Unknown is never shown as success.
type Severity string

const (
	Warn    Severity = "warn"
	Block   Severity = "block"
	Unknown Severity = "unknown"
)

// Finding is one check result. A clear field is not a finding and is not
// evidence that the app is official or unmodified.
type Finding struct {
	Code     string
	Severity Severity
	Path     string
	Detail   string
}

// Component is one app, extension, or Watch bundle inside the archive.
type Component struct {
	Path          string
	Kind          string
	BundleID      string
	DisplayName   string
	Version       string
	Build         string
	MinimumOS     string
	Executable    string
	CompanionID   string
	URLSchemes    []string
	Localizations map[string]string
}

// MachO is one architecture slice. CryptID is nil when the header has no
// encryption command. Signed means a signature blob exists, not that it
// was verified.
type MachO struct {
	Path      string
	Arch      string
	CryptID   *int
	Encrypted bool
	Signed    bool
}

// Report is the read-only inspection. SHA256 identifies the file bytes;
// it does not identify the publisher.
type Report struct {
	SHA256       string
	Scope        string
	BundleID     string
	DisplayName  string
	Version      string
	Build        string
	Components   []Component
	MachOs       []MachO
	Dylibs       []string
	Findings     []Finding
	IconPNG      []byte
	HasSinf      bool
	HasStoreMeta bool
}

// Change is a reviewed edit. Empty fields stay unchanged. Components and
// URL schemes are kept unless Remove lists their archive path.
type Change struct {
	BundleID      string
	DisplayName   string
	LocalizedName string
	Remove        []string
}

// DiffItem is one visible difference between the input and the export.
type DiffItem struct {
	Path   string
	Field  string
	Before string
	After  string
}

// Diff is the preview shown before Export. It does not write a file.
type Diff struct {
	Items    []DiffItem
	Findings []Finding
}
