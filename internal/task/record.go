// Package task records one local IPA job. A record has paths and hashes,
// never an account secret or a pairing record.
package task

import "time"

// Record is the durable summary of one export.
type Record struct {
	InputSHA256  string
	OutputPath   string
	OutputSHA256 string
	Version      string
	Changes      []string
	Created      time.Time
}
