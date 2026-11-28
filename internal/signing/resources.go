package signing

import (
	"crypto/sha1"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

// BuildCodeResources generates _CodeSignature/CodeResources XML plist for bundleDir,
// hashing all non-main-executable files (including signed nested frameworks and plugins)
// with SHA-1 and SHA-256 while omitting only this bundle's own _CodeSignature directory.
func BuildCodeResources(bundleDir, mainExecutable string) ([]byte, error) {
	files := map[string]any{}
	files2 := map[string]any{}

	err := filepath.WalkDir(bundleDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(bundleDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if rel == "_CodeSignature" || strings.HasPrefix(rel, "_CodeSignature/") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if rel == mainExecutable || rel == "CodeResources" || strings.HasSuffix(rel, ".DS_Store") || rel == ".DS_Store" {
			return nil
		}
		if rel == "Info.plist" || rel == "PkgInfo" {
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			s1 := sha1.Sum(raw)
			files[rel] = s1[:]
			return nil
		}

		if d.Type()&os.ModeSymlink != 0 {
			target, linkErr := os.Readlink(path)
			if linkErr != nil {
				return linkErr
			}
			files2[rel] = map[string]any{"symlink": target}
			return nil
		}

		var s1 [20]byte
		var s2 [32]byte
		info, statErr := d.Info()
		if statErr == nil && info.Size() <= 64*1024 {
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			s1 = sha1.Sum(raw)
			s2 = sha256.Sum256(raw)
		} else {
			f, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			h1 := sha1.New()
			h2 := sha256.New()
			mw := io.MultiWriter(h1, h2)
			buf := make([]byte, 64*1024)
			_, copyErr := io.CopyBuffer(mw, f, buf)
			_ = f.Close()
			if copyErr != nil {
				return copyErr
			}
			copy(s1[:], h1.Sum(nil))
			copy(s2[:], h2.Sum(nil))
		}
		files[rel] = s1[:]
		files2[rel] = map[string]any{
			"hash":  s1[:],
			"hash2": s2[:],
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	rules := map[string]any{
		"^.*": true,
		"^.*\\.lproj/": map[string]any{
			"optional": true,
			"weight":   float64(1000),
		},
		"^.*\\.lproj/locversion.plist$": map[string]any{
			"omit":   true,
			"weight": float64(1100),
		},
		"^Base\\.lproj/": map[string]any{
			"weight": float64(1010),
		},
		"^version.plist$": true,
	}
	rules2 := map[string]any{
		"^.*": true,
		"^.*\\.lproj/": map[string]any{
			"optional": true,
			"weight":   float64(1000),
		},
		"^.*\\.lproj/locversion.plist$": map[string]any{
			"omit":   true,
			"weight": float64(1100),
		},
		"^Base\\.lproj/": map[string]any{
			"weight": float64(1010),
		},
		"^Info\\.plist$": map[string]any{
			"omit":   true,
			"weight": float64(20),
		},
		"^PkgInfo$": map[string]any{
			"omit":   true,
			"weight": float64(20),
		},
		"^embedded\\.provisionprofile$": map[string]any{
			"weight": float64(20),
		},
		"^version\\.plist$": map[string]any{
			"weight": float64(20),
		},
		".*\\.dSYM($|/)": map[string]any{
			"weight": float64(11),
		},
		"^(.*/)?\\.DS_Store$": map[string]any{
			"omit":   true,
			"weight": float64(2000),
		},
	}

	doc := map[string]any{
		"files":  files,
		"files2": files2,
		"rules":  rules,
		"rules2": rules2,
	}
	return plist.Marshal(doc, plist.XMLFormat)
}
