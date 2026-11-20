package ipa

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ExtractZIP safely extracts a validated IPA ZIP into an existing empty directory.
// It rejects links and bounds actual decompressed bytes, not only ZIP metadata.
func ExtractZIP(zr *zip.Reader, destination string) error {
	if err := validateZIP(zr); err != nil {
		return err
	}

	root, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: extraction root is not a real directory", ErrUnsafe)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%w: extraction root is not empty", ErrUnsafe)
	}

	seen := make(map[string]struct{}, len(zr.File))
	for _, zf := range zr.File {
		if err := safeName(zf.Name); err != nil {
			return err
		}
		clean := path.Clean(zf.Name)
		if _, ok := seen[clean]; ok {
			return fmt.Errorf("%w: duplicate ZIP path %q", ErrUnsafe, zf.Name)
		}
		seen[clean] = struct{}{}

		rel := filepath.FromSlash(clean)
		dest := filepath.Join(root, rel)
		within, err := filepath.Rel(root, dest)
		if err != nil || within == ".." || strings.HasPrefix(within, ".."+string(filepath.Separator)) || filepath.IsAbs(within) {
			return fmt.Errorf("%w: path escapes extraction root: %q", ErrUnsafe, zf.Name)
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		mode := zf.Mode().Perm() & 0o777
		if mode == 0 {
			mode = 0o644
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		r, err := zf.Open()
		if err != nil {
			_ = out.Close()
			return fmt.Errorf("%w: %s", ErrUnsafe, zf.Name)
		}
		written, copyErr := io.Copy(out, io.LimitReader(r, maxFileBytes+1))
		closeReadErr := r.Close()
		closeWriteErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeReadErr != nil {
			return closeReadErr
		}
		if closeWriteErr != nil {
			return closeWriteErr
		}
		if written > maxFileBytes || uint64(written) != zf.UncompressedSize64 {
			return fmt.Errorf("%w: invalid or oversized entry %q", ErrUnsafe, zf.Name)
		}
	}
	return nil
}
