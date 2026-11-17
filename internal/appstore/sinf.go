package appstore

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"howett.net/plist"
)

type ipaInjectMeta struct {
	bundleName string
	sinfPaths  []string
	executable string
}

// InjectSinfAndMetadata injects DRM SINF signatures and binary iTunesMetadata.plist
// into an existing IPA archive using pure Go archive/zip stream copying (no external zip CLI).
func InjectSinfAndMetadata(ipaPath string, sinfs []Sinf, iTunesMetadataXML []byte) error {
	meta, err := readIPAInjectMeta(ipaPath)
	if err != nil {
		return err
	}

	type injectEntry struct {
		name string
		data []byte
	}
	var additions []injectEntry

	if meta.sinfPaths != nil {
		for i, sinfRel := range meta.sinfPaths {
			if i >= len(sinfs) {
				continue
			}
			target, err := safePayloadEntry(meta.bundleName, sinfRel)
			if err != nil {
				return err
			}
			additions = append(additions, injectEntry{name: target, data: sinfs[i].Data})
		}
	} else if meta.executable != "" {
		if len(sinfs) > 0 {
			target, err := safePayloadEntry(meta.bundleName, "SC_Info/"+meta.executable+".sinf")
			if err != nil {
				return err
			}
			additions = append(additions, injectEntry{name: target, data: sinfs[0].Data})
		}
	} else {
		return errors.New("appstore: could not read Manifest.plist or Info.plist in IPA")
	}

	if len(iTunesMetadataXML) > 0 {
		metaBytes := iTunesMetadataXML
		var parsed any
		if _, err := plist.Unmarshal(iTunesMetadataXML, &parsed); err == nil && parsed != nil {
			if bin, bErr := plist.Marshal(parsed, plist.BinaryFormat); bErr == nil {
				metaBytes = bin
			}
		}
		additions = append(additions, injectEntry{name: "iTunesMetadata.plist", data: metaBytes})
	}

	if len(additions) == 0 {
		return nil
	}

	replaceSet := make(map[string]bool, len(additions))
	for _, a := range additions {
		replaceSet[a.name] = true
	}

	srcFile, err := os.Open(ipaPath)
	if err != nil {
		return err
	}
	stat, err := srcFile.Stat()
	if err != nil {
		_ = srcFile.Close()
		return err
	}
	zr, err := zip.NewReader(srcFile, stat.Size())
	if err != nil {
		_ = srcFile.Close()
		return fmt.Errorf("appstore: open IPA zip: %w", err)
	}

	tmpDir := filepath.Dir(ipaPath)
	tmpFile, err := os.CreateTemp(tmpDir, filepath.Base(ipaPath)+".inject-*")
	if err != nil {
		_ = srcFile.Close()
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	zw := zip.NewWriter(tmpFile)
	for _, zf := range zr.File {
		if replaceSet[zf.Name] {
			continue
		}
		if err := zw.Copy(zf); err != nil {
			_ = zw.Close()
			_ = srcFile.Close()
			return fmt.Errorf("appstore: copy zip entry %s: %w", zf.Name, err)
		}
	}
	for _, a := range additions {
		hdr := &zip.FileHeader{
			Name:   a.name,
			Method: zip.Store,
		}
		hdr.SetMode(0o644)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			_ = zw.Close()
			_ = srcFile.Close()
			return err
		}
		if _, err := w.Write(a.data); err != nil {
			_ = zw.Close()
			_ = srcFile.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		_ = srcFile.Close()
		return err
	}
	_ = srcFile.Close()
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, ipaPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func readIPAInjectMeta(ipaPath string) (ipaInjectMeta, error) {
	f, err := os.Open(ipaPath)
	if err != nil {
		return ipaInjectMeta{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ipaInjectMeta{}, err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return ipaInjectMeta{}, err
	}

	var bundleName string
	var manifestBytes []byte
	var infoBytes []byte

	for _, zf := range zr.File {
		name := zf.Name
		if !strings.Contains(name, "/Watch/") && strings.HasSuffix(name, ".app/Info.plist") && strings.HasPrefix(name, "Payload/") {
			parts := strings.Split(name, "/")
			if len(parts) == 3 && strings.HasSuffix(parts[1], ".app") {
				if bundleName == "" {
					bundleName = strings.TrimSuffix(parts[1], ".app")
				}
				if infoBytes == nil {
					b, err := readSmallZipEntry(zf, 4<<20)
					if err != nil {
						return ipaInjectMeta{}, err
					}
					infoBytes = b
				}
			}
		}
		if manifestBytes == nil && strings.HasPrefix(name, "Payload/") && strings.HasSuffix(name, ".app/SC_Info/Manifest.plist") && !strings.Contains(name, "/Watch/") {
			parts := strings.Split(name, "/")
			if len(parts) == 4 && strings.HasSuffix(parts[1], ".app") {
				b, err := readSmallZipEntry(zf, 4<<20)
				if err != nil {
					return ipaInjectMeta{}, err
				}
				manifestBytes = b
			}
		}
	}

	if bundleName == "" {
		return ipaInjectMeta{}, errors.New("appstore: could not read bundle name from IPA")
	}

	meta := ipaInjectMeta{bundleName: bundleName}
	if len(manifestBytes) > 0 {
		var dict map[string]any
		if _, err := plist.Unmarshal(manifestBytes, &dict); err == nil && dict != nil {
			if rawPaths, ok := dict["SinfPaths"].([]any); ok {
				meta.sinfPaths = make([]string, 0, len(rawPaths))
				for _, p := range rawPaths {
					if s, ok := p.(string); ok && s != "" {
						meta.sinfPaths = append(meta.sinfPaths, s)
					}
				}
			}
		}
	}
	if len(infoBytes) > 0 {
		var dict map[string]any
		if _, err := plist.Unmarshal(infoBytes, &dict); err == nil && dict != nil {
			if execName, ok := dict["CFBundleExecutable"].(string); ok {
				meta.executable = execName
			}
		}
	}
	return meta, nil
}

func readSmallZipEntry(zf *zip.File, limit int64) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("appstore: zip entry %s exceeds limit", zf.Name)
	}
	return data, nil
}

func safePayloadEntry(bundleName, rel string) (string, error) {
	cleanRel := path.Clean(strings.TrimLeft(filepath.ToSlash(rel), "/"))
	if cleanRel == "." || cleanRel == ".." || strings.HasPrefix(cleanRel, "../") || strings.Contains(cleanRel, "\x00") {
		return "", fmt.Errorf("appstore: unsafe SINF path %q", rel)
	}
	full := path.Join("Payload", bundleName+".app", cleanRel)
	prefix := "Payload/" + bundleName + ".app/"
	if !strings.HasPrefix(full, prefix) {
		return "", fmt.Errorf("appstore: SINF path escapes bundle: %q", rel)
	}
	return full, nil
}

// VerifyBinaryPlist checks whether data is a valid binary plist (bplist00).
func VerifyBinaryPlist(data []byte) bool {
	return bytes.HasPrefix(data, []byte("bplist"))
}
