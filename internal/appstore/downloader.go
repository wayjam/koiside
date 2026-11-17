package appstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

// DownloadProgress reports CDN download progress and transfer speed.
type DownloadProgress struct {
	Downloaded int64
	Total      int64
	BytesPerS  float64
}

// DownloadOptions configures concurrent CDN IPA download.
type DownloadOptions struct {
	Threads    int
	MaxBytes   int64
	HTTPClient *http.Client
	OnProgress func(DownloadProgress)
	// AllowInsecureHTTP permits http:// URLs in unit tests only.
	AllowInsecureHTTP bool
}

const (
	defaultDownloadThreads = 8
	chunkRetryCount        = 3
	chunkRetryDelay        = 2 * time.Second
)

// ValidateDownloadURL enforces HTTPS and *.apple.com host restriction on the initial CDN URL.
func ValidateDownloadURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("appstore: invalid download URL")
	}
	if u.Scheme != "https" {
		return errors.New("appstore: download URL must use HTTPS")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || !strings.HasSuffix(host, ".apple.com") {
		return errors.New("appstore: download URL must be from an Apple domain (*.apple.com)")
	}
	return nil
}

// DownloadFile downloads an IPA from rawURL to destPath using parallel HTTP Range requests when supported,
// falling back to single-stream download otherwise. Writes atomically via temporary files.
func DownloadFile(ctx context.Context, rawURL, destPath string, opts DownloadOptions) error {
	if !opts.AllowInsecureHTTP {
		if err := ValidateDownloadURL(rawURL); err != nil {
			return err
		}
	}
	threads := opts.Threads
	if threads <= 0 {
		threads = defaultDownloadThreads
	} else if threads > 32 {
		threads = 32
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Minute}
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}

	supportsRange, contentLength := probeRange(ctx, client, rawURL)
	if opts.MaxBytes > 0 && contentLength > opts.MaxBytes {
		return fmt.Errorf("appstore: file too large (%d bytes exceeds %d byte limit)", contentLength, opts.MaxBytes)
	}

	if !supportsRange || threads <= 1 || contentLength < 1<<20 {
		return downloadSingleStream(ctx, client, rawURL, destPath, opts.MaxBytes, opts.OnProgress)
	}

	return downloadChunked(ctx, client, rawURL, destPath, contentLength, threads, opts.OnProgress)
}

func probeRange(ctx context.Context, client *http.Client, rawURL string) (bool, int64) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return false, 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, 0
	}
	if !strings.EqualFold(resp.Header.Get("Accept-Ranges"), "bytes") {
		return false, 0
	}
	cl, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil || cl <= 0 {
		return false, 0
	}
	return true, cl
}

func downloadSingleStream(ctx context.Context, client *http.Client, rawURL, destPath string, maxBytes int64, onProgress func(DownloadProgress)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("appstore: CDN HTTP %d", resp.StatusCode)
	}
	total := resp.ContentLength
	if maxBytes > 0 && total > maxBytes {
		return fmt.Errorf("appstore: file too large (%d bytes exceeds %d byte limit)", total, maxBytes)
	}

	tmp := destPath + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	var downloaded int64
	lastTick := time.Now()
	var lastBytes int64
	buf := make([]byte, 128*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			downloaded += int64(n)
			if maxBytes > 0 && downloaded > maxBytes {
				return errors.New("appstore: download exceeded maximum size")
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			if onProgress != nil && time.Since(lastTick) >= 250*time.Millisecond {
				elapsed := time.Since(lastTick).Seconds()
				speed := float64(downloaded-lastBytes) / elapsed
				lastTick = time.Now()
				lastBytes = downloaded
				onProgress(DownloadProgress{Downloaded: downloaded, Total: total, BytesPerS: speed})
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if onProgress != nil {
		onProgress(DownloadProgress{Downloaded: downloaded, Total: total})
	}
	if err := os.Rename(tmp, destPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

type chunkSpec struct {
	index int
	start int64
	end   int64
}

func downloadChunked(ctx context.Context, client *http.Client, rawURL, destPath string, total int64, threads int, onProgress func(DownloadProgress)) error {
	chunkSize := (total + int64(threads) - 1) / int64(threads)
	var chunks []chunkSpec
	for i := range threads {
		start := int64(i) * chunkSize
		if start >= total {
			break
		}
		end := start + chunkSize - 1
		if end >= total {
			end = total - 1
		}
		chunks = append(chunks, chunkSpec{index: i, start: start, end: end})
	}

	partPaths := make([]string, len(chunks))
	for i := range chunks {
		partPaths[i] = fmt.Sprintf("%s.part%d", destPath, i)
	}
	cleanupParts := func() {
		for _, p := range partPaths {
			_ = os.Remove(p)
		}
	}

	chunkCounts := make([]atomic.Int64, len(chunks))
	stopProgress := make(chan struct{})
	var progressWG sync.WaitGroup
	if onProgress != nil {
		progressWG.Add(1)
		go func() {
			defer progressWG.Done()
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			lastTick := time.Now()
			var lastBytes int64
			for {
				select {
				case <-stopProgress:
					return
				case <-ticker.C:
					var sum int64
					for i := range chunkCounts {
						sum += chunkCounts[i].Load()
					}
					elapsed := time.Since(lastTick).Seconds()
					speed := 0.0
					if elapsed > 0 {
						speed = float64(sum-lastBytes) / elapsed
					}
					lastTick = time.Now()
					lastBytes = sum
					onProgress(DownloadProgress{Downloaded: sum, Total: total, BytesPerS: speed})
				}
			}
		}()
	}

	g, gctx := errgroup.WithContext(ctx)
	for _, ch := range chunks {
		ch := ch
		g.Go(func() error {
			return downloadOneChunk(gctx, client, rawURL, partPaths[ch.index], ch, &chunkCounts[ch.index])
		})
	}
	err := g.Wait()
	close(stopProgress)
	progressWG.Wait()
	if err != nil {
		cleanupParts()
		return err
	}

	tmpOut := destPath + ".merging"
	out, err := os.Create(tmpOut)
	if err != nil {
		cleanupParts()
		return err
	}
	for _, p := range partPaths {
		in, openErr := os.Open(p)
		if openErr != nil {
			_ = out.Close()
			_ = os.Remove(tmpOut)
			cleanupParts()
			return openErr
		}
		_, copyErr := io.Copy(out, in)
		_ = in.Close()
		if copyErr != nil {
			_ = out.Close()
			_ = os.Remove(tmpOut)
			cleanupParts()
			return copyErr
		}
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpOut)
		cleanupParts()
		return err
	}
	cleanupParts()
	if err := os.Rename(tmpOut, destPath); err != nil {
		_ = os.Remove(tmpOut)
		return err
	}
	if onProgress != nil {
		onProgress(DownloadProgress{Downloaded: total, Total: total})
	}
	return nil
}

func downloadOneChunk(ctx context.Context, client *http.Client, rawURL, partPath string, ch chunkSpec, counter *atomic.Int64) error {
	expected := ch.end - ch.start + 1
	var lastErr error
	for attempt := range chunkRetryCount {
		counter.Store(0)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", ch.start, ch.end))
		resp, err := client.Do(req)
		if err == nil {
			err = writeChunkResponse(resp, partPath, expected, counter)
		}
		if err == nil {
			return nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt < chunkRetryCount-1 {
			t := time.NewTimer(chunkRetryDelay)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	return fmt.Errorf("appstore: chunk %d failed: %w", ch.index, lastErr)
}

func writeChunkResponse(resp *http.Response, partPath string, expected int64, counter *atomic.Int64) error {
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(partPath)
	if err != nil {
		return err
	}
	defer f.Close()

	var written int64
	buf := make([]byte, 128*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > expected*2 {
				return errors.New("chunk exceeded expected size")
			}
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			counter.Store(written)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if written != expected {
		return fmt.Errorf("short chunk: got %d bytes, want %d", written, expected)
	}
	return f.Close()
}
