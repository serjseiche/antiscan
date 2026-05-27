package service

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/serjseiche/antiscan/internal/domain"

	"github.com/rs/zerolog"
)

const maxResponseBytes = 50 * 1024 * 1024 // 50 MB

// Downloader handles downloading subnet lists from URLs
type Downloader struct {
	logger     zerolog.Logger
	httpClient *http.Client
}

// NewDownloader creates a new downloader service
func NewDownloader(logger zerolog.Logger) *Downloader {
	return &Downloader{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Download fetches subnets from multiple URLs and returns a NetworkList
func (d *Downloader) Download(urls []string) (*domain.NetworkList, error) {
	d.logger.Info().Int("url_count", len(urls)).Msg("Starting subnet list download")

	networks := domain.NewNetworkList()
	seenSubnets := make(map[string]bool)

	for i, url := range urls {
		d.logger.Info().
			Int("index", i+1).
			Int("total", len(urls)).
			Str("url", url).
			Msg("Downloading subnet list")

		subnets, err := d.downloadSingle(url)
		if err != nil {
			d.logger.Warn().
				Err(err).
				Str("url", url).
				Msg("Failed to download from URL, skipping")
			continue
		}

		added := 0
		for _, subnet := range subnets {
			subnet = strings.TrimSpace(subnet)
			if subnet == "" || strings.HasPrefix(subnet, "#") {
				continue
			}

			// Skip IPv6 (IPv4-only tool)
			if strings.Contains(subnet, ":") {
				continue
			}

			// Skip duplicates
			if seenSubnets[subnet] {
				continue
			}
			seenSubnets[subnet] = true

			networks.Add(subnet)
			added++
		}

		d.logger.Info().
			Int("added", added).
			Str("url", url).
			Msg("Subnet list downloaded")
	}

	d.logger.Info().
		Int("total", networks.IPv4Count()).
		Msg("Download complete")

	return networks, nil
}

// downloadSingle downloads subnets from a single URL
func (d *Downloader) downloadSingle(url string) ([]string, error) {
	resp, err := d.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// LimitedReader.N reaches 0 when the limit is hit; we use limit+1 so we
	// can distinguish "exactly at limit" from "body was larger than limit".
	lr := &io.LimitedReader{R: resp.Body, N: maxResponseBytes + 1}
	subnets := make([]string, 0)
	scanner := bufio.NewScanner(lr)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subnets = append(subnets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if lr.N == 0 {
		return nil, fmt.Errorf("response body exceeds %d MB limit", maxResponseBytes/1024/1024)
	}

	return subnets, nil
}
