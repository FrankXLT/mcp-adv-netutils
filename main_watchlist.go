package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/FrankXLT/mcp-adv-netutils/internal/cronmon"
)

const (
	defaultWatchlistYAML = "version: 1\nitems: []\n"
	seededWatchlistPerm  = 0o600
)

func seedWritableWatchlist(dataDir, currentPath string) string {
	cleanDir := strings.TrimSpace(dataDir)
	if cleanDir == "" {
		return currentPath
	}
	cleanDir = filepath.Clean(cleanDir)
	targetPath := filepath.Join(cleanDir, defaultWatchlistFile)
	if info, err := os.Stat(targetPath); err == nil && !info.IsDir() {
		return targetPath
	} else if err == nil || !errors.Is(err, os.ErrNotExist) {
		return currentPath
	}
	data := []byte(defaultWatchlistYAML)
	if trimmedSrc := strings.TrimSpace(currentPath); trimmedSrc != "" {
		// #nosec G304 -- currentPath comes from resolved default watchlist locations.
		if srcBytes, err := os.ReadFile(filepath.Clean(trimmedSrc)); err == nil {
			data = srcBytes
		}
	}
	if os.MkdirAll(cleanDir, dataDirPerm) != nil || writeSeedFileAtomic(cleanDir, targetPath, data) != nil {
		return currentPath
	}
	return targetPath
}

func writeSeedFileAtomic(dir, targetPath string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".watchlist-seed-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp watchlist: %w", err)
	}
	tmpName := tmp.Name()
	var writeErr error
	if writeErr = tmp.Chmod(seededWatchlistPerm); writeErr == nil {
		if _, writeErr = tmp.Write(data); writeErr == nil {
			writeErr = tmp.Sync()
		}
	}
	if closeErr := tmp.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(tmpName)
		return writeErr
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename temp watchlist: %w", err)
	}
	return nil
}

func loadWatchlistOrEmpty(configuredPath string, logger *log.Logger) (string, *cronmon.WatchlistFile, error) {
	trimmed := strings.TrimSpace(configuredPath)
	if trimmed == "" {
		return "", &cronmon.WatchlistFile{Version: 1}, nil
	}
	wl, err := cronmon.LoadWatchlist(trimmed)
	if err == nil {
		return trimmed, wl, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if logger != nil {
			logger.Printf("Watchlist %q not found; starting with empty watchlist", trimmed)
		}
		return trimmed, &cronmon.WatchlistFile{Version: 1}, nil
	}
	return "", nil, fmt.Errorf("load watchlist %q: %w", trimmed, err)
}
