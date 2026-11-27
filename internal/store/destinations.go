package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SavedDestination represents a persisted saved target destination and its optional monitor settings.
type SavedDestination struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Target          string `json:"target"`
	Category        string `json:"category"`
	MAC             string `json:"mac"`
	DefaultCheck    string `json:"default_check"`
	Pinned          bool   `json:"pinned"`
	MonitorEnabled  bool   `json:"monitor_enabled"`
	MonitorSchedule string `json:"monitor_schedule"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
}

const (
	defaultDestCategory    = "Core"
	defaultDestCheck       = "recipe_diff_ping"
	defaultMonitorSchedule = "*/5 * * * *"
	destIDRandByteSize     = 6

	upsertDestinationSQL = `INSERT INTO saved_destinations (
	id, name, target, category, mac, default_check, pinned, monitor_enabled, monitor_schedule, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	name = excluded.name,
	target = excluded.target,
	category = excluded.category,
	mac = excluded.mac,
	default_check = excluded.default_check,
	pinned = excluded.pinned,
	monitor_enabled = excluded.monitor_enabled,
	monitor_schedule = excluded.monitor_schedule,
	updated_at = excluded.updated_at
RETURNING created_at;`
	getDestinationSQL    = `SELECT id, name, target, category, mac, default_check, pinned, monitor_enabled, monitor_schedule, created_at, updated_at FROM saved_destinations WHERE id = ?;`
	listDestinationsSQL  = `SELECT id, name, target, category, mac, default_check, pinned, monitor_enabled, monitor_schedule, created_at, updated_at FROM saved_destinations ORDER BY pinned DESC, updated_at DESC, name ASC;`
	deleteDestinationSQL = `DELETE FROM saved_destinations WHERE id = ?;`
)

// SaveDestination validates, normalizes defaults, and upserts a SavedDestination using the read-write pool.
// On conflict with an existing ID, the original created_at timestamp is preserved.
func (s *JobStore) SaveDestination(ctx context.Context, dst *SavedDestination) error {
	if dst == nil {
		return errors.New("destination must not be nil")
	}
	name := strings.TrimSpace(dst.Name)
	if name == "" {
		return errors.New("destination name must not be empty")
	}
	target := strings.TrimSpace(dst.Target)
	if target == "" {
		return errors.New("destination target must not be empty")
	}

	id := strings.TrimSpace(dst.ID)
	if id == "" {
		generated, err := generateDestinationID()
		if err != nil {
			return err
		}
		id = generated
	}

	dst.ID = id
	dst.Name = name
	dst.Target = target
	dst.Category = defaultIfBlank(dst.Category, defaultDestCategory)
	dst.MAC = strings.TrimSpace(dst.MAC)
	dst.DefaultCheck = defaultIfBlank(dst.DefaultCheck, defaultDestCheck)
	dst.MonitorSchedule = defaultIfBlank(dst.MonitorSchedule, defaultMonitorSchedule)

	now := time.Now().UTC().Unix()
	if dst.CreatedAt <= 0 {
		dst.CreatedAt = now
	}
	dst.UpdatedAt = now

	if err := s.rwDB.QueryRowContext(ctx, upsertDestinationSQL,
		dst.ID, dst.Name, dst.Target, dst.Category, dst.MAC, dst.DefaultCheck,
		boolToInt(dst.Pinned), boolToInt(dst.MonitorEnabled), dst.MonitorSchedule,
		dst.CreatedAt, dst.UpdatedAt,
	).Scan(&dst.CreatedAt); err != nil {
		return fmt.Errorf("save destination %q: %w", dst.ID, err)
	}
	return nil
}

// GetDestination retrieves a saved destination by ID using the read-only pool.
func (s *JobStore) GetDestination(ctx context.Context, id string) (*SavedDestination, error) {
	trimmed := strings.TrimSpace(id)
	dst, err := scanDestination(s.roDB.QueryRowContext(ctx, getDestinationSQL, trimmed))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("destination %q (%w): %w", trimmed, ErrNotFound, err)
		}
		return nil, fmt.Errorf("get destination %q: %w", trimmed, err)
	}
	return dst, nil
}

// ListDestinations returns all saved destinations ordered by pinned DESC, updated_at DESC, name ASC.
func (s *JobStore) ListDestinations(ctx context.Context) ([]SavedDestination, error) {
	rows, err := s.roDB.QueryContext(ctx, listDestinationsSQL)
	if err != nil {
		return nil, fmt.Errorf("list destinations: %w", err)
	}
	defer rows.Close()

	destinations := []SavedDestination{}
	for rows.Next() {
		dst, scanErr := scanDestination(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		destinations = append(destinations, *dst)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate destination rows: %w", err)
	}
	return destinations, nil
}

// DeleteDestination removes a saved destination by ID using the read-write pool.
// It returns true when a row was deleted, or false if no matching row existed.
func (s *JobStore) DeleteDestination(ctx context.Context, id string) (bool, error) {
	trimmed := strings.TrimSpace(id)
	res, err := s.rwDB.ExecContext(ctx, deleteDestinationSQL, trimmed)
	if err != nil {
		return false, fmt.Errorf("delete destination %q: %w", trimmed, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("count deleted destinations %q: %w", trimmed, err)
	}
	return affected > 0, nil
}

func scanDestination(scanner rowScanner) (*SavedDestination, error) {
	var dst SavedDestination
	var pinnedInt, monitorInt int
	if err := scanner.Scan(
		&dst.ID, &dst.Name, &dst.Target, &dst.Category, &dst.MAC, &dst.DefaultCheck,
		&pinnedInt, &monitorInt, &dst.MonitorSchedule, &dst.CreatedAt, &dst.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan destination: %w", err)
	}
	dst.Pinned = pinnedInt != 0
	dst.MonitorEnabled = monitorInt != 0
	return &dst, nil
}

func generateDestinationID() (string, error) {
	var raw [destIDRandByteSize]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate destination id entropy: %w", err)
	}
	return "dest_" + hex.EncodeToString(raw[:]), nil
}

func defaultIfBlank(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}
