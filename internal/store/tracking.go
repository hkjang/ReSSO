package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/tracking"
)

// trackingSettingKey is the platform_settings row the tracking configuration
// lives in.
const trackingSettingKey = "tracking"

// TrackingConfig reads the visitor tracking configuration. No row is the
// default, which is off — an installation nobody has configured tracks
// nothing.
func (s *Store) TrackingConfig(ctx context.Context) (tracking.Config, error) {
	var raw []byte
	err := s.Pool.QueryRow(ctx, "SELECT value FROM platform_settings WHERE key=$1", trackingSettingKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return tracking.Default(), nil
	}
	if err != nil {
		return tracking.Config{}, fmt.Errorf("read tracking configuration: %w", err)
	}
	config := tracking.Default()
	if err := json.Unmarshal(raw, &config); err != nil {
		return tracking.Config{}, fmt.Errorf("decode tracking configuration: %w", err)
	}
	return config.Normalized(), nil
}

// SaveTrackingConfig replaces the tracking configuration. What the console
// sent is normalized and checked here, so an unknown provider or an
// oversized snippet is refused as the caller's input rather than stored.
func (s *Store) SaveTrackingConfig(ctx context.Context, config tracking.Config, actorID *uuid.UUID) (tracking.Config, error) {
	config = config.Normalized()
	if err := config.Validate(); err != nil {
		return tracking.Config{}, invalidf("%s", err.Error())
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return tracking.Config{}, fmt.Errorf("encode tracking configuration: %w", err)
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO platform_settings(key,value,updated_at,updated_by) VALUES($1,$2,now(),$3)
        ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now(), updated_by=EXCLUDED.updated_by`,
		trackingSettingKey, raw, actorID)
	if err != nil {
		return tracking.Config{}, fmt.Errorf("save tracking configuration: %w", err)
	}
	return config, nil
}
