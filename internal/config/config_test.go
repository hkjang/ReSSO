package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Setenv(EnvPostgresDSN, "postgres://resso:test@db/resso")
	t.Setenv(EnvBootstrapAdmin, "root-admin")
	t.Setenv(EnvBootstrapAdminPass, "correct horse battery staple")
	t.Setenv(EnvEncryptionKey, base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.EncryptionKey) != 32 || cfg.ListenAddress != ":8080" {
		t.Fatalf("unexpected config: key=%d listen=%q", len(cfg.EncryptionKey), cfg.ListenAddress)
	}
}

func TestLoadRejectsShortPassword(t *testing.T) {
	t.Setenv(EnvPostgresDSN, "postgres://db")
	t.Setenv(EnvBootstrapAdmin, "admin")
	t.Setenv(EnvBootstrapAdminPass, "too-short")
	t.Setenv(EnvEncryptionKey, strings.Repeat("00", 32))
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a short bootstrap password")
	}
}
