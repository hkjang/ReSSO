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
	t.Setenv(EnvDataEncryptionKeys, "")
	t.Setenv(EnvDigestKeys, "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.DataEncryptionKeys) != 1 || len(cfg.DigestKeys) != 1 || !cfg.LegacySingleKey || cfg.ListenAddress != ":8080" {
		t.Fatalf("unexpected config: data=%d digest=%d listen=%q",
			len(cfg.DataEncryptionKeys), len(cfg.DigestKeys), cfg.ListenAddress)
	}
}

func TestLoadRejectsShortPassword(t *testing.T) {
	t.Setenv(EnvPostgresDSN, "postgres://db")
	t.Setenv(EnvBootstrapAdmin, "admin")
	t.Setenv(EnvBootstrapAdminPass, "too-short")
	t.Setenv(EnvEncryptionKey, strings.Repeat("00", 32))
	t.Setenv(EnvDataEncryptionKeys, "")
	t.Setenv(EnvDigestKeys, "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a short bootstrap password")
	}
}

func TestLoadTrustedProxyCIDRs(t *testing.T) {
	t.Setenv(EnvPostgresDSN, "postgres://resso:test@db/resso")
	t.Setenv(EnvBootstrapAdmin, "root-admin")
	t.Setenv(EnvBootstrapAdminPass, "correct horse battery staple")
	t.Setenv(EnvEncryptionKey, strings.Repeat("00", 32))
	t.Setenv(EnvDataEncryptionKeys, "")
	t.Setenv(EnvDigestKeys, "")
	t.Setenv(EnvTrustedProxyCIDRs, "10.0.0.0/8, 2001:db8::/32")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 {
		t.Fatalf("trusted proxy networks = %d, want 2", len(cfg.TrustedProxyCIDRs))
	}
}

func TestLoadKeyringsRetainLegacyKey(t *testing.T) {
	t.Setenv(EnvPostgresDSN, "postgres://resso:test@db/resso")
	t.Setenv(EnvBootstrapAdmin, "root-admin")
	t.Setenv(EnvBootstrapAdminPass, "correct horse battery staple")
	t.Setenv(EnvEncryptionKey, strings.Repeat("11", 32))
	t.Setenv(EnvDataEncryptionKeys, "data-2026:"+strings.Repeat("22", 32))
	t.Setenv(EnvDigestKeys, "digest-2026:"+strings.Repeat("33", 32))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DataEncryptionKeys) != 2 || cfg.DataEncryptionKeys[0].ID != "data-2026" ||
		len(cfg.DigestKeys) != 2 || cfg.DigestKeys[0].ID != "digest-2026" {
		t.Fatalf("unexpected keyrings: data=%+v digest=%+v", cfg.DataEncryptionKeys, cfg.DigestKeys)
	}
}

func TestLoadMaintenanceDoesNotRequireBootstrapCredentials(t *testing.T) {
	t.Setenv(EnvPostgresDSN, "postgres://resso:test@db/resso")
	t.Setenv(EnvBootstrapAdmin, "")
	t.Setenv(EnvBootstrapAdminPass, "")
	t.Setenv(EnvEncryptionKey, strings.Repeat("44", 32))
	t.Setenv(EnvDataEncryptionKeys, "")
	t.Setenv(EnvDigestKeys, "")
	if _, err := LoadMaintenance(); err != nil {
		t.Fatalf("LoadMaintenance() error = %v", err)
	}
}

func TestLoadKeyringsKeepLegacyAliasWhenMaterialMatches(t *testing.T) {
	material := strings.Repeat("55", 32)
	t.Setenv(EnvPostgresDSN, "postgres://resso:test@db/resso")
	t.Setenv(EnvBootstrapAdmin, "root-admin")
	t.Setenv(EnvBootstrapAdminPass, "correct horse battery staple")
	t.Setenv(EnvEncryptionKey, material)
	t.Setenv(EnvDataEncryptionKeys, "data-current:"+material)
	t.Setenv(EnvDigestKeys, "digest-current:"+material)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DataEncryptionKeys) != 2 || cfg.DataEncryptionKeys[1].ID != "legacy" ||
		len(cfg.DigestKeys) != 2 || cfg.DigestKeys[1].ID != "legacy" {
		t.Fatalf("legacy alias missing: data=%+v digest=%+v", cfg.DataEncryptionKeys, cfg.DigestKeys)
	}
}

func TestLoadKeyringsRejectConflictingLegacyAlias(t *testing.T) {
	t.Setenv(EnvPostgresDSN, "postgres://resso:test@db/resso")
	t.Setenv(EnvBootstrapAdmin, "root-admin")
	t.Setenv(EnvBootstrapAdminPass, "correct horse battery staple")
	t.Setenv(EnvEncryptionKey, strings.Repeat("66", 32))
	t.Setenv(EnvDataEncryptionKeys, "legacy:"+strings.Repeat("77", 32))
	t.Setenv(EnvDigestKeys, "digest-current:"+strings.Repeat("88", 32))
	if _, err := Load(); err == nil {
		t.Fatal("conflicting legacy key ID was accepted")
	}
}

func TestLoadKeyringErrorDoesNotExposeMaterial(t *testing.T) {
	secret := strings.Repeat("ab", 32)
	t.Setenv(EnvPostgresDSN, "postgres://resso:test@db/resso")
	t.Setenv(EnvBootstrapAdmin, "root-admin")
	t.Setenv(EnvBootstrapAdminPass, "correct horse battery staple")
	t.Setenv(EnvEncryptionKey, "")
	t.Setenv(EnvDataEncryptionKeys, secret)
	t.Setenv(EnvDigestKeys, "digest:"+strings.Repeat("cd", 32))
	_, err := Load()
	if err == nil {
		t.Fatal("malformed keyring was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("configuration error exposed key material: %v", err)
	}
}

func TestLoadMaintenanceIgnoresProxyConfiguration(t *testing.T) {
	t.Setenv(EnvPostgresDSN, "postgres://resso:test@db/resso")
	t.Setenv(EnvBootstrapAdmin, "")
	t.Setenv(EnvBootstrapAdminPass, "")
	t.Setenv(EnvEncryptionKey, strings.Repeat("99", 32))
	t.Setenv(EnvDataEncryptionKeys, "")
	t.Setenv(EnvDigestKeys, "")
	t.Setenv(EnvTrustedProxyCIDRs, "not-a-cidr")
	if _, err := LoadMaintenance(); err != nil {
		t.Fatalf("maintenance config rejected irrelevant proxy setting: %v", err)
	}
}
