package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	EnvPostgresDSN           = "POSTGRES_DSN"
	EnvBootstrapAdmin        = "BOOTSTRAP_ADMIN"
	EnvBootstrapAdminPass    = "BOOTSTRAP_ADMIN_PASSWORD"
	EnvEncryptionKey         = "ENCRYPTION_KEY"
	EnvTrustedProxyCIDRs     = "TRUSTED_PROXY_CIDRS"
	DefaultListenAddress     = ":8080"
	DefaultBootstrapRealm    = "master"
	DefaultBootstrapIssuer   = "http://localhost:8080/realms/master"
	MinimumBootstrapPassword = 12
)

// Config intentionally contains only four environment-driven values. All
// mutable service settings live in PostgreSQL and are changed through the
// authenticated administration API.
type Config struct {
	PostgresDSN            string
	BootstrapAdmin         string
	BootstrapAdminPassword string
	EncryptionKey          []byte
	ListenAddress          string
	TrustedProxyCIDRs      []*net.IPNet
}

func Load() (Config, error) {
	cfg := Config{
		PostgresDSN:            strings.TrimSpace(os.Getenv(EnvPostgresDSN)),
		BootstrapAdmin:         strings.TrimSpace(os.Getenv(EnvBootstrapAdmin)),
		BootstrapAdminPassword: os.Getenv(EnvBootstrapAdminPass),
		ListenAddress:          DefaultListenAddress,
	}

	var missing []string
	if cfg.PostgresDSN == "" {
		missing = append(missing, EnvPostgresDSN)
	}
	if cfg.BootstrapAdmin == "" {
		missing = append(missing, EnvBootstrapAdmin)
	}
	if cfg.BootstrapAdminPassword == "" {
		missing = append(missing, EnvBootstrapAdminPass)
	}
	rawKey := strings.TrimSpace(os.Getenv(EnvEncryptionKey))
	if rawKey == "" {
		missing = append(missing, EnvEncryptionKey)
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("required environment variables are missing: %s", strings.Join(missing, ", "))
	}
	if len([]rune(cfg.BootstrapAdminPassword)) < MinimumBootstrapPassword {
		return Config{}, fmt.Errorf("%s must contain at least %d characters", EnvBootstrapAdminPass, MinimumBootstrapPassword)
	}
	if strings.ContainsAny(cfg.BootstrapAdmin, "\x00\r\n\t /\\") {
		return Config{}, errors.New("BOOTSTRAP_ADMIN contains unsupported characters")
	}

	key, err := decodeEncryptionKey(rawKey)
	if err != nil {
		return Config{}, err
	}
	cfg.EncryptionKey = key
	if raw := strings.TrimSpace(os.Getenv(EnvTrustedProxyCIDRs)); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			value = strings.TrimSpace(value)
			_, network, parseErr := net.ParseCIDR(value)
			if parseErr != nil {
				return Config{}, fmt.Errorf("%s contains invalid CIDR %q", EnvTrustedProxyCIDRs, value)
			}
			cfg.TrustedProxyCIDRs = append(cfg.TrustedProxyCIDRs, network)
		}
	}
	return cfg, nil
}

func decodeEncryptionKey(value string) ([]byte, error) {
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		hex.DecodeString,
	}
	for _, decode := range decoders {
		decoded, err := decode(value)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, errors.New("ENCRYPTION_KEY must be exactly 32 bytes encoded as base64 or hexadecimal")
}
