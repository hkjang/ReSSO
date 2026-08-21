// Package config loads and validates the environment configuration that
// ReSSO needs before it can serve or run an offline maintenance command.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

const (
	EnvPostgresDSN           = "POSTGRES_DSN"
	EnvBootstrapAdmin        = "BOOTSTRAP_ADMIN"
	EnvBootstrapAdminPass    = "BOOTSTRAP_ADMIN_PASSWORD"
	EnvEncryptionKey         = "ENCRYPTION_KEY"
	EnvDataEncryptionKeys    = "DATA_ENCRYPTION_KEYS"
	EnvDigestKeys            = "DIGEST_KEYS"
	EnvTrustedProxyCIDRs     = "TRUSTED_PROXY_CIDRS"
	EnvListenAddress         = "LISTEN_ADDRESS"
	DefaultListenAddress     = ":8080"
	DefaultBootstrapRealm    = "master"
	DefaultBootstrapIssuer   = "http://localhost:8080/realms/master"
	MinimumBootstrapPassword = 12
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type NamedKey struct {
	ID       string
	Material []byte
}

type Config struct {
	PostgresDSN            string
	BootstrapAdmin         string
	BootstrapAdminPassword string
	DataEncryptionKeys     []NamedKey
	DigestKeys             []NamedKey
	LegacySingleKey        bool
	ListenAddress          string
	TrustedProxyCIDRs      []*net.IPNet
}

func Load() (Config, error) {
	return load(true)
}

// LoadMaintenance validates only values needed by offline administrative
// commands. It deliberately does not require bootstrap credentials.
func LoadMaintenance() (Config, error) {
	return load(false)
}

func load(requireBootstrap bool) (Config, error) {
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
	if requireBootstrap && cfg.BootstrapAdmin == "" {
		missing = append(missing, EnvBootstrapAdmin)
	}
	if requireBootstrap && cfg.BootstrapAdminPassword == "" {
		missing = append(missing, EnvBootstrapAdminPass)
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("required environment variables are missing: %s", strings.Join(missing, ", "))
	}
	if requireBootstrap && len([]rune(cfg.BootstrapAdminPassword)) < MinimumBootstrapPassword {
		return Config{}, fmt.Errorf("%s must contain at least %d characters", EnvBootstrapAdminPass, MinimumBootstrapPassword)
	}
	if requireBootstrap && strings.ContainsAny(cfg.BootstrapAdmin, "\x00\r\n\t /\\") {
		return Config{}, errors.New("BOOTSTRAP_ADMIN contains unsupported characters")
	}

	legacyRaw := strings.TrimSpace(os.Getenv(EnvEncryptionKey))
	dataRaw := strings.TrimSpace(os.Getenv(EnvDataEncryptionKeys))
	digestRaw := strings.TrimSpace(os.Getenv(EnvDigestKeys))
	if dataRaw == "" && digestRaw == "" {
		if legacyRaw == "" {
			return Config{}, fmt.Errorf("either %s or both %s and %s are required",
				EnvEncryptionKey, EnvDataEncryptionKeys, EnvDigestKeys)
		}
		legacy, err := decodeKey(EnvEncryptionKey, legacyRaw)
		if err != nil {
			return Config{}, err
		}
		cfg.DataEncryptionKeys = []NamedKey{{ID: "legacy", Material: legacy}}
		cfg.DigestKeys = []NamedKey{{ID: "legacy", Material: legacy}}
		cfg.LegacySingleKey = true
	} else {
		if dataRaw == "" || digestRaw == "" {
			return Config{}, fmt.Errorf("%s and %s must be configured together", EnvDataEncryptionKeys, EnvDigestKeys)
		}
		var err error
		cfg.DataEncryptionKeys, err = parseKeyring(EnvDataEncryptionKeys, dataRaw)
		if err != nil {
			return Config{}, err
		}
		cfg.DigestKeys, err = parseKeyring(EnvDigestKeys, digestRaw)
		if err != nil {
			return Config{}, err
		}
		if legacyRaw != "" {
			legacy, err := decodeKey(EnvEncryptionKey, legacyRaw)
			if err != nil {
				return Config{}, err
			}
			cfg.DataEncryptionKeys, err = appendLegacyKey(cfg.DataEncryptionKeys, legacy)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", EnvDataEncryptionKeys, err)
			}
			cfg.DigestKeys, err = appendLegacyKey(cfg.DigestKeys, legacy)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", EnvDigestKeys, err)
			}
		}
	}
	if raw := strings.TrimSpace(os.Getenv(EnvListenAddress)); raw != "" {
		if _, _, err := net.SplitHostPort(raw); err != nil {
			return Config{}, fmt.Errorf("%s must be host:port, for example :8080", EnvListenAddress)
		}
		cfg.ListenAddress = raw
	}
	if raw := strings.TrimSpace(os.Getenv(EnvTrustedProxyCIDRs)); requireBootstrap && raw != "" {
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

func parseKeyring(name, value string) ([]NamedKey, error) {
	parts := strings.Split(value, ",")
	keys := make([]NamedKey, 0, len(parts))
	seen := map[string]bool{}
	for index, part := range parts {
		id, encoded, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok || !keyIDPattern.MatchString(id) || strings.TrimSpace(encoded) == "" {
			return nil, fmt.Errorf("%s entry %d is invalid; expected key-id:encoded-32-byte-key", name, index+1)
		}
		if seen[id] {
			return nil, fmt.Errorf("%s entry %d duplicates an earlier key ID", name, index+1)
		}
		material, err := decodeKey(fmt.Sprintf("%s entry %d", name, index+1), strings.TrimSpace(encoded))
		if err != nil {
			return nil, err
		}
		keys = append(keys, NamedKey{ID: id, Material: material})
		seen[id] = true
	}
	return keys, nil
}

func appendLegacyKey(keys []NamedKey, material []byte) ([]NamedKey, error) {
	for _, key := range keys {
		if key.ID == "legacy" {
			if string(key.Material) == string(material) {
				return keys, nil
			}
			return nil, errors.New("reserved key ID \"legacy\" does not match ENCRYPTION_KEY")
		}
	}
	// The ID is required even when another entry has identical material:
	// single-key v0.2.1 envelopes explicitly reference "legacy".
	return append(keys, NamedKey{ID: "legacy", Material: material}), nil
}

func decodeKey(label, value string) ([]byte, error) {
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
	return nil, fmt.Errorf("%s must be exactly 32 bytes encoded as base64 or hexadecimal", label)
}
