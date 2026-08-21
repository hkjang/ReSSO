package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hkjang/ReSSO/internal/config"
	"github.com/hkjang/ReSSO/internal/store"
)

func runMaintenanceCommand(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		return errors.New("usage: resso admin <diagnose|recover> or resso crypto rewrap")
	}
	switch args[0] + " " + args[1] {
	case "admin diagnose":
		if len(args) != 2 {
			return errors.New("usage: resso admin diagnose")
		}
		return withMaintenanceStore(30*time.Second, false, func(ctx context.Context, data *store.Store) error {
			result, err := data.DiagnoseRecovery(ctx)
			if err != nil {
				return err
			}
			return writeCommandJSON(stdout, result)
		})
	case "admin recover":
		flags := flag.NewFlagSet("admin recover", flag.ContinueOnError)
		flags.SetOutput(stderr)
		username := flags.String("username", "", "local master Realm username")
		passwordStdin := flags.Bool("password-stdin", false, "read the replacement password from standard input")
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || strings.TrimSpace(*username) == "" || !*passwordStdin {
			return errors.New("usage: resso admin recover --username <local-user> --password-stdin")
		}
		password, err := readPassword(stdin)
		if err != nil {
			return err
		}
		return withMaintenanceStore(2*time.Minute, true, func(ctx context.Context, data *store.Store) error {
			result, err := data.RecoverPlatformAdmin(ctx, *username, password)
			if err != nil {
				return err
			}
			return writeCommandJSON(stdout, result)
		})
	case "crypto rewrap":
		if len(args) != 2 {
			return errors.New("usage: resso crypto rewrap")
		}
		return withMaintenanceStore(10*time.Minute, true, func(ctx context.Context, data *store.Store) error {
			result, err := data.RewrapEncryptedSecrets(ctx)
			if err != nil {
				return err
			}
			return writeCommandJSON(stdout, result)
		})
	default:
		return fmt.Errorf("unknown maintenance command %q", strings.Join(args, " "))
	}
}

func withMaintenanceStore(timeout time.Duration, migrate bool, operation func(context.Context, *store.Store) error) error {
	cfg, err := config.LoadMaintenance()
	if err != nil {
		return err
	}
	sealer, err := newSealer(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	data, err := store.Open(ctx, cfg.PostgresDSN, sealer)
	if err != nil {
		return err
	}
	defer data.Close()
	if migrate {
		if err := store.Migrate(ctx, data.Pool); err != nil {
			return err
		}
	}
	return operation(ctx, data)
}

func readPassword(input io.Reader) (string, error) {
	const maximumBytes = 4096
	value, err := io.ReadAll(io.LimitReader(input, maximumBytes+1))
	if err != nil {
		return "", fmt.Errorf("read replacement password: %w", err)
	}
	if len(value) > maximumBytes {
		return "", errors.New("replacement password is too long")
	}
	password := strings.TrimSuffix(string(value), "\n")
	password = strings.TrimSuffix(password, "\r")
	if password == "" {
		return "", errors.New("replacement password is empty")
	}
	if strings.ContainsAny(password, "\x00\r\n") {
		return "", errors.New("replacement password must be provided as exactly one line")
	}
	return password, nil
}

func writeCommandJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
