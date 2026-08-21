// Package password hashes and verifies user passwords with Argon2id, and
// bounds how many hashes may run at once so that a burst of authentication
// attempts cannot exhaust the process.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultParams = Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}

func Hash(value string) (string, error) {
	if value == "" {
		return "", errors.New("password cannot be empty")
	}
	p := DefaultParams
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(value), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.Memory, p.Iterations, p.Parallelism, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func Verify(value, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, errors.New("unsupported password hash")
	}
	var p Params
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return false, errors.New("invalid password hash parameters")
	}
	memory, err := parseParam(params[0], "m")
	if err != nil {
		return false, err
	}
	iterations, err := parseParam(params[1], "t")
	if err != nil {
		return false, err
	}
	parallelism, err := parseParam(params[2], "p")
	if err != nil || parallelism > 255 {
		return false, errors.New("invalid password hash parallelism")
	}
	p.Memory, p.Iterations, p.Parallelism = uint32(memory), uint32(iterations), uint8(parallelism)
	if p.Memory < 8*1024 || p.Memory > 1024*1024 || p.Iterations < 1 || p.Iterations > 20 || p.Parallelism < 1 || p.Parallelism > 32 {
		return false, errors.New("password hash parameters outside safe bounds")
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false, errors.New("invalid password hash salt")
	}
	expected, err := b64.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false, errors.New("invalid password hash value")
	}
	actual := argon2.IDKey([]byte(value), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func parseParam(value, name string) (uint64, error) {
	prefix := name + "="
	if !strings.HasPrefix(value, prefix) {
		return 0, errors.New("invalid password hash parameter")
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
	if err != nil {
		return 0, errors.New("invalid password hash parameter")
	}
	return n, nil
}

// Argon2id deliberately trades memory for brute-force resistance: every call
// allocates DefaultParams.Memory. Without a bound, a burst of authentication
// attempts multiplies that allocation by the number of in-flight requests and
// exhausts the process. The gate below keeps peak usage proportional to the
// available CPUs instead of to the request rate, so excess attempts queue (and
// observe their caller's deadline) rather than pushing the service into OOM.
var hashGate = make(chan struct{}, gateCapacity())

func gateCapacity() int {
	capacity := runtime.GOMAXPROCS(0)
	if capacity < 2 {
		capacity = 2
	}
	if capacity > 8 {
		capacity = 8
	}
	return capacity
}

func acquire(ctx context.Context) error {
	select {
	case hashGate <- struct{}{}:
		return nil
	default:
	}
	select {
	case hashGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func release() { <-hashGate }

// HashContext derives a new password hash, waiting for a free Argon2 slot.
func HashContext(ctx context.Context, value string) (string, error) {
	if err := acquire(ctx); err != nil {
		return "", err
	}
	defer release()
	return Hash(value)
}

// VerifyContext compares a password against an encoded hash, waiting for a
// free Argon2 slot. Malformed hashes are rejected before the slot is taken.
func VerifyContext(ctx context.Context, value, encoded string) (bool, error) {
	if err := acquire(ctx); err != nil {
		return false, err
	}
	defer release()
	return Verify(value, encoded)
}
