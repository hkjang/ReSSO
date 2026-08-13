package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func RandomToken(bytes int) (string, error) {
	if bytes < 16 {
		return "", fmt.Errorf("random token size must be at least 16 bytes")
	}
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
