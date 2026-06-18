package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateRealityKeypair returns an X25519 keypair encoded exactly like
// `xray x25519` (base64.RawURLEncoding of the raw 32-byte keys), suitable for
// realitySettings.privateKey (node-side) and the client's pbk.
func GenerateRealityKeypair() (privateKey, publicKey string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("x25519 generate: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(priv.Bytes()), enc.EncodeToString(priv.PublicKey().Bytes()), nil
}

// GenerateShortID returns 8 random bytes as 16 hex chars (matches install.sh).
func GenerateShortID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("short id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
