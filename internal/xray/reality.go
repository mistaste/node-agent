package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateRealityKeypair returns an X25519 keypair encoded like `xray x25519`.
func GenerateRealityKeypair() (privateKey, publicKey string, err error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate x25519 key: %w", err)
	}
	encoding := base64.RawURLEncoding
	return encoding.EncodeToString(private.Bytes()), encoding.EncodeToString(private.PublicKey().Bytes()), nil
}

func GenerateShortID() (string, error) {
	value := make([]byte, 8)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate reality short id: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func RealityPublicKey(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("decode x25519 private key: %w", err)
	}
	private, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("parse x25519 private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), nil
}
