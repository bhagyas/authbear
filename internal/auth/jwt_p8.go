package auth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwtPayload struct {
	Iss string `json:"iss"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Aud string `json:"aud"`
}

// ValidateP8Key parses the PEM key, returning an error if invalid.
func ValidateP8Key(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		return fmt.Errorf("expected PEM type PRIVATE KEY, got %q", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		return fmt.Errorf("expected EC private key, got %T", key)
	}
	return nil
}

// GenerateJWT generates a fresh ES256 JWT for Apple's APIs.
// ttl=0 uses the default 20-minute lifetime.
func GenerateJWT(pemKey, keyID, issuerID, audience string, ttl time.Duration) (string, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	key, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("expected EC private key, got %T", raw)
	}

	if ttl <= 0 {
		ttl = 20 * time.Minute
	}

	now := time.Now()
	header := jwtHeader{Alg: "ES256", Kid: keyID}
	payload := jwtPayload{
		Iss: issuerID,
		Iat: now.Unix(),
		Exp: now.Add(ttl).Unix(),
		Aud: audience,
	}

	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	pBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	headerSeg := base64.RawURLEncoding.EncodeToString(hBytes)
	payloadSeg := base64.RawURLEncoding.EncodeToString(pBytes)
	signingInput := headerSeg + "." + payloadSeg

	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	// P1363 format: fixed 64 bytes, r and s each zero-padded to 32 bytes
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
