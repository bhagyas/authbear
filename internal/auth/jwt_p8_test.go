package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func generateTestP8PEM(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return pemBytes, key
}

func TestValidateP8Key_Valid(t *testing.T) {
	pemBytes, _ := generateTestP8PEM(t)
	if err := ValidateP8Key(pemBytes); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateP8Key_Invalid(t *testing.T) {
	if err := ValidateP8Key([]byte("not a pem block")); err == nil {
		t.Fatal("expected error for garbage input")
	}
}

func TestValidateP8Key_WrongPEMType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")})
	if err := ValidateP8Key(block); err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

func decodeJWTSegment(t *testing.T, seg string, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("decode segment: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("unmarshal segment: %v", err)
	}
}

func TestGenerateJWT_Structure(t *testing.T) {
	pemBytes, _ := generateTestP8PEM(t)
	tok, err := GenerateJWT(string(pemBytes), "TESTKEY123", "issuer-abc", "appstoreconnect-v1", 0)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	var hdr jwtHeader
	decodeJWTSegment(t, parts[0], &hdr)
	if hdr.Alg != "ES256" {
		t.Errorf("alg: want ES256, got %q", hdr.Alg)
	}
	if hdr.Kid != "TESTKEY123" {
		t.Errorf("kid: want TESTKEY123, got %q", hdr.Kid)
	}

	var pl jwtPayload
	decodeJWTSegment(t, parts[1], &pl)
	if pl.Iss != "issuer-abc" {
		t.Errorf("iss: want issuer-abc, got %q", pl.Iss)
	}
	if pl.Aud != "appstoreconnect-v1" {
		t.Errorf("aud: want appstoreconnect-v1, got %q", pl.Aud)
	}
}

func TestGenerateJWT_DefaultTTL(t *testing.T) {
	pemBytes, _ := generateTestP8PEM(t)
	tok, err := GenerateJWT(string(pemBytes), "KID", "ISS", "AUD", 0)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	parts := strings.Split(tok, ".")
	var pl jwtPayload
	decodeJWTSegment(t, parts[1], &pl)
	ttl := pl.Exp - pl.Iat
	if ttl != 1200 {
		t.Errorf("default ttl: want 1200 seconds, got %d", ttl)
	}
}

func TestGenerateJWT_CustomTTL(t *testing.T) {
	pemBytes, _ := generateTestP8PEM(t)
	tok, err := GenerateJWT(string(pemBytes), "KID", "ISS", "AUD", 30*time.Minute)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}
	parts := strings.Split(tok, ".")
	var pl jwtPayload
	decodeJWTSegment(t, parts[1], &pl)
	ttl := pl.Exp - pl.Iat
	if ttl != 1800 {
		t.Errorf("custom ttl: want 1800 seconds, got %d", ttl)
	}
}

func TestGenerateJWT_SignatureVerifies(t *testing.T) {
	pemBytes, key := generateTestP8PEM(t)
	tok, err := GenerateJWT(string(pemBytes), "KID", "ISS", "AUD", 0)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Fatalf("sig length: want 64, got %d", len(sigBytes))
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("signature verification failed")
	}
}
