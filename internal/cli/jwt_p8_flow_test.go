package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"authbear/internal/config"
	"authbear/internal/secret"

	"github.com/zalando/go-keyring"
)

func generateJWTP8PEM(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), key
}

func TestJWTP8Flow_GetAuthHeader(t *testing.T) {
	keyring.MockInit()

	pemBytes, _ := generateJWTP8PEM(t)

	profile := config.Profile{
		Name:        "appstore-test",
		BaseURL:     "https://api.appstoreconnect.apple.com",
		AuthType:    config.AuthTypeJWTP8,
		KeyID:       "TESTKEY123",
		IssuerID:    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		JWTAudience: "appstoreconnect-v1",
	}

	if err := secret.Set(jwtP8Key(profile.Name), string(pemBytes)); err != nil {
		t.Fatalf("store p8 key: %v", err)
	}

	header, _, err := getAuthHeaderValue(profile)
	if err != nil {
		t.Fatalf("getAuthHeaderValue: %v", err)
	}

	if !strings.HasPrefix(header, "Bearer ") {
		t.Fatalf("expected Bearer prefix, got: %q", header)
	}

	tok := strings.TrimPrefix(header, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if hdr.Alg != "ES256" {
		t.Errorf("alg: want ES256, got %q", hdr.Alg)
	}
	if hdr.Kid != profile.KeyID {
		t.Errorf("kid: want %q, got %q", profile.KeyID, hdr.Kid)
	}
}

func TestJWTP8Flow_MissingKey(t *testing.T) {
	keyring.MockInit()

	profile := config.Profile{
		Name:     "no-key-profile",
		AuthType: config.AuthTypeJWTP8,
		KeyID:    "KID",
		IssuerID: "ISS",
	}

	_, _, err := getAuthHeaderValue(profile)
	if err == nil {
		t.Fatal("expected error for missing p8 key")
	}
	if !strings.Contains(err.Error(), "missing p8 key") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestJWTP8Flow_HTTPTransportVerifiesJWT(t *testing.T) {
	keyring.MockInit()

	pemBytes, key := generateJWTP8PEM(t)

	profile := config.Profile{
		Name:        "appstore-verify",
		BaseURL:     "https://api.appstoreconnect.apple.com",
		AuthType:    config.AuthTypeJWTP8,
		KeyID:       "MYKEY",
		IssuerID:    "my-issuer",
		JWTAudience: "appstoreconnect-v1",
	}

	if err := secret.Set(jwtP8Key(profile.Name), string(pemBytes)); err != nil {
		t.Fatalf("store p8 key: %v", err)
	}

	header, _, err := getAuthHeaderValue(profile)
	if err != nil {
		t.Fatalf("getAuthHeaderValue: %v", err)
	}

	client := &http.Client{Transport: &jwtVerifyTransport{pubKey: &key.PublicKey}}

	req, err := http.NewRequest(http.MethodGet, "https://api.appstoreconnect.apple.com/v1/apps", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", header)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

type jwtVerifyTransport struct {
	pubKey *ecdsa.PublicKey
}

func (tr *jwtVerifyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return respond(req, http.StatusUnauthorized, map[string]string{"error": "missing Bearer"})
	}
	tok := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return respond(req, http.StatusUnauthorized, map[string]string{"error": "invalid JWT structure"})
	}

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sigBytes) != 64 {
		return respond(req, http.StatusUnauthorized, map[string]string{"error": "invalid sig encoding"})
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(tr.pubKey, digest[:], r, s) {
		return respond(req, http.StatusUnauthorized, map[string]string{"error": "sig verification failed"})
	}

	data, _ := json.Marshal(map[string]string{"status": "ok"})
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
		Request:    req,
	}, nil
}
