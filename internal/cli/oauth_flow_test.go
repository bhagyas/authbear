package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"authbear/internal/auth"
	"authbear/internal/config"
	"authbear/internal/secret"

	"github.com/zalando/go-keyring"
)

func TestOAuthDeviceFlowAndCalls(t *testing.T) {
	keyring.MockInit()

	profiles := &config.Store{Profiles: map[string]config.Profile{}}
	profile := config.Profile{
		Name:          "mock",
		BaseURL:       "https://api.mock",
		AuthType:      config.AuthTypeOAuthDevice,
		DeviceCodeURL: "https://auth.mock/device/code",
		TokenURL:      "https://auth.mock/token",
		ClientID:      "cli-tool",
		Scopes:        []string{"openid", "profile", "offline_access"},
	}
	profiles.Profiles[profile.Name] = profile

	client := &http.Client{Transport: oauthStubTransport{}}

	device, err := auth.StartDeviceFlow(client, profile.DeviceCodeURL, profile.ClientID, profile.Scopes, profile.Audience)
	if err != nil {
		t.Fatalf("start device flow: %v", err)
	}
	t.Logf("Device flow response: user code %q, verification %q", device.UserCode, device.VerificationURI)

	tr, err := auth.PollDeviceToken(client, profile.TokenURL, profile.ClientID, "", device.DeviceCode, device.Interval, device.ExpiresIn)
	if err != nil {
		t.Fatalf("poll device token: %v", err)
	}
	t.Logf("Token response: access %q refresh %q expires %d", tr.AccessToken, tr.RefreshToken, tr.ExpiresIn)

	stored := auth.StoredOAuthToken{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scope:        tr.Scope,
	}
	if tr.ExpiresIn > 0 {
		stored.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}

	raw, err := auth.EncodeStoredToken(stored)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	if err := secret.Set(oauthTokenKey(profile.Name), raw); err != nil {
		t.Fatalf("store token: %v", err)
	}

	head, _, err := getAuthHeaderValue(profile)
	if err != nil {
		t.Fatalf("get auth header: %v", err)
	}
	t.Logf("Authorization header that would be used: %s", head)

	snapshot, err := doCall(client, profile, head, "/v1/me")
	if err != nil {
		t.Fatalf("call /v1/me: %v", err)
	}
	t.Logf("/v1/me response: %s", snapshot)

	snapshot, err = doCall(client, profile, head, "/v1/data")
	if err != nil {
		t.Fatalf("call /v1/data: %v", err)
	}
	t.Logf("/v1/data response: %s", snapshot)
}

func doCall(client *http.Client, profile config.Profile, authHeader, path string) (string, error) {
	full, err := buildURL(profile.BaseURL, path, nil)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodGet, full, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", authHeader)
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

type oauthStubTransport struct{}

func (oauthStubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		defer req.Body.Close()
	}
	path := req.URL.Path
	if strings.HasSuffix(path, "/device/code") {
		resp := deviceCodeResponse{
			DeviceCode: "mock-device-code",
			UserCode:   "MOCK-CODE",
			URI:        "https://auth.mock/activate",
		}
		return respond(req, http.StatusOK, resp)
	}
	if strings.HasSuffix(path, "/token") {
		grant := parseForm(string(body)).Get("grant_type")
		if grant == "urn:ietf:params:oauth:grant-type:device_code" {
			return respond(req, http.StatusOK, tokenResponse{AccessToken: "mock-access-token", RefreshToken: "mock-refresh-token", TokenType: "Bearer", ExpiresIn: 600, Scope: "openid profile offline_access"})
		}
		if grant == "refresh_token" {
			return respond(req, http.StatusOK, tokenResponse{AccessToken: "refreshed-access-token", RefreshToken: "mock-refresh-token", TokenType: "Bearer", ExpiresIn: 600})
		}
	}
	if path == "/v1/me" || path == "/v1/data" {
		if req.Header.Get("Authorization") != "Bearer mock-access-token" {
			return respond(req, http.StatusUnauthorized, map[string]string{"error": "missing auth"})
		}
		if path == "/v1/me" {
			return respond(req, http.StatusOK, map[string]any{"id": "user", "email": "test@example.com"})
		}
		return respond(req, http.StatusOK, map[string]any{"items": []string{"alpha", "beta", "gamma"}})
	}
	return respond(req, http.StatusNotFound, map[string]string{"error": "unknown path"})
}

func respond(req *http.Request, status int, payload any) (*http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
		Request:    req,
	}, nil
}

func parseForm(body string) url.Values {
	vals, _ := url.ParseQuery(body)
	return vals
}

type deviceCodeResponse struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	URI        string `json:"verification_uri"`
	Message    string `json:"message"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}
