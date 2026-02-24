package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Message                 string `json:"message"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`

	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type StoredOAuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	Scope        string    `json:"scope,omitempty"`
}

func StartDeviceFlow(client *http.Client, deviceCodeURL, clientID string, scopes []string, audience string) (*DeviceCodeResponse, error) {
	v := url.Values{}
	v.Set("client_id", clientID)
	if len(scopes) > 0 {
		v.Set("scope", strings.Join(scopes, " "))
	}
	if audience != "" {
		v.Set("audience", audience)
	}

	resp, err := client.Post(deviceCodeURL, "application/x-www-form-urlencoded", strings.NewReader(v.Encode()))
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read device code response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("device code request failed: %s", summarizeBody(b))
	}

	var out DeviceCodeResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}
	if out.DeviceCode == "" {
		return nil, errors.New("device code response missing device_code")
	}
	if out.Interval <= 0 {
		out.Interval = 5
	}
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 900
	}

	return &out, nil
}

func PollDeviceToken(client *http.Client, tokenURL, clientID, clientSecret, deviceCode string, intervalSec, expiresInSec int) (*TokenResponse, error) {
	deadline := time.Now().Add(time.Duration(expiresInSec) * time.Second)
	wait := time.Duration(intervalSec) * time.Second

	for time.Now().Before(deadline) {
		res, err := requestDeviceToken(client, tokenURL, clientID, clientSecret, deviceCode)
		if err != nil {
			return nil, err
		}

		switch res.Error {
		case "":
			return res, nil
		case "authorization_pending":
			time.Sleep(wait)
			continue
		case "slow_down":
			wait += 2 * time.Second
			time.Sleep(wait)
			continue
		case "expired_token":
			return nil, errors.New("device code expired before authorization completed")
		default:
			msg := res.Error
			if res.ErrorDescription != "" {
				msg += ": " + res.ErrorDescription
			}
			return nil, fmt.Errorf("device token flow failed: %s", msg)
		}
	}

	return nil, errors.New("timed out waiting for device authorization")
}

func RefreshToken(client *http.Client, tokenURL, clientID, clientSecret, refreshToken string) (*TokenResponse, error) {
	v := url.Values{}
	v.Set("grant_type", "refresh_token")
	v.Set("refresh_token", refreshToken)
	v.Set("client_id", clientID)
	if clientSecret != "" {
		v.Set("client_secret", clientSecret)
	}

	resp, err := client.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(v.Encode()))
	if err != nil {
		return nil, fmt.Errorf("refresh token request: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read refresh token response: %w", err)
	}

	out := &TokenResponse{}
	if err := json.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("decode refresh token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := out.Error
		if msg == "" {
			msg = summarizeBody(b)
		}
		if out.ErrorDescription != "" {
			msg += ": " + out.ErrorDescription
		}
		return nil, fmt.Errorf("refresh token failed: %s", msg)
	}

	if out.AccessToken == "" {
		return nil, errors.New("refresh token response missing access_token")
	}

	return out, nil
}

func requestDeviceToken(client *http.Client, tokenURL, clientID, clientSecret, deviceCode string) (*TokenResponse, error) {
	v := url.Values{}
	v.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	v.Set("device_code", deviceCode)
	v.Set("client_id", clientID)
	if clientSecret != "" {
		v.Set("client_secret", clientSecret)
	}

	resp, err := client.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(v.Encode()))
	if err != nil {
		return nil, fmt.Errorf("poll device token: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read device token response: %w", err)
	}

	out := &TokenResponse{}
	if err := json.Unmarshal(b, out); err != nil {
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("device token endpoint error: %s", summarizeBody(b))
		}
		return nil, fmt.Errorf("decode device token response: %w", err)
	}

	if resp.StatusCode >= 400 && out.Error == "" {
		out.Error = "http_" + strconv.Itoa(resp.StatusCode)
		out.ErrorDescription = summarizeBody(b)
	}

	return out, nil
}

func EncodeStoredToken(t StoredOAuthToken) (string, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("encode stored oauth token: %w", err)
	}
	return string(b), nil
}

func DecodeStoredToken(raw string) (*StoredOAuthToken, error) {
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	dec.DisallowUnknownFields()

	var out StoredOAuthToken
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode stored oauth token: %w", err)
	}
	if out.AccessToken == "" {
		return nil, errors.New("stored oauth token missing access_token")
	}
	return &out, nil
}

func summarizeBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "empty response"
	}
	if len(s) > 280 {
		return s[:280] + "..."
	}
	return s
}
