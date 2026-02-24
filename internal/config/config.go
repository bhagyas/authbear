package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	AuthTypeBearer      = "bearer"
	AuthTypeAPIKey      = "api-key"
	AuthTypeOAuthDevice = "oauth-device"
)

type Profile struct {
	Name          string   `json:"name"`
	BaseURL       string   `json:"base_url,omitempty"`
	AuthType      string   `json:"auth_type"`
	APIKeyHeader  string   `json:"api_key_header,omitempty"`
	TokenURL      string   `json:"token_url,omitempty"`
	DeviceCodeURL string   `json:"device_code_url,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
	Audience      string   `json:"audience,omitempty"`
}

type Store struct {
	Profiles map[string]Profile `json:"profiles"`
}

func DefaultPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(cfgDir, "authbear", "profiles.json"), nil
}

func Load(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{Profiles: map[string]Profile{}}, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if s.Profiles == nil {
		s.Profiles = map[string]Profile{}
	}
	return &s, nil
}

func Save(path string, s *Store) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize config: %w", err)
	}
	b = append(b, '\n')

	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func ValidateProfile(p Profile) error {
	p.AuthType = strings.TrimSpace(p.AuthType)
	switch p.AuthType {
	case AuthTypeBearer, AuthTypeAPIKey:
		return nil
	case AuthTypeOAuthDevice:
		if strings.TrimSpace(p.TokenURL) == "" {
			return errors.New("token_url is required for oauth-device")
		}
		if strings.TrimSpace(p.DeviceCodeURL) == "" {
			return errors.New("device_code_url is required for oauth-device")
		}
		if strings.TrimSpace(p.ClientID) == "" {
			return errors.New("client_id is required for oauth-device")
		}
		return nil
	default:
		return fmt.Errorf("unsupported auth type %q", p.AuthType)
	}
}

func SortedNames(s *Store) []string {
	names := make([]string, 0, len(s.Profiles))
	for name := range s.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
