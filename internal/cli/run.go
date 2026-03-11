package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"authbear/internal/auth"
	"authbear/internal/config"
	"authbear/internal/secret"

	"golang.org/x/term"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func Run(args []string) int {
	if len(args) == 0 {
		printRootHelp()
		return 0
	}

	cfgPath, err := config.DefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	s, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	switch args[0] {
	case "profile":
		return runProfile(args[1:], cfgPath, s)
	case "login":
		return runLogin(args[1:], s)
	case "token":
		return runToken(args[1:], s)
	case "call":
		return runCall(args[1:], s)
	case "health":
		return runHealth(args[1:], s)
	case "logout":
		return runLogout(args[1:], s)
	case "env":
		return runEnv(args[1:], cfgPath, s)
	case "doctor":
		return runDoctor()
	case "help", "-h", "--help":
		printRootHelp()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", args[0])
		printRootHelp()
		return 1
	}
}

func runProfile(args []string, cfgPath string, s *config.Store) int {
	if len(args) == 0 {
		printProfileHelp()
		return 0
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "error: profile name required")
			return 1
		}
		name := args[1]

		fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		baseURL := fs.String("base-url", "", "Base URL for API requests")
		healthPath := fs.String("health-path", "", "Default health endpoint path")
		authType := fs.String("auth-type", config.AuthTypeBearer, "Auth type: bearer|api-key|oauth-device|jwt-p8")
		apiKeyHeader := fs.String("api-key-header", "X-API-Key", "Header name for api-key auth")
		tokenURL := fs.String("token-url", "", "OAuth token URL")
		deviceCodeURL := fs.String("device-code-url", "", "OAuth device code URL")
		clientID := fs.String("client-id", "", "OAuth client ID")
		scopes := fs.String("scopes", "", "Comma-separated OAuth scopes")
		audience := fs.String("audience", "", "OAuth audience (optional)")
		keyID := fs.String("key-id", "", "Apple key ID (jwt-p8)")
		issuerID := fs.String("issuer-id", "", "Apple issuer ID (jwt-p8)")
		jwtAud := fs.String("jwt-audience", "appstoreconnect-v1", "JWT audience (jwt-p8)")
		var envFlags multiFlag
		fs.Var(&envFlags, "env", "Env var in KEY=VALUE format (repeatable; for secrets use `authbear env set`)")
		if err := fs.Parse(args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}

		p := config.Profile{
			Name:          name,
			BaseURL:       strings.TrimRight(strings.TrimSpace(*baseURL), "/"),
			HealthPath:    strings.TrimSpace(*healthPath),
			AuthType:      strings.TrimSpace(*authType),
			APIKeyHeader:  strings.TrimSpace(*apiKeyHeader),
			TokenURL:      strings.TrimSpace(*tokenURL),
			DeviceCodeURL: strings.TrimSpace(*deviceCodeURL),
			ClientID:      strings.TrimSpace(*clientID),
			Audience:      strings.TrimSpace(*audience),
			KeyID:         strings.TrimSpace(*keyID),
			IssuerID:      strings.TrimSpace(*issuerID),
			JWTAudience:   strings.TrimSpace(*jwtAud),
		}
		if *scopes != "" {
			for _, item := range strings.Split(*scopes, ",") {
				item = strings.TrimSpace(item)
				if item != "" {
					p.Scopes = append(p.Scopes, item)
				}
			}
		}
		for _, kv := range envFlags {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
				fmt.Fprintf(os.Stderr, "error: invalid --env format %q, expected KEY=VALUE\n", kv)
				return 1
			}
			if p.Env == nil {
				p.Env = map[string]string{}
			}
			p.Env[strings.TrimSpace(parts[0])] = parts[1]
		}

		if err := config.ValidateProfile(p); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}

		s.Profiles[name] = p
		if err := config.Save(cfgPath, s); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("profile %q saved\n", name)
		return 0

	case "list":
		names := config.SortedNames(s)
		if len(names) == 0 {
			fmt.Println("no profiles configured")
			return 0
		}
		for _, n := range names {
			p := s.Profiles[n]
			fmt.Printf("%s\t%s\t%s\n", p.Name, p.AuthType, p.BaseURL)
		}
		return 0

	case "show":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "error: profile name required")
			return 1
		}
		p, ok := s.Profiles[args[1]]
		if !ok {
			fmt.Fprintf(os.Stderr, "error: profile %q not found\n", args[1])
			return 1
		}
		out, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(out))
		return 0

	case "remove":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "error: profile name required")
			return 1
		}
		name := args[1]
		if _, ok := s.Profiles[name]; !ok {
			fmt.Fprintf(os.Stderr, "error: profile %q not found\n", name)
			return 1
		}
		delete(s.Profiles, name)
		if err := config.Save(cfgPath, s); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("profile %q removed\n", name)
		return 0

	default:
		fmt.Fprintf(os.Stderr, "error: unknown profile subcommand %q\n\n", args[0])
		printProfileHelp()
		return 1
	}
}

func runLogin(args []string, s *config.Store) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "error: profile name required")
		return 1
	}
	name := args[0]
	p, ok := s.Profiles[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: profile %q not found\n", name)
		return 1
	}

	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	clientSecret := fs.String("client-secret", "", "OAuth client secret (optional)")
	keyFile := fs.String("key-file", "", "Path to .p8 private key file (jwt-p8)")
	deleteAfterStore := fs.Bool("delete-after-store", false, "Delete key file from disk after storing in keychain (jwt-p8)")
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	switch p.AuthType {
	case config.AuthTypeBearer:
		tok, err := promptHidden("Bearer token: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if err := secret.Set(bearerKey(name), tok); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("token stored for %q\n", name)
		return 0

	case config.AuthTypeAPIKey:
		key, err := promptHidden("API key: ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if err := secret.Set(apiKeyKey(name), key); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("api key stored for %q\n", name)
		return 0

	case config.AuthTypeOAuthDevice:
		if *clientSecret != "" {
			if err := secret.Set(clientSecretKey(name), *clientSecret); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return 1
			}
		}

		cs := strings.TrimSpace(*clientSecret)
		if cs == "" {
			stored, err := secret.Get(clientSecretKey(name))
			if err == nil {
				cs = stored
			}
		}

		hc := &http.Client{Timeout: 30 * time.Second}
		device, err := auth.StartDeviceFlow(hc, p.DeviceCodeURL, p.ClientID, p.Scopes, p.Audience)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}

		fmt.Println("Open this URL to authorize:")
		if device.VerificationURIComplete != "" {
			fmt.Println(device.VerificationURIComplete)
		} else {
			fmt.Println(device.VerificationURI)
			fmt.Printf("User code: %s\n", device.UserCode)
		}
		if device.Message != "" {
			fmt.Println(device.Message)
		}

		fmt.Println("Waiting for authorization...")
		tr, err := auth.PollDeviceToken(hc, p.TokenURL, p.ClientID, cs, device.DeviceCode, device.Interval, device.ExpiresIn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}

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
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if err := secret.Set(oauthTokenKey(name), raw); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("oauth token stored for %q\n", name)
		return 0

	case config.AuthTypeJWTP8:
		if *keyFile == "" {
			fmt.Fprintln(os.Stderr, "error: --key-file is required for jwt-p8")
			return 1
		}
		pemBytes, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read key file: %v\n", err)
			return 1
		}
		if err := auth.ValidateP8Key(pemBytes); err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid p8 key: %v\n", err)
			return 1
		}
		if err := secret.Set(jwtP8Key(name), string(pemBytes)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if *deleteAfterStore {
			if err := os.Remove(*keyFile); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not delete key file: %v\n", err)
			} else {
				fmt.Printf("key file %q deleted from disk\n", *keyFile)
			}
		}
		fmt.Printf("p8 key stored for %q\n", name)
		return 0

	default:
		fmt.Fprintf(os.Stderr, "error: unsupported auth type %q\n", p.AuthType)
		return 1
	}
}

func runToken(args []string, s *config.Store) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "error: profile name required")
		return 1
	}
	name := args[0]
	p, ok := s.Profiles[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: profile %q not found\n", name)
		return 1
	}

	tok, _, err := getAuthHeaderValue(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Println(tok)
	return 0
}

func runCall(args []string, s *config.Store) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "error: usage authbear call <profile> <METHOD> <path-or-url> [flags]")
		return 1
	}

	profileName := args[0]
	p, ok := s.Profiles[profileName]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: profile %q not found\n", profileName)
		return 1
	}

	method := strings.ToUpper(args[1])
	target := args[2]

	fs := flag.NewFlagSet("call", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var headers multiFlag
	var queries multiFlag
	fs.Var(&headers, "header", "Header in 'Key: Value' format (repeatable)")
	fs.Var(&queries, "query", "Query in 'key=value' format (repeatable)")
	jsonBody := fs.String("json", "", "JSON body string")
	dataPath := fs.String("data", "", "Read request body from file")
	rawOut := fs.Bool("raw", false, "Raw response output")
	responseJSON := fs.Bool("response-json", false, "Print machine-readable response envelope as JSON")
	withStatus := fs.Bool("status", false, "Print status and response headers")
	timeoutSec := fs.Int("timeout", 30, "Request timeout in seconds")

	if err := fs.Parse(args[3:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fullURL, err := buildURL(p.BaseURL, target, queries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	body, contentType, err := buildBody(*jsonBody, *dataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build request: %v\n", err)
		return 1
	}

	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "error: invalid --header format %q\n", h)
			return 1
		}
		req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	if contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}

	authHeaderValue, _, err := getAuthHeaderValue(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if p.AuthType == config.AuthTypeAPIKey {
		headerName := p.APIKeyHeader
		if headerName == "" {
			headerName = "X-API-Key"
		}
		req.Header.Set(headerName, authHeaderValue)
	} else {
		req.Header.Set("Authorization", authHeaderValue)
	}

	hc := &http.Client{Timeout: time.Duration(*timeoutSec) * time.Second}
	started := time.Now()
	resp, err := hc.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: request failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	latency := time.Since(started)

	if *withStatus {
		fmt.Printf("HTTP %d %s\n", resp.StatusCode, resp.Status)
		for k, vals := range resp.Header {
			for _, v := range vals {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
		fmt.Println()
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read response: %v\n", err)
		return 1
	}

	if *responseJSON {
		payload := map[string]any{
			"ok":          resp.StatusCode < 400,
			"method":      method,
			"url":         fullURL,
			"status_code": resp.StatusCode,
			"status":      resp.Status,
			"latency_ms":  latency.Round(time.Millisecond).Milliseconds(),
			"headers":     resp.Header,
		}

		var parsed any
		if err := json.Unmarshal(b, &parsed); err == nil {
			payload["body_json"] = parsed
		} else {
			payload["body_text"] = string(b)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(payload)

		if resp.StatusCode >= 400 {
			return 1
		}
		return 0
	}

	if *rawOut {
		fmt.Print(string(b))
	} else {
		pretty, ok := prettyJSON(b)
		if ok {
			fmt.Print(pretty)
		} else {
			fmt.Print(string(b))
		}
	}

	if resp.StatusCode >= 400 {
		return 1
	}
	return 0
}

func runHealth(args []string, s *config.Store) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "error: usage authbear health <profile> [flags]")
		return 1
	}

	profileName := args[0]
	p, ok := s.Profiles[profileName]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: profile %q not found\n", profileName)
		return 1
	}

	defaultPath := p.HealthPath
	if strings.TrimSpace(defaultPath) == "" {
		defaultPath = "/health"
	}

	fs := flag.NewFlagSet("health", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("path", defaultPath, "Health path or absolute URL")
	expect := fs.Int("expect", 200, "Expected status code")
	timeoutSec := fs.Int("timeout", 5, "Request timeout in seconds")
	noAuth := fs.Bool("no-auth", false, "Skip auth headers")
	jsonOut := fs.Bool("json", false, "Print machine-readable JSON output")
	var headers multiFlag
	var queries multiFlag
	fs.Var(&headers, "header", "Header in 'Key: Value' format (repeatable)")
	fs.Var(&queries, "query", "Query in 'key=value' format (repeatable)")

	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fullURL, err := buildURL(p.BaseURL, *path, queries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build request: %v\n", err)
		return 1
	}

	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "error: invalid --header format %q\n", h)
			return 1
		}
		req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	if !*noAuth {
		authHeaderValue, _, err := getAuthHeaderValue(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}

		if p.AuthType == config.AuthTypeAPIKey {
			headerName := p.APIKeyHeader
			if headerName == "" {
				headerName = "X-API-Key"
			}
			req.Header.Set(headerName, authHeaderValue)
		} else {
			req.Header.Set("Authorization", authHeaderValue)
		}
	}

	hc := &http.Client{Timeout: time.Duration(*timeoutSec) * time.Second}
	started := time.Now()
	resp, err := hc.Do(req)
	latency := time.Since(started)
	latencyMs := latency.Round(time.Millisecond).Milliseconds()

	type healthResult struct {
		OK           bool   `json:"ok"`
		Profile      string `json:"profile"`
		URL          string `json:"url"`
		ExpectedCode int    `json:"expected_code"`
		StatusCode   int    `json:"status_code,omitempty"`
		LatencyMs    int64  `json:"latency_ms"`
		Error        string `json:"error,omitempty"`
		Body         string `json:"body,omitempty"`
	}

	if err != nil {
		if *jsonOut {
			res := healthResult{
				OK:           false,
				Profile:      profileName,
				URL:          fullURL,
				ExpectedCode: *expect,
				LatencyMs:    latencyMs,
				Error:        err.Error(),
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
		} else {
			fmt.Printf("unhealthy %s (%s): request failed: %v\n", fullURL, latency.Round(time.Millisecond), err)
		}
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != *expect {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		snippet := strings.TrimSpace(string(body))
		if *jsonOut {
			res := healthResult{
				OK:           false,
				Profile:      profileName,
				URL:          fullURL,
				ExpectedCode: *expect,
				StatusCode:   resp.StatusCode,
				LatencyMs:    latencyMs,
				Body:         snippet,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
		} else {
			if snippet != "" {
				fmt.Printf("unhealthy %s (%s): got %d expected %d; body: %s\n", fullURL, latency.Round(time.Millisecond), resp.StatusCode, *expect, snippet)
			} else {
				fmt.Printf("unhealthy %s (%s): got %d expected %d\n", fullURL, latency.Round(time.Millisecond), resp.StatusCode, *expect)
			}
		}
		return 1
	}

	if *jsonOut {
		res := healthResult{
			OK:           true,
			Profile:      profileName,
			URL:          fullURL,
			ExpectedCode: *expect,
			StatusCode:   resp.StatusCode,
			LatencyMs:    latencyMs,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("healthy %s (%s): %d\n", fullURL, latency.Round(time.Millisecond), resp.StatusCode)
	}
	return 0
}

func runLogout(args []string, s *config.Store) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "error: profile name required")
		return 1
	}
	name := args[0]
	p, ok := s.Profiles[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: profile %q not found\n", name)
		return 1
	}

	switch p.AuthType {
	case config.AuthTypeBearer:
		_ = secret.Delete(bearerKey(name))
	case config.AuthTypeAPIKey:
		_ = secret.Delete(apiKeyKey(name))
	case config.AuthTypeOAuthDevice:
		_ = secret.Delete(oauthTokenKey(name))
		_ = secret.Delete(clientSecretKey(name))
	case config.AuthTypeJWTP8:
		_ = secret.Delete(jwtP8Key(name))
	}
	fmt.Printf("credentials removed for %q\n", name)
	return 0
}

func runEnv(args []string, cfgPath string, s *config.Store) int {
	if len(args) == 0 {
		printEnvHelp()
		return 0
	}

	switch args[0] {
	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "error: usage authbear env set <profile> <KEY>")
			return 1
		}
		name, key := args[1], args[2]
		p, ok := s.Profiles[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "error: profile %q not found\n", name)
			return 1
		}
		val, err := promptHidden(key + ": ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		if err := secret.Set(envKey(name, key), val); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		// Track the key name in the profile so env export knows to fetch it.
		for _, k := range p.SecretEnv {
			if k == key {
				fmt.Printf("secret env %q updated for profile %q\n", key, name)
				return 0
			}
		}
		p.SecretEnv = append(p.SecretEnv, key)
		sort.Strings(p.SecretEnv)
		s.Profiles[name] = p
		if err := config.Save(cfgPath, s); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("secret env %q stored for profile %q\n", key, name)
		return 0

	case "unset":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "error: usage authbear env unset <profile> <KEY>")
			return 1
		}
		name, key := args[1], args[2]
		p, ok := s.Profiles[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "error: profile %q not found\n", name)
			return 1
		}
		_ = secret.Delete(envKey(name, key))
		newKeys := p.SecretEnv[:0]
		for _, k := range p.SecretEnv {
			if k != key {
				newKeys = append(newKeys, k)
			}
		}
		p.SecretEnv = newKeys
		if len(p.SecretEnv) == 0 {
			p.SecretEnv = nil
		}
		s.Profiles[name] = p
		if err := config.Save(cfgPath, s); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 1
		}
		fmt.Printf("secret env %q removed from profile %q\n", key, name)
		return 0

	default:
		// Treat the first arg as a profile name: print export lines.
		name := args[0]
		p, ok := s.Profiles[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "error: profile %q not found\n", name)
			return 1
		}

		// Plain env vars from config.
		plainKeys := make([]string, 0, len(p.Env))
		for k := range p.Env {
			plainKeys = append(plainKeys, k)
		}
		sort.Strings(plainKeys)
		for _, k := range plainKeys {
			fmt.Printf("export %s=%s\n", k, shellQuote(p.Env[k]))
		}

		// Secret env vars from keychain.
		for _, k := range p.SecretEnv {
			val, err := secret.Get(envKey(name, k))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: secret env %q not found in keychain for profile %q\n", k, name)
				return 1
			}
			fmt.Printf("export %s=%s\n", k, shellQuote(val))
		}
		return 0
	}
}

// shellQuote wraps a value in single quotes, escaping any single quotes within.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func runDoctor() int {
	path, err := config.DefaultPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("config path: %s\n", path)
	fmt.Printf("config dir: %s\n", filepath.Dir(path))

	probeKey := "doctor-probe"
	if err := secret.Set(probeKey, "ok"); err != nil {
		fmt.Fprintf(os.Stderr, "keychain: fail (%v)\n", err)
		return 1
	}
	defer secret.Delete(probeKey)

	v, err := secret.Get(probeKey)
	if err != nil || v != "ok" {
		fmt.Fprintf(os.Stderr, "keychain: fail (%v)\n", err)
		return 1
	}

	fmt.Println("keychain: ok")
	return 0
}

func getAuthHeaderValue(p config.Profile) (string, bool, error) {
	switch p.AuthType {
	case config.AuthTypeBearer:
		tok, err := secret.Get(bearerKey(p.Name))
		if err != nil {
			return "", false, errors.New("missing bearer token; run `authbear login <profile>`")
		}
		return "Bearer " + tok, false, nil

	case config.AuthTypeAPIKey:
		key, err := secret.Get(apiKeyKey(p.Name))
		if err != nil {
			return "", false, errors.New("missing api key; run `authbear login <profile>`")
		}
		return key, false, nil

	case config.AuthTypeOAuthDevice:
		raw, err := secret.Get(oauthTokenKey(p.Name))
		if err != nil {
			return "", false, errors.New("missing oauth token; run `authbear login <profile>`")
		}
		stored, err := auth.DecodeStoredToken(raw)
		if err != nil {
			return "", false, err
		}

		refreshed := false
		if shouldRefresh(stored) {
			if stored.RefreshToken == "" {
				return "", false, errors.New("oauth token expired and no refresh token available; run `authbear login <profile>`")
			}
			cs, _ := secret.Get(clientSecretKey(p.Name))
			hc := &http.Client{Timeout: 30 * time.Second}
			tr, err := auth.RefreshToken(hc, p.TokenURL, p.ClientID, cs, stored.RefreshToken)
			if err != nil {
				return "", false, err
			}
			stored.AccessToken = tr.AccessToken
			if tr.RefreshToken != "" {
				stored.RefreshToken = tr.RefreshToken
			}
			if tr.TokenType != "" {
				stored.TokenType = tr.TokenType
			}
			if tr.Scope != "" {
				stored.Scope = tr.Scope
			}
			if tr.ExpiresIn > 0 {
				stored.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
			}

			newRaw, err := auth.EncodeStoredToken(*stored)
			if err != nil {
				return "", false, err
			}
			if err := secret.Set(oauthTokenKey(p.Name), newRaw); err != nil {
				return "", false, err
			}
			refreshed = true
		}

		typeName := strings.TrimSpace(stored.TokenType)
		if typeName == "" {
			typeName = "Bearer"
		}
		return typeName + " " + stored.AccessToken, refreshed, nil

	case config.AuthTypeJWTP8:
		pemKey, err := secret.Get(jwtP8Key(p.Name))
		if err != nil {
			return "", false, errors.New("missing p8 key; run `authbear login <profile>`")
		}
		audience := p.JWTAudience
		if audience == "" {
			audience = "appstoreconnect-v1"
		}
		tok, err := auth.GenerateJWT(pemKey, p.KeyID, p.IssuerID, audience, 0)
		if err != nil {
			return "", false, fmt.Errorf("generate jwt: %w", err)
		}
		return "Bearer " + tok, false, nil

	default:
		return "", false, fmt.Errorf("unsupported auth type %q", p.AuthType)
	}
}

func shouldRefresh(t *auth.StoredOAuthToken) bool {
	if t == nil {
		return false
	}
	if t.Expiry.IsZero() {
		return false
	}
	return time.Now().After(t.Expiry.Add(-30 * time.Second))
}

func buildURL(baseURL, target string, queryItems []string) (string, error) {
	var full string
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		full = target
	} else {
		if strings.TrimSpace(baseURL) == "" {
			return "", errors.New("profile has no base_url and target is not absolute URL")
		}
		if !strings.HasPrefix(target, "/") {
			target = "/" + target
		}
		full = strings.TrimRight(baseURL, "/") + target
	}

	u, err := url.Parse(full)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", err)
	}
	q := u.Query()
	for _, item := range queryItems {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid --query format %q", item)
		}
		q.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildBody(jsonBody, dataPath string) (io.Reader, string, error) {
	if jsonBody != "" && dataPath != "" {
		return nil, "", errors.New("use either --json or --data, not both")
	}
	if jsonBody != "" {
		return strings.NewReader(jsonBody), "application/json", nil
	}
	if dataPath != "" {
		b, err := os.ReadFile(dataPath)
		if err != nil {
			return nil, "", fmt.Errorf("read --data file: %w", err)
		}
		return bytes.NewReader(b), "application/octet-stream", nil
	}
	return nil, "", nil
}

func prettyJSON(b []byte) (string, bool) {
	if len(bytes.TrimSpace(b)) == 0 {
		return "", false
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return "", false
	}
	out.WriteByte('\n')
	return out.String(), true
}

func promptHidden(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read secret input: %w", err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", errors.New("input cannot be empty")
	}
	return v, nil
}

func bearerKey(name string) string       { return "profile:" + name + ":bearer" }
func apiKeyKey(name string) string       { return "profile:" + name + ":api-key" }
func oauthTokenKey(name string) string   { return "profile:" + name + ":oauth" }
func clientSecretKey(name string) string { return "profile:" + name + ":client-secret" }
func jwtP8Key(name string) string        { return "profile:" + name + ":jwt-p8" }
func envKey(profile, key string) string  { return "profile:" + profile + ":env:" + key }

func printRootHelp() {
	fmt.Print(`authbear - auth manager and API caller

Usage:
  authbear <command>

Commands:
  profile add|list|show|remove  Manage named profiles
  login <profile>               Authenticate and store credentials in keychain
  token <profile>               Print Authorization header value (or api key)
  call <profile> <METHOD> <url-or-path> [flags]
                                Call an endpoint with profile auth
  health <profile> [flags]      Check health endpoint with optional auth
  logout <profile>              Remove credentials from keychain
  env <profile>                 Print export statements for all env vars
  env set <profile> <KEY>       Store a secret env var in keychain
  env unset <profile> <KEY>     Remove a secret env var from keychain
  doctor                        Validate config path and keychain access

Examples:
  authbear profile add github --base-url https://api.github.com --auth-type bearer
  authbear login github
  authbear call github GET /user
  authbear health github --path /health
  authbear env set myprofile REVENUECAT_API_KEY
  eval $(authbear env myprofile)
`)
}

func printProfileHelp() {
	fmt.Print(`authbear profile - manage profiles

Usage:
  authbear profile add <name> [flags]
  authbear profile list
  authbear profile show <name>
  authbear profile remove <name>

Flags for add:
  --base-url         API base URL
  --health-path      Default health endpoint path
  --auth-type        bearer|api-key|oauth-device|jwt-p8
  --api-key-header   Header name for api-key auth (default X-API-Key)
  --token-url        OAuth token URL (oauth-device)
  --device-code-url  OAuth device code URL (oauth-device)
  --client-id        OAuth client ID (oauth-device)
  --scopes           Comma-separated OAuth scopes
  --audience         OAuth audience (optional)
  --key-id           Apple key ID (jwt-p8)
  --issuer-id        Apple issuer ID / team ID (jwt-p8)
  --jwt-audience     JWT audience claim (jwt-p8, default: appstoreconnect-v1)
  --env KEY=VALUE    Plain (non-secret) env var (repeatable)

Flags for login (jwt-p8):
  --key-file             Path to .p8 private key file
  --delete-after-store   Delete key file from disk after storing in keychain
`)
}

func printEnvHelp() {
	fmt.Print(`authbear env - manage environment variables for a profile

Usage:
  authbear env <profile>              Print export statements for all env vars
  authbear env set <profile> <KEY>    Store a secret env var in keychain (prompts for value)
  authbear env unset <profile> <KEY>  Remove a secret env var from keychain

Non-secret env vars are set via 'authbear profile add --env KEY=VALUE'.

Examples:
  authbear env set myprofile REVENUECAT_API_KEY
  authbear env myprofile
  eval $(authbear env myprofile)
`)
}
