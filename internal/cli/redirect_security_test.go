package cli

import (
	"authbear/internal/config"
	"authbear/internal/secret"
	"github.com/zalando/go-keyring"
	"io"
	"net/http"
	"strings"
	"testing"
)

type redirectTransport func(*http.Request) (*http.Response, error)

func (f redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAPIKeyRedirectBoundary(t *testing.T) {
	for _, target := range []string{"https://other.invalid/destination", "http://trusted.invalid/destination", "https://trusted.invalid/destination"} {
		t.Run(target, func(t *testing.T) {
			keyring.MockInit()
			if err := secret.Set(apiKeyKey("fictional"), "fictional-key"); err != nil {
				t.Fatal(err)
			}
			old := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = old })
			reached := false
			http.DefaultTransport = redirectTransport(func(r *http.Request) (*http.Response, error) {
				h := make(http.Header)
				status := 200
				if r.URL.Path == "/start" {
					status = 302
					h.Set("Location", target)
				} else {
					reached = true
					if r.Header.Get("X-API-Key") != "fictional-key" {
						t.Error("trusted destination lost key")
					}
				}
				return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
			})
			p := config.Profile{Name: "fictional", BaseURL: "https://trusted.invalid", AuthType: config.AuthTypeAPIKey}
			runCall([]string{"fictional", "GET", "/start"}, &config.Store{Profiles: map[string]config.Profile{"fictional": p}})
			want := target == "https://trusted.invalid/destination"
			if reached != want {
				t.Errorf("redirect reached destination=%v, want %v", reached, want)
			}
		})
	}
}
