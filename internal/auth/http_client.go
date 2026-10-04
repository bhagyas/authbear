package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// NewHTTPClient keeps credentials, including custom API-key headers and OAuth
// POST bodies, on the origin explicitly selected by the user.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if len(via) == 0 {
			return nil
		}
		initial := via[0].URL
		if !strings.EqualFold(req.URL.Scheme, initial.Scheme) || !strings.EqualFold(req.URL.Host, initial.Host) {
			return errors.New("refusing credentialed redirect to a different origin")
		}
		return nil
	}}
}
