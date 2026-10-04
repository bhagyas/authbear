package auth

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestRedirectPolicy(t *testing.T) {
	base, _ := url.Parse("https://trusted.invalid/start")
	first := &http.Request{URL: base}
	for _, tc := range []struct {
		target  string
		allowed bool
	}{
		{"https://trusted.invalid/next", true},
		{"https://other.invalid/next", false},
		{"http://trusted.invalid/next", false},
		{"https://trusted.invalid:8443/next", false},
	} {
		u, _ := url.Parse(tc.target)
		err := NewHTTPClient(time.Second).CheckRedirect(&http.Request{URL: u}, []*http.Request{first})
		if (err == nil) != tc.allowed {
			t.Errorf("redirect policy mismatch for %s", tc.target)
		}
	}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = first
	}
	if NewHTTPClient(time.Second).CheckRedirect(first, via) == nil {
		t.Fatal("redirect limit not enforced")
	}
}
