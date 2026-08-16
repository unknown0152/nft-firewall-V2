package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestFeedRequiresHTTPS(t *testing.T) {
	_, err := (Feed{URL: "http://example.test"}).Fetch(context.Background())
	if err == nil {
		t.Fatal("HTTP feed accepted")
	}
}

func TestDefaultFeedClientRejectsNonPublicTargets(t *testing.T) {
	for _, target := range []string{"https://127.0.0.1/feed", "https://169.254.169.254/feed", "https://[::1]/feed"} {
		if _, err := (Feed{URL: target}).Fetch(context.Background()); err == nil {
			t.Fatalf("non-public threat feed target accepted: %s", target)
		}
	}
	for _, raw := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !isPublicFeedAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("public address rejected: %s", raw)
		}
	}
	for _, raw := range []string{"10.0.0.1", "100.64.0.1", "198.18.0.1", "fc00::1", "fe80::1"} {
		if isPublicFeedAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("non-public address accepted: %s", raw)
		}
	}
}

func TestFeedRejectsCredentialsAndAlwaysEnforcesRedirectLimit(t *testing.T) {
	if _, err := (Feed{URL: "https://user@example.test/feed"}).Fetch(context.Background()); err == nil {
		t.Fatal("credential-bearing feed URL accepted")
	}
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server.URL, http.StatusFound)
	}))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	if _, err := (Feed{URL: server.URL, Client: client}).Fetch(context.Background()); err == nil {
		t.Fatal("custom redirect policy bypassed the feed redirect cap")
	}
}
func TestFeedParserBoundsAndValidates(t *testing.T) {
	got, err := Parse([]byte("203.0.113.1\n203.0.113.2/32 # comment\n"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("unexpected feed: %v", got)
	}
	for _, body := range []string{"not-an-ip\n", "0.0.0.0/0\n"} {
		if _, err := Parse([]byte(body), 3); err == nil {
			t.Fatalf("malformed feed entry accepted: %q", body)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("203.0.113.1\n"), 10)
	f.Add([]byte("not-an-ip\n"), 1)
	f.Fuzz(func(t *testing.T, body []byte, max int) {
		if max < 1 || max > 1000 {
			max = 10
		}
		_, _ = Parse(body, max)
	})
}
