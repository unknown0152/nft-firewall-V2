package threatintel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestFeedRequiresHTTPS(t *testing.T) {
	_, err := (Feed{URL: "http://example.test"}).Fetch(context.Background())
	if err == nil {
		t.Fatal("HTTP feed accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestFeedErrorsNeverExposeURLValues(t *testing.T) {
	for _, target := range []string{
		"https://feed.example.test/list?api_key=do-not-log",
		"https://feed.example.test/list#do-not-log",
		"https://feed.example.test/list#",
	} {
		_, err := (Feed{URL: target}).Fetch(context.Background())
		if err == nil {
			t.Fatalf("unsafe URL accepted: %s", target)
		}
		if strings.Contains(err.Error(), "do-not-log") || strings.Contains(err.Error(), target) {
			t.Fatalf("URL value escaped in validation error: %q", err)
		}
	}

	const secretPath = "do-not-log-transport-value"
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("failed request for %s: %w", request.URL.String(), errors.New(secretPath))
	})}
	_, err := (Feed{URL: "https://feed.example.test/" + secretPath, Client: client}).Fetch(context.Background())
	if err == nil {
		t.Fatal("synthetic transport failure unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), secretPath) || strings.Contains(err.Error(), "feed.example.test") {
		t.Fatalf("outbound HTTP error exposed the configured URL: %q", err)
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
	for _, raw := range []string{"10.0.0.1", "100.64.0.1", "198.18.0.1", "fc00::1", "fe80::1", "3fff::1"} {
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
	got, err := Parse([]byte("1.1.1.1\n8.8.8.8/32 # comment\n"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("unexpected feed: %v", got)
	}
	for _, body := range []string{"not-an-ip\n", "0.0.0.0/0\n", "0.0.0.0/1\n128.0.0.0/1\n"} {
		if _, err := Parse([]byte(body), 3); err == nil {
			t.Fatalf("malformed feed entry accepted: %q", body)
		}
	}
}

func TestFeedRejectsPrivateReservedAndOverlyBroadNetworks(t *testing.T) {
	for _, entry := range []string{
		"10.0.0.1",
		"192.168.10.0/24",
		"100.64.0.0/24",
		"169.254.1.0/24",
		"192.0.2.0/24",
		"1.0.0.0/23",
		"fc00::1",
		"fe80::/64",
		"2001:db8::/48",
		"2606:4700::/47",
	} {
		if _, err := Parse([]byte(entry+"\n"), 10); err == nil {
			t.Fatalf("unsafe threat prefix accepted: %s", entry)
		}
	}
	for _, entry := range []string{"1.1.1.0/24", "1.1.1.1/32", "2606:4700::/48", "2606:4700:4700::1111/128"} {
		if _, err := Parse([]byte(entry+"\n"), 10); err != nil {
			t.Fatalf("bounded public threat prefix rejected: %s: %v", entry, err)
		}
	}
}

func TestFeedRejectsExcessiveAggregateCoverage(t *testing.T) {
	for _, family := range []struct {
		name  string
		entry func(int) string
	}{
		{name: "ipv4", entry: func(i int) string { return fmt.Sprintf("8.%d.%d.0/24", i>>8, i&0xff) }},
		{name: "ipv6", entry: func(i int) string { return fmt.Sprintf("2600:0:%x::/48", i) }},
	} {
		t.Run(family.name, func(t *testing.T) {
			var body strings.Builder
			var atLimit string
			// 4096 widest allowed entries equal the per-family aggregate
			// limit; one more must fail even though every item is public.
			for i := 0; i <= 4096; i++ {
				fmt.Fprintln(&body, family.entry(i))
				if i == 4095 {
					atLimit = body.String()
				}
			}
			if _, err := Parse([]byte(atLimit), 5000); err != nil {
				t.Fatalf("feed exactly at aggregate coverage limit rejected: %v", err)
			}
			if _, err := Parse([]byte(body.String()), 5000); err == nil {
				t.Fatal("feed exceeding aggregate coverage was accepted")
			}
		})
	}
}

func TestFeedRejectsProtectedPublicPrefixes(t *testing.T) {
	addresses, err := Parse([]byte("1.1.1.0/24\n2606:4700:4700::/48\n"), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, protected := range [][]string{
		{"1.1.1.1/32"},
		{"2606:4700:4700::1111/128"},
	} {
		if err := Validate(addresses, protected); err == nil {
			t.Fatalf("feed overlapping protected public prefix accepted: %v", protected)
		}
	}
	if err := Validate(addresses, []string{"9.9.9.9/32"}); err != nil {
		t.Fatalf("disjoint protected prefix rejected: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("1.1.1.1\n"), 10)
	f.Add([]byte("not-an-ip\n"), 1)
	f.Fuzz(func(t *testing.T, body []byte, max int) {
		if max < 1 || max > 1000 {
			max = 10
		}
		_, _ = Parse(body, max)
	})
}
