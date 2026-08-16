package threatintel

import (
	"context"
	"testing"
)

func TestFeedRequiresHTTPS(t *testing.T) {
	_, err := (Feed{URL: "http://example.test"}).Fetch(context.Background())
	if err == nil {
		t.Fatal("HTTP feed accepted")
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
