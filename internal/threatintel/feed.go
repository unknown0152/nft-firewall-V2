package threatintel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type Feed struct {
	URL        string
	MaxEntries int
	MaxBytes   int64
	Client     *http.Client
}

func (f Feed) Fetch(ctx context.Context) ([]string, error) {
	if !strings.HasPrefix(strings.ToLower(f.URL), "https://") {
		return nil, errors.New("threat feed must use HTTPS")
	}
	max := f.MaxEntries
	if max <= 0 {
		max = 10000
	}
	bytes := f.MaxBytes
	if bytes <= 0 {
		bytes = 8 << 20
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	clientCopy := *client
	previousRedirect := clientCopy.CheckRedirect
	clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("threat feed redirect left HTTPS")
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		if len(via) >= 5 {
			return errors.New("too many threat feed redirects")
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := clientCopy.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("feed HTTP status %d", resp.StatusCode)
	}
	r := io.LimitReader(resp.Body, bytes+1)
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > bytes {
		return nil, errors.New("feed response exceeds byte limit")
	}
	return Parse(body, max)
}

func Parse(body []byte, max int) ([]string, error) {
	if max <= 0 {
		max = 10000
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 1024), 64<<10)
	seen := map[string]bool{}
	result := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			if ip, ipErr := netip.ParseAddr(line); ipErr == nil {
				p = netip.PrefixFrom(ip, ip.BitLen())
			} else {
				return nil, fmt.Errorf("invalid feed entry %q", line)
			}
		}
		if p.Bits() == 0 {
			return nil, fmt.Errorf("feed entry %q is /0", line)
		}
		if !seen[p.String()] {
			seen[p.String()] = true
			result = append(result, p.String())
			if len(result) > max {
				return nil, errors.New("feed entry limit exceeded")
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
