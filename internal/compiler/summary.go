package compiler

import (
	"bufio"
	"sort"
	"strings"
)

// ScriptSummary extracts operator-facing metadata from a compiler-produced
// generation. It is informational only and never participates in enforcement.
type ScriptSummary struct {
	Policies map[string]string   `json:"policies"`
	NAT      []string            `json:"nat"`
	Sets     map[string][]string `json:"sets"`
	IPv6Mode string              `json:"ipv6_mode"`
}

func SummarizeScript(script string) ScriptSummary {
	summary := ScriptSummary{Policies: map[string]string{}, Sets: map[string][]string{}}
	nat := map[string]bool{}
	currentSet := ""
	scanner := bufio.NewScanner(strings.NewReader(script))
	scanner.Buffer(make([]byte, 1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "set ") && strings.HasSuffix(line, "{") {
			fields := strings.Fields(line)
			if len(fields) == 3 {
				currentSet = fields[1]
			}
			continue
		}
		if currentSet != "" && strings.HasPrefix(line, "elements = {") {
			start := strings.IndexByte(line, '{')
			end := strings.LastIndexByte(line, '}')
			if start >= 0 && end > start {
				for _, value := range strings.Split(line[start+1:end], ",") {
					if value = strings.TrimSpace(value); value != "" {
						summary.Sets[currentSet] = append(summary.Sets[currentSet], value)
					}
				}
			}
			continue
		}
		if line == "}" && currentSet != "" {
			currentSet = ""
		}
		if name, ok := commentValue(line, "nftfw-policy:"); ok {
			action := "unknown"
			prefix := line[:strings.Index(line, "comment")]
			if strings.Contains(prefix, " accept ") {
				action = "allow"
			} else if strings.Contains(prefix, " drop ") {
				action = "deny"
			}
			summary.Policies[name] = action
		}
		if name, ok := commentValue(line, "nftfw-nat:"); ok {
			nat[name] = true
		}
		if mode, ok := commentValue(line, "nftfw:ipv6-mode-"); ok {
			summary.IPv6Mode = mode
		}
	}
	for name := range nat {
		summary.NAT = append(summary.NAT, name)
	}
	sort.Strings(summary.NAT)
	for name := range summary.Sets {
		sort.Strings(summary.Sets[name])
	}
	return summary
}

func commentValue(line, prefix string) (string, bool) {
	marker := `comment "` + prefix
	start := strings.Index(line, marker)
	if start < 0 {
		return "", false
	}
	value := line[start+len(marker):]
	end := strings.IndexByte(value, '"')
	if end < 0 {
		return "", false
	}
	return value[:end], true
}
