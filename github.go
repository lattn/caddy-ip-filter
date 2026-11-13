package caddyipfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

const githubAPI = "https://api.github.com/meta"

// Only IP range fields are included; the API also returns arrays of keys.
var githubCategories = []string{
	"hooks", "web", "shared_ingress", "api", "git", "github_enterprise_importer",
	"packages", "pages", "importer", "actions", "actions_macos", "codespaces", "copilot",
}

func fetchGitHubIPList(ctx context.Context, url, source string) (string, error) {
	categories := githubCategories
	if source != "github" {
		category := strings.TrimPrefix(source, "github:")
		known := false
		for _, name := range githubCategories {
			if name == category {
				known = true
				break
			}
		}
		if !known {
			return "", fmt.Errorf("unknown GitHub IP category %q", category)
		}
		categories = []string{category}
	}
	body, err := fetch(ctx, url)
	if err != nil {
		return "", err
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(body, &meta); err != nil {
		return "", fmt.Errorf("decode GitHub metadata: %w", err)
	}
	var ranges []string
	for _, category := range categories {
		var entries []string
		if len(meta[category]) == 0 {
			return "", fmt.Errorf("GitHub metadata missing %q", category)
		}
		if err := json.Unmarshal(meta[category], &entries); err != nil || len(entries) == 0 {
			return "", fmt.Errorf("invalid or empty GitHub IP category %q", category)
		}
		for _, entry := range entries {
			if _, err := netip.ParsePrefix(entry); err != nil {
				if _, err := netip.ParseAddr(entry); err != nil {
					return "", fmt.Errorf("invalid GitHub IP range %q in %s", entry, category)
				}
			}
		}
		ranges = append(ranges, entries...)
	}
	return strings.Join(ranges, "\n"), nil
}
