package caddyipfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	cloudflareAPI = "https://api.cloudflare.com/client/v4/ips"
	cloudflareKey = "cloudflare"
)

type CloudflareResult struct {
	Result struct {
		Ipv4Cidrs []string `json:"ipv4_cidrs"`
		Ipv6Cidrs []string `json:"ipv6_cidrs"`
		Etag      string   `json:"etag"`
	} `json:"result"`
	Success  bool  `json:"success"`
	Errors   []any `json:"errors"`
	Messages []any `json:"messages"`
}

func fetchIPListFromCloudflare(ctx context.Context) (string, error) {
	b, err := fetch(ctx, cloudflareAPI)
	if err != nil {
		return "", err
	}
	var res CloudflareResult
	err = json.Unmarshal(b, &res)
	if err != nil {
		return "", err
	}
	if !res.Success {
		return "", fmt.Errorf("fetch ip list from cloudflare: %w", err)
	}
	return strings.Join(res.Result.Ipv4Cidrs, "\n") + "\n" + strings.Join(res.Result.Ipv6Cidrs, "\n"), nil
}
