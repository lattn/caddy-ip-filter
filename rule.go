package caddyipfilter

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const ruleALl = "all"

type Rule struct {
	Allow       bool     `json:"allow"`
	Args        []string `json:"args"`
	ips         map[string]struct{}
	networks    []*net.IPNet
	prefixes    map[netip.Prefix]struct{}
	prefixBits4 []int
	prefixBits6 []int
	mutex       sync.RWMutex
	logger      *zap.Logger
}

func NewRule(allow bool, args ...string) *Rule {
	return &Rule{
		Allow:    allow,
		Args:     args,
		ips:      make(map[string]struct{}),
		networks: make([]*net.IPNet, 0),
	}
}

func (r *Rule) setLogger(logger *zap.Logger) {
	r.logger = logger.With(zap.Bool("allow", r.Allow), zap.Strings("args", r.Args))
}

func (r *Rule) Match(ip net.IP) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	if _, found := r.ips[ip.String()]; found {
		return true
	}
	if r.prefixes != nil {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return false
		}
		addr = addr.Unmap()
		bits := r.prefixBits6
		if addr.Is4() {
			bits = r.prefixBits4
		}
		for _, n := range bits {
			if _, found := r.prefixes[netip.PrefixFrom(addr, n).Masked()]; found {
				return true
			}
		}
		return false
	}
	for _, network := range r.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Rule) Fetch(ctx context.Context) error {
	r.logger.Debug("fetch list: start")

	newIPs := make(map[string]struct{})
	var newNetworks []*net.IPNet
	var newNetworkStrs []string

	for _, arg := range r.Args {
		ips, networks, err := loadIPList(ctx, arg)
		if err != nil {
			return err
		}
		for ip := range ips {
			newIPs[ip] = struct{}{}
		}
		newNetworks = append(newNetworks, networks...)
		for _, network := range networks {
			newNetworkStrs = append(newNetworkStrs, network.String())
		}
	}

	r.logger.Debug("fetch list: finish", zap.Any("ips", newIPs), zap.Any("networks", newNetworkStrs))

	prefixes := make(map[netip.Prefix]struct{}, len(newNetworks))
	bits4, bits6 := map[int]bool{}, map[int]bool{}
	for _, network := range newNetworks {
		prefix, err := netip.ParsePrefix(network.String())
		if err != nil {
			return err
		}
		prefix = prefix.Masked()
		prefixes[prefix] = struct{}{}
		if prefix.Addr().Is4() {
			bits4[prefix.Bits()] = true
		} else {
			bits6[prefix.Bits()] = true
		}
	}
	var prefixBits4, prefixBits6 []int
	for n := range bits4 {
		prefixBits4 = append(prefixBits4, n)
	}
	for n := range bits6 {
		prefixBits6 = append(prefixBits6, n)
	}
	r.mutex.Lock()
	r.ips = newIPs
	r.networks = newNetworks
	r.prefixes, r.prefixBits4, r.prefixBits6 = prefixes, prefixBits4, prefixBits6
	r.mutex.Unlock()
	return nil
}

func loadIPList(ctx context.Context, arg string) (map[string]struct{}, []*net.IPNet, error) {
	var content string
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		body, err := fetch(ctx, arg)
		if err != nil {
			return nil, nil, err
		}
		content = string(body)
	} else if strings.HasPrefix(arg, "file://") {
		data, err := os.ReadFile(strings.TrimPrefix(arg, "file://"))
		if err != nil {
			return nil, nil, err
		}
		content = string(data)
	} else if arg == cloudflareKey {
		data, err := fetchIPListFromCloudflare(ctx)
		if err != nil {
			return nil, nil, err
		}
		content = data
	} else if arg == "github" || strings.HasPrefix(arg, "github:") {
		data, err := fetchGitHubIPList(ctx, githubAPI, arg)
		if err != nil {
			return nil, nil, err
		}
		content = data
	} else if arg == ruleALl {
		content = "0.0.0.0/0\n::/0"
	} else {
		content = arg
	}

	lines := strings.Split(content, "\n")
	ips, networks := parseIPList(lines)
	return ips, networks, nil
}

func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fetch IP list: HTTP %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func parseIPList(lines []string) (map[string]struct{}, []*net.IPNet) {
	seen := make(map[string]struct{})
	ips := make(map[string]struct{})
	var networks []*net.IPNet
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}

		if _, network, err := net.ParseCIDR(line); err == nil {
			networks = append(networks, network)
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			ips[ip.String()] = struct{}{}
		}
	}
	return ips, networks
}
