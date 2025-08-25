package caddyipfilter

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

const ruleALl = "all"

type Rule struct {
	Allow    bool
	Args     []string
	ips      map[string]struct{}
	networks []*net.IPNet
	mutex    sync.RWMutex
}

func NewRule(allow bool, args ...string) *Rule {
	return &Rule{
		Allow:    allow,
		Args:     args,
		ips:      make(map[string]struct{}),
		networks: make([]*net.IPNet, 0),
	}
}

func (r *Rule) Match(ip net.IP) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	if _, found := r.ips[ip.String()]; found {
		return true
	}
	for _, network := range r.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *Rule) Fetch(ctx context.Context) error {
	newIPs := make(map[string]struct{})
	var newNetworks []*net.IPNet

	for _, arg := range r.Args {
		ips, networks, err := loadIPList(ctx, arg)
		if err != nil {
			return err
		}
		for ip := range ips {
			newIPs[ip] = struct{}{}
		}
		newNetworks = append(newNetworks, networks...)
	}

	r.mutex.Lock()
	r.ips = newIPs
	r.networks = newNetworks
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
