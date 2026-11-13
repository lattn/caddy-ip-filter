package caddyipfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestGitHubIPLists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"hooks":["192.0.2.0/24","2001:db8::/32"],"actions":["198.51.100.0/24"],"ssh_keys":["not an IP"]}`)
	}))
	defer server.Close()
	got, err := fetchGitHubIPList(context.Background(), server.URL, "github:hooks")
	if err != nil || got != "192.0.2.0/24\n2001:db8::/32" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := fetchGitHubIPList(context.Background(), server.URL, "github:unknown"); err == nil {
		t.Fatal("unknown category accepted")
	}
	if _, err := fetchGitHubIPList(context.Background(), server.URL, "github"); err == nil {
		t.Fatal("missing category accepted")
	}
}

func TestGitHubGlobalAndFailures(t *testing.T) {
	meta := map[string][]string{"ssh_keys": {"not an IP"}}
	for _, name := range githubCategories {
		meta[name] = []string{"192.0.2.0/24"}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(meta) }))
	defer server.Close()
	got, err := fetchGitHubIPList(context.Background(), server.URL, "github")
	if err != nil || len(strings.Split(got, "\n")) != len(githubCategories) {
		t.Fatalf("global list: %q, %v", got, err)
	}
	meta["hooks"] = []string{"invalid"}
	if _, err := fetchGitHubIPList(context.Background(), server.URL, "github:hooks"); err == nil {
		t.Fatal("invalid range accepted")
	}
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "failed", http.StatusServiceUnavailable) }))
	defer failed.Close()
	if _, err := fetchGitHubIPList(context.Background(), failed.URL, "github:hooks"); err == nil {
		t.Fatal("HTTP error accepted")
	}
}

func TestIndexedNetworks(t *testing.T) {
	r := NewRule(true, "10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32", "192.0.2.1")
	r.setLogger(zap.NewNop())
	if err := r.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip   string
		want bool
	}{{"10.2.0.1", true}, {"10.1.0.1", true}, {"11.0.0.1", false}, {"2001:db8::1", true}, {"2001:db9::1", false}, {"192.0.2.1", true}} {
		if got := r.Match(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("%s: got %v", tc.ip, got)
		}
	}
}

func BenchmarkNetworkMatch(b *testing.B) {
	lines := make([]string, 8350)
	for i := range lines {
		lines[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	_, networks := parseIPList(lines)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Join(lines, "\n")) }))
	defer server.Close()
	r := NewRule(true, server.URL)
	r.setLogger(zap.NewNop())
	if err := r.Fetch(context.Background()); err != nil {
		b.Fatal(err)
	}
	ip := net.ParseIP("203.0.113.1")
	b.Run("indexed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r.Match(ip)
		}
	})
	b.Run("linear", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, n := range networks {
				if n.Contains(ip) {
					break
				}
			}
		}
	})
}
