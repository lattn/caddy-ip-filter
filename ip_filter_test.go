package caddyipfilter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	blockIPList1 := "blockIPList.txt"
	blockIPList2 := "blockIPList2.txt"
	allowIPList1 := "allowIPList.txt"
	allowIPList2 := "allowIPList2.txt"
	config := fmt.Sprintf(`ip_filter {
		interval 1h
		timeout 10s
		deny %s %s
		allow %s %s
	}`, blockIPList1, blockIPList2, allowIPList1, allowIPList2)

	d := caddyfile.NewTestDispenser(config)

	filter := IPFilter{}
	err := filter.UnmarshalCaddyfile(d)
	if err != nil {
		t.Errorf("unmarshal error for %q: %v", config, err)
		return
	}

	expectedRules := []*Rule{
		NewRule(false, blockIPList1, blockIPList2),
		NewRule(true, allowIPList1, allowIPList2),
	}
	if !reflect.DeepEqual(filter.Rules, expectedRules) {
		t.Errorf("expected rules to be %v, got %v", expectedRules, filter.Rules)
	}

	if filter.Interval != caddy.Duration(1*time.Hour) {
		t.Errorf("expected interval to be 1h, got %v", filter.Interval)
	}

	if filter.Timeout != caddy.Duration(10*time.Second) {
		t.Errorf("expected timeout to be 10s, got %v", filter.Timeout)
	}
}

func TestRule_Match(t *testing.T) {
	tests := []struct {
		name     string
		list     []string
		ip       string
		expected bool
	}{
		{
			name:     "ipv4 in list",
			list:     []string{"192.168.1.1"},
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "ipv4 not in list",
			list:     []string{"192.168.1.1"},
			ip:       "192.168.1.2",
			expected: false,
		},
		{
			name:     "ipv4 in cidr",
			list:     []string{"192.168.1.0/24"},
			ip:       "192.168.1.100",
			expected: true,
		},
		{
			name:     "ipv4 not in cidr",
			list:     []string{"192.168.1.0/24"},
			ip:       "192.168.2.1",
			expected: false,
		},
		{
			name:     "ipv6 in list",
			list:     []string{"::1"},
			ip:       "::1",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, networks := parseIPList(tt.list)
			rule := &Rule{
				ips:      ips,
				networks: networks,
			}
			ip := net.ParseIP(tt.ip)
			if rule.Match(ip) != tt.expected {
				t.Errorf("expected %s in list %v to be %v", tt.ip, tt.list, tt.expected)
			}
		})
	}
}

func TestGetRealIP(t *testing.T) {
	filter := &IPFilter{}
	tests := []struct {
		name   string
		header http.Header
		remote string
		want   string
	}{
		{
			name:   "no headers",
			header: http.Header{},
			remote: "1.1.1.1:1234",
			want:   "1.1.1.1",
		},
		{
			name: "x-forwarded-for",
			header: http.Header{
				"X-Forwarded-For": []string{"2.2.2.2, 3.3.3.3"},
			},
			remote: "1.1.1.1:1234",
			want:   "2.2.2.2",
		},
		{
			name: "x-real-ip",
			header: http.Header{
				"X-Real-Ip": []string{"4.4.4.4"},
			},
			remote: "1.1.1.1:1234",
			want:   "4.4.4.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{
				Header:     tt.header,
				RemoteAddr: tt.remote,
			}
			filter.TrustXForwardedFor = true
			filter.TrustXRealIP = true
			if got := filter.getRealIP(r); got != tt.want {
				t.Errorf("getRealIP() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run(`do not trust xff and x-real-ip`, func(t *testing.T) {
		r := &http.Request{
			Header: http.Header{
				"X-Forwarded-For": []string{"2.2.2.2, 3.3.3.3"},
				"X-Real-Ip":       []string{"4.4.4.4"},
			},
			RemoteAddr: "1.1.1.1:1234",
		}
		filter.TrustXForwardedFor = false
		filter.TrustXRealIP = false
		if got := filter.getRealIP(r); got != "1.1.1.1" {
			t.Errorf("getRealIP() = %v, want %v", got, "1.1.1.1")
		}
	})
}

func TestServeHTTP(t *testing.T) {
	ips1, networks1 := parseIPList([]string{"1.1.1.1", "192.168.1.0/24"})
	ips2, networks2 := parseIPList([]string{"2.2.2.2"})
	filter := &IPFilter{
		Rules: []*Rule{
			{Allow: false, ips: ips1, networks: networks1},
			{Allow: true, ips: ips2, networks: networks2},
		},
		logger: zap.NewNop(),
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	tests := []struct {
		name       string
		ip         string
		statusCode int
	}{
		{"blocked ip", "1.1.1.1", http.StatusForbidden},
		{"blocked cidr", "192.168.1.100", http.StatusForbidden},
		{"allowed ip", "2.2.2.2", http.StatusOK},
		{"not in any list", "3.3.3.3", http.StatusOK},
		{"xff blocked", "1.1.1.1", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.name == "xff blocked" {
				req.Header.Set("X-Forwarded-For", tt.ip)
				filter.TrustXForwardedFor = true
			} else {
				req.RemoteAddr = tt.ip + ":12345"
			}
			rr := httptest.NewRecorder()
			filter.ServeHTTP(rr, req, next)
			if rr.Code != tt.statusCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					rr.Code, tt.statusCode)
			}
		})
	}
}

func TestRule_Fetch(t *testing.T) {
	// Create a dummy file for testing
	dummyFile := "test_list.txt"
	err := os.WriteFile(dummyFile, []byte("1.1.1.1\n2.2.2.0/24"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dummyFile)

	// Create a mock server for testing URL fetching
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "3.3.3.3\n4.4.4.0/24")
	}))
	defer server.Close()

	rule := NewRule(true, "file://"+dummyFile, server.URL, "5.5.5.5", "6.6.6.0/24")
	err = rule.Fetch(context.Background())
	if err != nil {
		t.Fatalf("error fetching rule: %v", err)
	}

	expectedIPs := []string{"1.1.1.1", "2.2.2.0/24", "3.3.3.3", "4.4.4.0/24", "5.5.5.5", "6.6.6.0/24"}
	var actualIPs []string
	for ip := range rule.ips {
		actualIPs = append(actualIPs, ip)
	}
	for _, ipNet := range rule.networks {
		actualIPs = append(actualIPs, ipNet.String())
	}

	// sort slices for comparison
	sort.Strings(expectedIPs)
	sort.Strings(actualIPs)

	if !reflect.DeepEqual(expectedIPs, actualIPs) {
		t.Errorf("expected ips %v, got %v", expectedIPs, actualIPs)
	}
}
