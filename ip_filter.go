package caddyipfilter

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type IPFilter struct {
	Rules              []*Rule        `json:"rules"`
	Interval           caddy.Duration `json:"interval,omitempty"`
	Timeout            caddy.Duration `json:"timeout,omitempty"`
	TrustXForwardedFor bool           `json:"trust_x_forwarded_for,omitempty"`
	TrustXRealIP       bool           `json:"trust_x_real_ip,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

// ServeHTTP Implemented caddyhttp.MiddlewareHandler
func (filter *IPFilter) ServeHTTP(w http.ResponseWriter, r *http.Request,
	next caddyhttp.Handler) error {
	clientIPStr := filter.getRealIP(r)
	filter.logger.Debug("Client IP", zap.String("ip", clientIPStr))

	ip := net.ParseIP(clientIPStr)
	if ip == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return nil
	}

	for _, rule := range filter.Rules {
		match := rule.Match(ip)
		if !match {
			continue
		}
		if rule.Allow {
			break
		} else {
			filter.logger.Warn("Access blocked", zap.String("ip", clientIPStr))
			http.Error(w, "Access denied", http.StatusForbidden)
			return nil
		}
	}

	return next.ServeHTTP(w, r)
}

func (filter *IPFilter) updateRules(init bool) error {
	for _, rule := range filter.Rules {
		err := filter.updateRule(rule)
		if err != nil {
			if init {
				return err
			}
			filter.logger.Error("fail to update rule", zap.Error(err), zap.Strings("args", rule.Args))
		}
	}

	return nil
}

func (filter *IPFilter) updateRule(rule *Rule) error {
	var ctx context.Context
	var cancel context.CancelFunc
	if filter.Timeout > 0 {
		ctx, cancel = context.WithTimeout(filter.ctx, time.Duration(filter.Timeout))
	} else {
		ctx, cancel = context.WithTimeout(filter.ctx, 30*time.Second)
	}
	defer cancel()

	return rule.Fetch(ctx)
}

func (filter *IPFilter) getRealIP(r *http.Request) string {
	if filter.TrustXForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if ips := strings.Split(xff, ","); len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
	}
	if filter.TrustXRealIP {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
