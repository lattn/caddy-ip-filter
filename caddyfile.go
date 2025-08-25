package caddyipfilter

import (
	"fmt"
	"time"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"go.uber.org/zap"
)

// init Register the module
func init() {
	caddy.RegisterModule(&IPFilter{})
	httpcaddyfile.RegisterHandlerDirective("ip_filter", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("ip_filter", httpcaddyfile.Before, "basic_auth")
}

// CaddyModule Return information of Caddy module
func (*IPFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ip_filter",
		New: func() caddy.Module { return new(IPFilter) },
	}
}

// Provision Implemented caddy.Provisioner
func (filter *IPFilter) Provision(ctx caddy.Context) error {
	filter.ctx = ctx
	filter.logger = ctx.Logger(filter)

	if filter.Interval == 0 {
		filter.Interval = caddy.Duration(time.Hour)
	}

	if err := filter.updateRules(true); err != nil {
		return fmt.Errorf("updating IP lists: %v", err)
	}

	ticker := time.NewTicker(time.Duration(filter.Interval))
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				filter.logger.Debug("Start updating IP lists")
				if err := filter.updateRules(false); err != nil {
					filter.logger.Error("Failed to update IP lists", zap.Error(err))
				}
				filter.logger.Debug("Finish updating IP lists")
			case <-ctx.Done():
				filter.logger.Debug("IPFilter ticker exit")
				return
			}
		}
	}()

	return nil
}

// Validate Implemented caddy.Validator
func (filter *IPFilter) Validate() error {
	if len(filter.Rules) == 0 {
		return fmt.Errorf("at least 1 ip filter rule needs to be provided")
	}
	return nil
}

// UnmarshalCaddyfile Implemented caddyfile.Unmarshaler
func (filter *IPFilter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				filter.Interval = caddy.Duration(val)
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return err
				}
				filter.Timeout = caddy.Duration(val)
			case "allow":
				filter.Rules = append(filter.Rules, NewRule(true, d.RemainingArgs()...))
			case "deny":
				filter.Rules = append(filter.Rules, NewRule(false, d.RemainingArgs()...))
			case "trust_x_forwarded_for":
				filter.TrustXForwardedFor = true
			case "trust_x_real_ip":
				filter.TrustXRealIP = true
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}
