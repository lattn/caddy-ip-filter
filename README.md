# Caddy IP Filter Module

This module provides an IP filter middleware for Caddy, enabling you to block or allow requests based on the client's IP address.

## Features

- **Support for IPv4 and IPv6**: Works seamlessly with both IP address versions.
- **Flexible IP Definitions**: Supports single IP addresses (e.g., `192.168.1.1`), CIDR ranges (e.g., `192.168.1.0/24`), and Subnet masks.
- **Multiple IP Sources**: Fetch allow/block lists from a URL, local file, or directly from Cloudflare.
- **Dynamic Updates**: Automatically updates IP lists at a configurable interval.
- **Header Support**: Trust `X-Forwarded-For` and `X-Real-IP` headers to identify the client's IP address.

## IP List File Format

The IP list file should contain one IP address, CIDR range, or Subnet mask per line.

```
1.1.1.1
8.8.8.8
103.31.200.0/22
103.218.216.0/22
2405:f080:1000::/38
2405:f080:1400::/47
```

## Caddyfile Configuration

```caddyfile
:80 {
    ip_filter {
        # Deny IPs from a local file
        deny file:///var/block_ips.txt

        # Deny IPs from a URL
        deny https://example.com/block_ips.txt

        # Allow IPs from Cloudflare
        allow cloudflare

        # Allow GitHub webhook delivery IPs (or use github for all categories)
        allow github:hooks

        # Allow a single IP
        allow 1.2.3.4

        # Allow all IPs (if you want to use this as a logging tool)
        allow all
        
        # Set the update interval for the IP lists
        interval 1h
        
        # Set the timeout for fetching remote IP lists
        timeout 10s
        
        # Trust the X-Forwarded-For and X-Real-IP headers
        trust_x_forwarded_for
        trust_x_real_ip
    }

    reverse_proxy localhost:8080
}
```

## Parameters

| Name                  | Description                                                                                                | Type     | Default    |
|-----------------------|------------------------------------------------------------------------------------------------------------|----------|------------|
| `deny`                | A list of sources for the deny list. Sources can be a file path (prefixed with `file://`), a URL, `cloudflare`, `all`, a single IP, or a CIDR. | `string` | `[]`       |
| `allow`               | A list of sources for the allow list. Sources can be a file path (prefixed with `file://`), a URL, `cloudflare`, `all`, a single IP, or a CIDR. | `string` | `[]`       |
| `interval`            | The interval at which to update the IP lists.                                                              | `duration` | `1h`       |
| `timeout`             | The timeout for fetching remote IP lists.                                                                  | `duration` | `0s`       |
| `trust_x_forwarded_for` | Trust the `X-Forwarded-For` header to identify the client's IP address. By default, this is disabled.      | `bool`   | `false`    |
| `trust_x_real_ip`     | Trust the `X-Real-IP` header to identify the client's IP address. By default, this is disabled.            | `bool`   | `false`    |

**Note**: If neither `trust_x_forwarded_for` nor `trust_x_real_ip` is enabled, the module will use the remote address of the connection to identify the client's IP address.

## GitHub IP lists

`github` combines the IP ranges from the GitHub metadata API. Use `github:<category>` to select one category: `hooks`, `web`, `shared_ingress`, `api`, `git`, `github_enterprise_importer`, `packages`, `pages`, `importer`, `actions`, `actions_macos`, `codespaces`, or `copilot`. These sources are refreshed at the configured interval. New categories require a module update.

GitHub's Actions ranges are large and include shared cloud infrastructure; matching an address does not authenticate a GitHub workflow. For webhooks, validate the webhook signature as well as restricting the source IP. As with all rules, the first matching rule determines the outcome; unmatched requests are allowed, so an allowlist also needs a subsequent `deny all`.
