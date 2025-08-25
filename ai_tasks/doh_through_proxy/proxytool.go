package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

func main() {
	// Test proxy detection
	fmt.Println("Testing proxy environment detection...")

	// Test without proxy
	fmt.Printf("No proxy set: %v\n", hasProxyEnvironment())

	// Test with HTTP_PROXY
	setEnvOrLog("HTTP_PROXY", "http://127.0.0.1:8080")
	fmt.Printf("HTTP_PROXY set: %v\n", hasProxyEnvironment())

	// Test with SOCKS proxy in HTTP_PROXY
	setEnvOrLog("HTTP_PROXY", "socks5://127.0.0.1:1080")
	fmt.Printf("SOCKS in HTTP_PROXY set: %v\n", hasProxyEnvironment())

	// Test with ALL_PROXY SOCKS
	unsetEnvOrLog("HTTP_PROXY")
	setEnvOrLog("ALL_PROXY", "socks5://127.0.0.1:1080")
	fmt.Printf("ALL_PROXY SOCKS set: %v\n", hasProxyEnvironment())

	// Test creating different types of upstreams with SOCKS proxy
	fmt.Println("\nTesting different upstream types with SOCKS proxy...")

	// Keep the SOCKS proxy setting for actual test
	setEnvOrLog("ALL_PROXY", "socks5://127.0.0.1:1080")

	opts := &upstream.Options{
		Logger:  slogutil.NewDiscardLogger(),
		Timeout: 5 * time.Second,
	}

	testUpstreams(opts)

	// Clean up
	unsetEnvOrLog("ALL_PROXY")
}

func setEnvOrLog(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		slog.Error("failed to set env", "key", key, "error", err)
	}
}

func unsetEnvOrLog(key string) {
	if err := os.Unsetenv(key); err != nil {
		slog.Error("failed to unset env", "key", key, "error", err)
	}
}

func testUpstreams(opts *upstream.Options) {
	testOne("8.8.8.8:53", "Plain DNS (UDP)", opts)
	testOne("tcp://8.8.8.8:53", "Plain DNS (TCP)", opts)
	testOne("tls://8.8.8.8:853", "DNS-over-TLS", opts)
	testOne("quic://8.8.8.8:853", "DNS-over-QUIC", opts)
	testOne("https://8.8.8.8/dns-query", "DNS-over-HTTPS", opts)
}

func testOne(addr, label string, opts *upstream.Options) {
	fmt.Println("Testing " + label + "...")
	u, err := upstream.AddressToUpstream(addr, opts)
	if err != nil {
		slog.Error("Failed to create "+label+" upstream", "error", err)
		return
	}

	fmt.Printf(label+" upstream created: %s\n", u.Address())
	testDNSQuery(u, label)
}

func testDNSQuery(u upstream.Upstream, protocol string) {
	// Create a test DNS query
	req := &dns.Msg{}
	req.SetQuestion("example.com.", dns.TypeA)

	fmt.Printf("  Attempting %s query through SOCKS proxy...", protocol)
	resp, err := u.Exchange(req)
	if err != nil {
		fmt.Printf(" FAILED (expected if no proxy is running): %v\n", err)
		if strings.Contains(err.Error(), "socks") || strings.Contains(err.Error(), "proxy") {
			fmt.Printf("  ✓ Confirmed: %s is trying to use SOCKS proxy\n", protocol)
		}
	} else {
		fmt.Printf(" SUCCESS: %d answers\n", len(resp.Answer))
	}
}

// hasProxyEnvironment checks if any proxy environment variables are set.
// This function checks for HTTP_PROXY, HTTPS_PROXY, and their lowercase versions.
func hasProxyEnvironment() bool {
	proxies := []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"ALL_PROXY", "all_proxy",
	}

	for _, proxy := range proxies {
		if os.Getenv(proxy) != "" {
			return true
		}
	}

	return false
}
