package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	
	"github.com/AdGuardPrivate/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

func main() {
	// Test proxy detection
	fmt.Println("Testing proxy environment detection...")
	
	// Test without proxy
	fmt.Printf("No proxy set: %v\n", hasProxyEnvironment())
	
	// Test with HTTP_PROXY
	os.Setenv("HTTP_PROXY", "http://127.0.0.1:8080")
	fmt.Printf("HTTP_PROXY set: %v\n", hasProxyEnvironment())
	
	// Test with SOCKS proxy in HTTP_PROXY
	os.Setenv("HTTP_PROXY", "socks5://127.0.0.1:1080")
	fmt.Printf("SOCKS in HTTP_PROXY set: %v\n", hasProxyEnvironment())
	
	// Test with ALL_PROXY SOCKS
	os.Unsetenv("HTTP_PROXY")
	os.Setenv("ALL_PROXY", "socks5://127.0.0.1:1080")
	fmt.Printf("ALL_PROXY SOCKS set: %v\n", hasProxyEnvironment())
	
	// Test creating different types of upstreams with SOCKS proxy
	fmt.Println("\nTesting different upstream types with SOCKS proxy...")
	
	// Keep the SOCKS proxy setting for actual test
	os.Setenv("ALL_PROXY", "socks5://127.0.0.1:1080")
	
	opts := &upstream.Options{
		Logger:  slogutil.NewDiscardLogger(),
		Timeout: 5 * time.Second,
	}
	
	// Test Plain DNS (UDP)
	fmt.Println("Testing Plain DNS (UDP)...")
	u1, err := upstream.AddressToUpstream("8.8.8.8:53", opts)
	if err != nil {
		log.Printf("Failed to create plain UDP upstream: %v", err)
	} else {
		fmt.Printf("Plain UDP upstream created: %s\n", u1.Address())
		testDNSQuery(u1, "Plain UDP")
	}
	
	// Test Plain DNS (TCP)
	fmt.Println("Testing Plain DNS (TCP)...")
	u2, err := upstream.AddressToUpstream("tcp://8.8.8.8:53", opts)
	if err != nil {
		log.Printf("Failed to create plain TCP upstream: %v", err)
	} else {
		fmt.Printf("Plain TCP upstream created: %s\n", u2.Address())
		testDNSQuery(u2, "Plain TCP")
	}
	
	// Test DNS-over-TLS
	fmt.Println("Testing DNS-over-TLS...")
	u3, err := upstream.AddressToUpstream("tls://8.8.8.8:853", opts)
	if err != nil {
		log.Printf("Failed to create DoT upstream: %v", err)
	} else {
		fmt.Printf("DoT upstream created: %s\n", u3.Address())
		testDNSQuery(u3, "DNS-over-TLS")
	}
	
	// Test DNS-over-QUIC
	fmt.Println("Testing DNS-over-QUIC...")
	u4, err := upstream.AddressToUpstream("quic://8.8.8.8:853", opts)
	if err != nil {
		log.Printf("Failed to create DoQ upstream: %v", err)
	} else {
		fmt.Printf("DoQ upstream created: %s\n", u4.Address())
		testDNSQuery(u4, "DNS-over-QUIC")
	}
	
	// Test DNS-over-HTTPS
	fmt.Println("Testing DNS-over-HTTPS...")
	u5, err := upstream.AddressToUpstream("https://8.8.8.8/dns-query", opts)
	if err != nil {
		log.Printf("Failed to create DoH upstream: %v", err)
	} else {
		fmt.Printf("DoH upstream created: %s\n", u5.Address())
		testDNSQuery(u5, "DNS-over-HTTPS")
	}
	
	// Clean up
	os.Unsetenv("ALL_PROXY")
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
