package upstream

import (
    "os"
    "testing"
)

func withEnv(k, v string, fn func()) {
    old, ok := os.LookupEnv(k)
    if v == "" {
        _ = os.Unsetenv(k)
    } else {
        _ = os.Setenv(k, v)
    }
    defer func() {
        if ok { _ = os.Setenv(k, old) } else { _ = os.Unsetenv(k) }
    }()
    fn()
}

func Test_matchesNOProxy(t *testing.T) {
    withEnv("NO_PROXY", "", func() {
        if matchesNOProxy("example.com", 443) {
            t.Fatal("expected no match when NO_PROXY empty")
        }
    })

    withEnv("NO_PROXY", "example.com", func() {
        if !matchesNOProxy("api.example.com", 443) { t.Fatal("suffix match failed") }
        if !matchesNOProxy("example.com", 853) { t.Fatal("exact domain match failed") }
        if matchesNOProxy("foo.bar", 443) { t.Fatal("unexpected non-suffix match") }
    })

    withEnv("NO_PROXY", "example.com:853", func() {
        if !matchesNOProxy("example.com", 853) { t.Fatal("port-specific match failed") }
        if matchesNOProxy("example.com", 443) { t.Fatal("port-specific should not match different port") }
    })

    withEnv("NO_PROXY", "10.0.0.0/8", func() {
        if !matchesNOProxy("10.1.2.3", 853) { t.Fatal("cidr match failed") }
        if matchesNOProxy("192.168.1.1", 53) { t.Fatal("cidr non-match failed") }
    })

    withEnv("NO_PROXY", "*", func() {
        if !matchesNOProxy("anything", 1) { t.Fatal("wildcard match failed") }
    })

    withEnv("NO_PROXY", "fd00::1", func() {
        if !matchesNOProxy("[fd00::1]", 853) { t.Fatal("ipv6 match with brackets failed") }
    })
}

func Test_detectProxyTypeFor_NO_PROXY_TakesPrecedence(t *testing.T) {
    // Set both ALL_PROXY and NO_PROXY; NO_PROXY should disable proxy for the target.
    withEnv("ALL_PROXY", "socks5://127.0.0.1:1080", func() {
        withEnv("NO_PROXY", "example.com", func() {
            if pt, _ := detectProxyTypeFor("api.example.com:443"); pt != ProxyTypeNone {
                t.Fatalf("expected ProxyTypeNone, got %v", pt)
            }
        })
    })
}

