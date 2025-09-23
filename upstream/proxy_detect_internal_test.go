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
		if ok {
			_ = os.Setenv(k, old)
		} else {
			_ = os.Unsetenv(k)
		}
	}()
	fn()
}

func Test_matchesNOProxy(t *testing.T) {
	cases := []struct {
		name string
		env  string
		host string
		port int
		want bool
	}{
		{"empty", "", "example.com", 443, false},
		{"suffix", "example.com", "api.example.com", 443, true},
		{"exact", "example.com", "example.com", 853, true},
		{"non_suffix", "example.com", "foo.bar", 443, false},
		{"port_match", "example.com:853", "example.com", 853, true},
		{"port_mismatch", "example.com:853", "example.com", 443, false},
		{"cidr_hit", "10.0.0.0/8", "10.1.2.3", 853, true},
		{"cidr_miss", "10.0.0.0/8", "192.168.1.1", 53, false},
		{"wildcard", "*", "anything", 1, true},
		{"ipv6_brackets", "fd00::1", "[fd00::1]", 853, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withEnv("NO_PROXY", c.env, func() {
				if got := matchesNOProxy(c.host, c.port); got != c.want {
					t.Fatalf("NO_PROXY=%q host=%q port=%d: got %v want %v", c.env, c.host, c.port, got, c.want)
				}
			})
		})
	}
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
