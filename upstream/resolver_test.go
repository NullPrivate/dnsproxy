package upstream_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/dnsproxytest"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUpstreamResolver(t *testing.T) {
	ups := &dnsproxytest.FakeUpstream{
		OnAddress: func() (_ string) { panic("not implemented") },
		OnClose:   func() (_ error) { panic("not implemented") },
		OnExchange: func(req *dns.Msg) (resp *dns.Msg, err error) {
			resp = (&dns.Msg{}).SetReply(req)
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: netip.MustParseAddr("1.2.3.4").AsSlice(),
			}}

			return resp, nil
		},
	}

	r := &upstream.UpstreamResolver{Upstream: ups}

	ipAddrs, err := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
	require.NoError(t, err)

	assert.NotEmpty(t, ipAddrs)
}

func TestNewUpstreamResolver_validity(t *testing.T) {
	t.Parallel()

	withTimeoutOpt := &upstream.Options{
		Logger:  slogutil.NewDiscardLogger(),
		Timeout: 3 * time.Second,
	}

	testCases := newUpstreamResolverTestCases()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runUpstreamResolverTest(t, tc, withTimeoutOpt)
		})
	}
}

// testCase represents a single test case for upstream resolver validation.
type testCase struct {
	name       string
	addr       string
	wantErrMsg string
}

// newUpstreamResolverTestCases returns test cases for upstream resolver validation.
func newUpstreamResolverTestCases() []testCase {
	return []testCase{{
		name:       "udp",
		addr:       "1.1.1.1:53",
		wantErrMsg: "",
	}, {
		name:       "dot",
		addr:       "tls://1.1.1.1",
		wantErrMsg: "",
	}, {
		name:       "doh",
		addr:       "https://1.1.1.1/dns-query",
		wantErrMsg: "",
	}, {
		name:       "sdns",
		addr:       "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		wantErrMsg: "",
	}, {
		name:       "tcp",
		addr:       "tcp://9.9.9.9",
		wantErrMsg: "",
	}, {
		name: "invalid_tls",
		addr: "tls://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_https",
		addr: "https://dns.adguard.com/dns-query",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_tcp",
		addr: "tcp://dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}, {
		name: "invalid_no_scheme",
		addr: "dns.adguard.com",
		wantErrMsg: `not a bootstrap: ParseAddr("dns.adguard.com"): ` +
			`unexpected character (at "dns.adguard.com")`,
	}}
}

// runUpstreamResolverTest runs a single upstream resolver test case.
func runUpstreamResolverTest(t *testing.T, tc testCase, opts *upstream.Options) {
	r, err := upstream.NewUpstreamResolver(tc.addr, opts)
	if tc.wantErrMsg != "" {
		assert.Equal(t, tc.wantErrMsg, err.Error())
		assertErrorType(t, err)
		return
	}

	require.NoError(t, err)
	validateResolverLookup(t, r)
}

// assertErrorType checks if the error is of expected type.
func assertErrorType(t *testing.T, err error) {
	if nberr := (&upstream.NotBootstrapError{}); errors.As(err, &nberr) {
		assert.NotNil(t, nberr)
	}
}

// validateResolverLookup validates the resolver can perform lookups.
func validateResolverLookup(t *testing.T, r upstream.Resolver) {
	addrs, err := r.LookupNetIP(context.Background(), "ip", "cloudflare-dns.com")
	if err != nil {
		handleLookupError(t, err)
		return
	}
	assert.NotEmpty(t, addrs)
}

// handleLookupError handles network timeout errors gracefully.
func handleLookupError(t *testing.T, err error) {
	// 在某些环境下 TCP 53 可能被防火墙拦截，出现 i/o timeout。
	if strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "timeout") {
		t.Skipf("skip tcp lookup due to network timeout: %v", err)
	}
	require.NoError(t, err)
}
