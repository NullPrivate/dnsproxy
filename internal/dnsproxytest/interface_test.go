package dnsproxytest_test

import (
	"github.com/AdGuardPrivate/dnsproxy/internal/dnsmsg"
	"github.com/AdGuardPrivate/dnsproxy/internal/dnsproxytest"
	"github.com/AdGuardPrivate/dnsproxy/upstream"
)

// type checks
var (
	_ upstream.Upstream         = (*dnsproxytest.FakeUpstream)(nil)
	_ dnsmsg.MessageConstructor = (*dnsproxytest.TestMessageConstructor)(nil)
)
