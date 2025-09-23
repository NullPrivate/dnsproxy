package upstream

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"golang.org/x/net/proxy"
)

// dialTCPWithOptionalProxy 根据系统代理设置选择 SOCKS 代理或引导拨号或直接拨号。
// - 若检测到 SOCKS 代理，优先通过 dialViaSocksProxy 建立连接；
// - 若提供了引导拨号器（bootstrap.DialHandler），使用其进行直连；
// - 否则回退使用默认的 net.Dialer；
// 该方法被 DoT/Plain TCP 回退等场景复用。
func dialTCPWithOptionalProxy(dialContext bootstrap.DialHandler, upstreamAddr string) (net.Conn, error) {
	proxyType, proxyURLStr := detectProxyTypeFor(upstreamAddr)

	if proxyType == ProxyTypeSOCKS {
		return dialViaSocksProxy(proxyURLStr, upstreamAddr)
	}

	if dialContext != nil {
		rawConn, err := dialContext(context.Background(), networkTCP, "")
		if err != nil {
			return nil, err
		}
		return rawConn, nil
	}

	var d net.Dialer
	rawConn, err := d.DialContext(context.Background(), networkTCP, upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("dialing upstream address: %w", err)
	}
	return rawConn, nil
}

// dialViaSocksProxy 使用 SOCKS 代理拨号 TCP 连接。
func dialViaSocksProxy(proxyURLStr, upstreamAddr string) (net.Conn, error) {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy url: %w", err)
	}

	dialer, err := proxy.FromURL(proxyURL, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("creating proxy dialer: %w", err)
	}

	rawConn, err := dialer.Dial(networkTCP, upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("dialing via proxy: %w", err)
	}

	return rawConn, nil
}
