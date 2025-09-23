package upstream

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// network is the semantic type alias of the network to pass to dialing
// functions.  It's either [networkUDP] or [networkTCP].  It may also be used as
// URL scheme for plain upstreams.
type network = string

const (
	// networkUDP is the UDP network.
	networkUDP network = "udp"

	// networkTCP is the TCP network.
	networkTCP network = "tcp"
)

// plainDNS implements the [Upstream] interface for the regular DNS protocol.
type plainDNS struct {
	// addr is the DNS server URL.  Scheme is always "udp" or "tcp".
	addr *url.URL

	// logger is used for exchange logging.  It is never nil.
	logger *slog.Logger

	// getDialer either returns an initialized dial handler or creates a new
	// one.
	getDialer DialerInitializer

	// net is the network of the connections.
	net network

	// timeout is the timeout for DNS requests.
	timeout time.Duration
}

// newPlain returns the plain DNS Upstream.  addr.Scheme should be either "udp"
// or "tcp".
func newPlain(addr *url.URL, opts *Options) (u *plainDNS, err error) {
	switch addr.Scheme {
	case networkUDP, networkTCP:
		// Go on.
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", addr.Scheme)
	}

	addPort(addr, defaultPortPlain)

	// 当环境变量 USE_TCP_REPLACE_UDP=1 且该目标需要通过 SOCKS 代理时：
	// 若用户指定为 udp:53，则强制改为 tcp:53（仅影响该 upstream）。
	// 无代理或非 SOCKS 代理时不转换。
	if os.Getenv("USE_TCP_REPLACE_UDP") == "1" && addr.Scheme == string(networkUDP) {
		if pt, _ := detectProxyTypeFor(addr.Host); pt == ProxyTypeSOCKS {
			if addr.Port() == "53" { // 明确的 53 端口（addPort 已确保默认端口补全为 53）
				addr.Scheme = string(networkTCP)
			}
		}
	}

	return &plainDNS{
		addr:      addr,
		logger:    opts.Logger,
		getDialer: newDialerInitializer(addr, opts),
		net:       addr.Scheme,
		timeout:   opts.Timeout,
	}, nil
}

// type check
var _ Upstream = &plainDNS{}

// Address implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Address() string {
	switch p.net {
	case networkUDP, networkTCP:
		return p.addr.Host
	// case networkTCP:
	// 	return p.addr.String()
	default:
		panic(fmt.Sprintf("unexpected network: %s", p.net))
	}
}

// dialExchange performs a DNS exchange with the specified dial handler.
// network must be either [networkUDP] or [networkTCP].
func (p *plainDNS) dialExchange(
	network network,
	dial bootstrap.DialHandler,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	addr := p.Address()
	client := &dns.Client{Timeout: p.timeout}

	conn := &dns.Conn{}
	if network == networkUDP {
		conn.UDPSize = dns.MinMsgSize
	}

	logBegin(p.logger, addr, network, req)
	defer func() { logFinish(p.logger, addr, network, err) }()

	ctx := context.Background()
	conn.Conn, err = p.dialConnForNetwork(ctx, network, dial)
	if err != nil {
		return nil, fmt.Errorf("dialing %s over %s: %w", p.addr.Host, network, err)
	}
	defer func(c net.Conn) { err = errors.WithDeferred(err, c.Close()) }(conn.Conn)

	resp, err = p.doExchangeWithRetry(client, conn, req, ctx, network, dial)
	if err != nil {
		return resp, fmt.Errorf("exchanging with %s over %s: %w", addr, network, err)
	}

	return resp, validatePlainResponse(req, resp)
}

func (p *plainDNS) dialConnForNetwork(ctx context.Context, network network, dial bootstrap.DialHandler) (net.Conn, error) {
	switch network {
	case networkUDP:
		if pt, proxyURL := detectProxyTypeFor(p.addr.Host); pt == ProxyTypeSOCKS {
			return dialUDPViaSocks(proxyURL, p.addr.Host)
		}
		return dial(ctx, network, "")
	case networkTCP:
		if pt, _ := detectProxyTypeFor(p.addr.Host); pt == ProxyTypeSOCKS {
			return dialTCPWithOptionalProxy(dial, p.addr.Host)
		}
		return dial(ctx, network, "")
	default:
		return dial(ctx, network, "")
	}
}

func (p *plainDNS) doExchangeWithRetry(client *dns.Client, conn *dns.Conn, req *dns.Msg, ctx context.Context, network network, dial bootstrap.DialHandler) (*dns.Msg, error) {
	resp, _, err := client.ExchangeWithConn(req, conn)
	if !isExpectedConnErr(err) {
		return resp, err
	}
	// 重试一次
	c2, dErr := dial(ctx, network, "")
	if dErr != nil {
		return nil, dErr
	}
	defer func() { _ = c2.Close() }()
	conn.Conn = c2
	resp, _, err = client.ExchangeWithConn(req, conn)
	return resp, err
}

// isExpectedConnErr returns true if the error is expected.  In this case,
// we will make a second attempt to process the request.
func isExpectedConnErr(err error) (is bool) {
	var netErr net.Error

	return err != nil && (errors.As(err, &netErr) || errors.Is(err, io.EOF))
}

// Exchange implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	dial, err := p.getDialer()
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	addr := p.Address()

	resp, err = p.dialExchange(p.net, dial, req)
	if p.net != networkUDP {
		// The network is already TCP.
		return resp, err
	}

	if resp == nil {
		// There is likely an error with the upstream.
		return resp, err
	}

	if errors.Is(err, errQuestion) {
		// The upstream responds with malformed messages, so try TCP.
		p.logger.Debug(
			"plain response is malformed, using tcp",
			"addr", addr,
			slogutil.KeyError, err,
		)

		return p.dialExchange(networkTCP, dial, req)
	} else if resp.Truncated {
		// Fallback to TCP on truncated responses.
		p.logger.Debug(
			"plain response is truncated, using tcp",
			"question", &req.Question[0],
			"addr", addr,
		)

		return p.dialExchange(networkTCP, dial, req)
	}

	// There is either no error or the error isn't related to the received
	// message.
	return resp, err
}

// Close implements the [Upstream] interface for *plainDNS.
func (p *plainDNS) Close() (err error) {
	return nil
}

// errQuestion is returned when a message has malformed question section.
const errQuestion errors.Error = "bad question section"

// validatePlainResponse validates resp from an upstream DNS server for
// compliance with req.  Any error returned wraps [ErrQuestion], since it
// essentially validates the question section of resp.
func validatePlainResponse(req, resp *dns.Msg) (err error) {
	if qlen := len(resp.Question); qlen != 1 {
		return fmt.Errorf("%w: only 1 question allowed; got %d", errQuestion, qlen)
	}

	reqQ, respQ := req.Question[0], resp.Question[0]

	if reqQ.Qtype != respQ.Qtype {
		return fmt.Errorf("%w: mismatched type %s", errQuestion, dns.Type(respQ.Qtype))
	}

	// Compare the names case-insensitively, just like CoreDNS does.
	if !strings.EqualFold(reqQ.Name, respQ.Name) {
		return fmt.Errorf("%w: mismatched name %q", errQuestion, respQ.Name)
	}

	return nil
}
