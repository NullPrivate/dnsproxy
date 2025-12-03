package upstream

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// dialUDPViaSocks 通过 SOCKS5 建立 UDP ASSOCIATE 通道，并返回一个实现 net.Conn 的封装，
// 其 Write/Read 会自动添加/剥离 SOCKS5 UDP 头部，从而对上层表现为普通 UDP 连接。
func dialUDPViaSocks(proxyURLStr, upstreamHost string) (net.Conn, error) {
	u, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy url: %w", err)
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "1080")
	}

	// 与 SOCKS5 服务器建立 TCP 控制连接
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	tcpConnRaw, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("dial socks tcp: %w", err)
	}

	// 完成方法协商（仅支持 no-auth 与 username/password）
	if err = socks5Handshake(tcpConnRaw, u); err != nil {
		_ = tcpConnRaw.Close()
		return nil, err
	}

	// 发送 UDP ASSOCIATE 请求，请求服务器分配 UDP 中继地址
	bndAddr, bndPort, err := socks5UDPAssociate(tcpConnRaw)
	if err != nil {
		_ = tcpConnRaw.Close()
		return nil, err
	}

	// 建立到中继地址的 UDP“连接”
	raddr := &net.UDPAddr{IP: bndAddr, Port: int(bndPort)}
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		_ = tcpConnRaw.Close()
		return nil, fmt.Errorf("dial socks udp relay: %w", err)
	}

	// 返回封装连接；关闭时会同时关闭 TCP 控制连接
	return newSocksUDPConn(udpConn, tcpConnRaw, upstreamHost), nil
}

// socks5Handshake 执行 RFC1928 方法协商及可选的 RFC1929 认证。
func socks5Handshake(tcpConn net.Conn, u *url.URL) error {
	user, pass := credsFromURL(u)
	methods := chooseSocksMethods(user, pass)

	if err := writeSocksMethods(tcpConn, methods); err != nil {
		return err
	}

	method, err := readSocksChosenMethod(tcpConn)
	if err != nil {
		return err
	}

	switch method {
	case 0x00: // NoAuth
		return nil
	case 0x02: // Username/Password
		return doSocksUserPassAuth(tcpConn, user, pass)
	case 0xFF:
		return fmt.Errorf("socks: no acceptable auth methods")
	default:
		return fmt.Errorf("socks: unsupported method 0x%02x", method)
	}
}

func credsFromURL(u *url.URL) (user, pass string) {
	if u.User == nil {
		return "", ""
	}
	user = u.User.Username()
	pass, _ = u.User.Password()
	return user, pass
}

func chooseSocksMethods(user, pass string) []byte {
	if user != "" || pass != "" {
		return []byte{0x02}
	}
	return []byte{0x00}
}

func writeSocksMethods(w io.Writer, methods []byte) error {
	req := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := w.Write(req); err != nil {
		return fmt.Errorf("socks handshake write: %w", err)
	}
	return nil
}

func readSocksChosenMethod(r io.Reader) (byte, error) {
	resp := make([]byte, 2)
	if _, err := io.ReadFull(r, resp); err != nil {
		return 0, fmt.Errorf("socks handshake read: %w", err)
	}
	if resp[0] != 0x05 {
		return 0, fmt.Errorf("socks version mismatch: %d", resp[0])
	}
	return resp[1], nil
}

func doSocksUserPassAuth(tcpConn net.Conn, user, pass string) error {
	if user == "" && pass == "" {
		return fmt.Errorf("socks requested auth but no credentials provided")
	}
	ub := []byte(user)
	pb := []byte(pass)
	if len(ub) > 255 || len(pb) > 255 {
		return fmt.Errorf("socks credentials too long")
	}
	var buf bytes.Buffer
	buf.WriteByte(0x01)
	buf.WriteByte(byte(len(ub)))
	buf.Write(ub)
	buf.WriteByte(byte(len(pb)))
	buf.Write(pb)
	if _, err := tcpConn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("socks auth write: %w", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, authResp); err != nil {
		return fmt.Errorf("socks auth read: %w", err)
	}
	if authResp[1] != 0x00 {
		return fmt.Errorf("socks auth failed")
	}
	return nil
}

// socks5UDPAssociate 发送 UDP ASSOCIATE 请求，返回服务器分配的中继地址与端口。
// 若服务器返回的 BND.ADDR 为未指定地址（0.0.0.0 或 ::），按 RFC1928 约定，
// 客户端应当使用已建立的 TCP 控制连接的对端地址作为 UDP 中继 IP。
func socks5UDPAssociate(tcpConn net.Conn) (net.IP, uint16, error) {
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := tcpConn.Write(req); err != nil {
		return nil, 0, fmt.Errorf("socks udp associate write: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, hdr); err != nil {
		return nil, 0, fmt.Errorf("socks udp associate read header: %w", err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		return nil, 0, fmt.Errorf("socks udp associate failed: rep=0x%02x", hdr[1])
	}

	bndIP, err := readSocksAddr(tcpConn, hdr[3])
	if err != nil {
		return nil, 0, err
	}

	portBuf := make([]byte, 2)
	if _, e := io.ReadFull(tcpConn, portBuf); e != nil {
		return nil, 0, fmt.Errorf("socks read bnd.port: %w", e)
	}
	bndPort := binary.BigEndian.Uint16(portBuf)

	// 一些 SOCKS5 实现（例如部分服务器或移动端代理）会返回 0.0.0.0/:: 作为 BND.ADDR，
	// 表示 UDP 中继 IP 与 TCP 控制连接的对端 IP 相同。此时需要用 TCP 对端 IP 代替。
	if bndIP.Equal(net.IPv4zero) || bndIP.Equal(net.IPv6zero) {
		if raddr := tcpConn.RemoteAddr(); raddr != nil {
			if ta, ok := raddr.(*net.TCPAddr); ok && ta.IP != nil {
				bndIP = ta.IP
			} else {
				// 兜底解析字符串形式
				host, _, herr := net.SplitHostPort(raddr.String())
				if herr == nil {
					if ip := net.ParseIP(host); ip != nil {
						bndIP = ip
					}
				}
			}
		}
	}

	return bndIP, bndPort, nil
}

func readSocksAddr(r io.Reader, atyp byte) (net.IP, error) {
	switch atyp {
	case 0x01:
		return readIPN(r, 4, "v4")
	case 0x04:
		return readIPN(r, 16, "v6")
	case 0x03:
		return readDomainIP(r)
	default:
		return nil, fmt.Errorf("socks: unsupported ATYP 0x%02x", atyp)
	}
}

func readIPN(r io.Reader, n int, tag string) (net.IP, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("socks read bnd.addr %s: %w", tag, err)
	}
	return net.IP(buf), nil
}

func readDomainIP(r io.Reader) (net.IP, error) {
	var l [1]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, fmt.Errorf("socks read bnd.addr len: %w", err)
	}
	name := make([]byte, int(l[0]))
	if _, err := io.ReadFull(r, name); err != nil {
		return nil, fmt.Errorf("socks read bnd.addr name: %w", err)
	}
	ips, err := net.LookupIP(string(name))
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("resolve bnd.addr %q: %w", string(name), err)
	}
	return ips[0], nil
}

// socksUDPConn 封装 UDPConn 与保持映射用的 TCPConn。
type socksUDPConn struct {
	// 指针字段前置，减小指针区域
	udp *net.UDPConn
	tcp net.Conn

	readDeadline  time.Time
	writeDeadline time.Time

	// 将字符串放在末尾以填充指针对齐空隙
	targetHostPort string
}

func newSocksUDPConn(udp *net.UDPConn, tcp net.Conn, targetHostPort string) net.Conn {
	return &socksUDPConn{udp: udp, tcp: tcp, targetHostPort: targetHostPort}
}

func (c *socksUDPConn) Read(b []byte) (int, error) {
	buf := make([]byte, 65535)
	n, _, err := c.udp.ReadFromUDP(buf)
	if err != nil {
		return 0, err
	}
	off, err := parseSocksUDPHeader(buf, n)
	if err != nil {
		return 0, err
	}
	data := buf[off:n]
	if len(data) > len(b) {
		copy(b, data[:len(b)])
		return len(b), io.ErrShortBuffer
	}
	copy(b, data)
	return len(data), nil
}

func parseSocksUDPHeader(buf []byte, n int) (int, error) {
	if n < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
		return 0, fmt.Errorf("socks udp: bad header or fragmentation not supported")
	}
	off := 3
	if off >= n {
		return 0, io.ErrUnexpectedEOF
	}
	newOff, _, err := decodeSocksAddr(buf, off, n)
	if err != nil {
		return 0, err
	}
	off = newOff
	off += 2 // 跳过端口
	if off > n {
		return 0, io.ErrUnexpectedEOF
	}
	return off, nil
}

func (c *socksUDPConn) Write(b []byte) (int, error) {
	// 构造 SOCKS5 UDP 请求头
	host, portStr, err := net.SplitHostPort(c.targetHostPort)
	if err != nil {
		return 0, err
	}
	portUint, err := parsePort(portStr)
	if err != nil {
		return 0, err
	}

	var hdr bytes.Buffer
	hdr.Write([]byte{0x00, 0x00, 0x00}) // RSV(2)=0, FRAG=0

	// 处理主机名/IP
	h := strings.Trim(host, "[]")
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			hdr.WriteByte(0x01)
			hdr.Write(v4)
		} else {
			hdr.WriteByte(0x04)
			hdr.Write(ip.To16())
		}
	} else {
		if len(h) > 255 {
			return 0, fmt.Errorf("hostname too long for socks: %d", len(h))
		}
		hdr.WriteByte(0x03)
		hdr.WriteByte(byte(len(h)))
		hdr.WriteString(h)
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], portUint)
	hdr.Write(portBuf[:])

	packet := make([]byte, 0, hdr.Len()+len(b))
	packet = append(packet, hdr.Bytes()...)
	packet = append(packet, b...)

	_, err = c.udp.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socksUDPConn) Close() error {
	_ = c.udp.Close()
	return c.tcp.Close()
}

func (c *socksUDPConn) LocalAddr() net.Addr  { return c.udp.LocalAddr() }
func (c *socksUDPConn) RemoteAddr() net.Addr { return c.udp.RemoteAddr() }

func (c *socksUDPConn) SetDeadline(t time.Time) error {
	c.readDeadline, c.writeDeadline = t, t
	if err := c.udp.SetDeadline(t); err != nil {
		return err
	}
	return c.tcp.SetDeadline(t)
}

func (c *socksUDPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	if err := c.udp.SetReadDeadline(t); err != nil {
		return err
	}
	return c.tcp.SetReadDeadline(t)
}

func (c *socksUDPConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	if err := c.udp.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.tcp.SetWriteDeadline(t)
}

func parsePort(s string) (uint16, error) {
	var p uint64
	var err error
	if s == "" {
		return 0, fmt.Errorf("empty port")
	}
	// 手写解析以避免额外依赖；端口有效范围 1..65535（0 在此处不应出现）
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port: %s", s)
		}
		p = p*10 + uint64(c-'0')
		if p > 65535 {
			return 0, fmt.Errorf("invalid port: %s", s)
		}
	}
	return uint16(p), err
}
