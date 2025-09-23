package upstream

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// socksPacketConn 实现 net.PacketConn，通过 SOCKS5 UDP ASSOCIATE 中继报文。
//
// 注意：
// - 写入时忽略 WriteTo 提供的目的地址是否与中继一致，始终写到中继地址，并在数据前加 SOCKS5 头。
// - 读取时剥离 SOCKS5 头，并返回真实源地址（由中继头部提供）。
type socksPacketConn struct {
	udp       *net.UDPConn
	tcp       net.Conn
	relayAddr *net.UDPAddr

	readDeadline  time.Time
	writeDeadline time.Time
}

// newSocksPacketConn 建立到 SOCKS5 服务器的 UDP 中继通道并返回 PacketConn。
func newSocksPacketConn(proxyURLStr string) (net.PacketConn, error) {
	u, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, fmt.Errorf("parsing proxy url: %w", err)
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "1080")
	}

	// 建立到 SOCKS5 的 TCP 控制连接 + 认证
	var d net.Dialer
	tcpConn, err := d.Dial("tcp", host)
	if err != nil {
		return nil, fmt.Errorf("dial socks tcp: %w", err)
	}
	if err = socks5Handshake(tcpConn, u); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	// UDP ASSOCIATE 获取中继地址
	ip, port, err := socks5UDPAssociate(tcpConn)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	relay := &net.UDPAddr{IP: ip, Port: int(port)}

	// 建立到中继的 UDP 连接
	udpConn, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		_ = tcpConn.Close()
		return nil, fmt.Errorf("dial socks udp relay: %w", err)
	}

	return &socksPacketConn{udp: udpConn, tcp: tcpConn, relayAddr: relay}, nil
}

func (c *socksPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, 65535)
	n, _, err = c.udp.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}

	off, src, err := parseSocksUDPHeaderAddr(buf, n)
	if err != nil {
		return 0, nil, err
	}

	data := buf[off:n]
	if len(data) > len(b) {
		copy(b, data[:len(b)])
		return len(b), src, io.ErrShortBuffer
	}
	copy(b, data)
	return len(data), src, nil
}

// parseSocksUDPHeaderAddr 解析 SOCKS5 UDP 头并返回负载偏移与源地址。
func parseSocksUDPHeaderAddr(buf []byte, n int) (int, *net.UDPAddr, error) {
	if n < 4 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
		return 0, nil, fmt.Errorf("socks udp: bad header or fragmentation not supported")
	}
	off := 3
	if off >= n {
		return 0, nil, io.ErrUnexpectedEOF
	}

	newOff, ip, err := decodeSocksAddr(buf, off, n)
	if err != nil {
		return 0, nil, err
	}
	off = newOff

	if off+2 > n {
		return 0, nil, io.ErrUnexpectedEOF
	}
	port := int(binary.BigEndian.Uint16(buf[off : off+2]))
	off += 2

	return off, &net.UDPAddr{IP: ip, Port: port}, nil
}

// decodeSocksAddr 解析 ATYP + ADDR，返回新的偏移与解析出的 IP。
func decodeSocksAddr(buf []byte, off, n int) (int, net.IP, error) {
	if off >= n {
		return 0, nil, io.ErrUnexpectedEOF
	}
	atyp := buf[off]
	off++
	switch atyp {
	case 0x01:
		return decodeIPv4(buf, off, n)
	case 0x04:
		return decodeIPv6(buf, off, n)
	case 0x03:
		return decodeDomainIPFromBuf(buf, off, n)
	default:
		return 0, nil, fmt.Errorf("socks udp: unsupported ATYP 0x%02x", atyp)
	}
}

func decodeIPv4(buf []byte, off, n int) (int, net.IP, error) {
	if off+4 > n {
		return 0, nil, io.ErrUnexpectedEOF
	}
	return off + 4, net.IP(buf[off : off+4]), nil
}

func decodeIPv6(buf []byte, off, n int) (int, net.IP, error) {
	if off+16 > n {
		return 0, nil, io.ErrUnexpectedEOF
	}
	return off + 16, net.IP(buf[off : off+16]), nil
}

func decodeDomainIPFromBuf(buf []byte, off, n int) (int, net.IP, error) {
	if off >= n {
		return 0, nil, io.ErrUnexpectedEOF
	}
	l := int(buf[off])
	off++
	if off+l > n {
		return 0, nil, io.ErrUnexpectedEOF
	}
	name := string(buf[off : off+l])
	off += l
	ips, _ := net.LookupIP(name)
	if len(ips) > 0 {
		return off, ips[0], nil
	}
	return off, net.IPv4zero, nil
}

func (c *socksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	hdr, err := buildSocksUDPHeaderForAddr(addr)
	if err != nil {
		return 0, err
	}
	pkt := make([]byte, 0, len(hdr)+len(b))
	pkt = append(pkt, hdr...)
	pkt = append(pkt, b...)
	if _, err = c.udp.Write(pkt); err != nil {
		return 0, err
	}
	return len(b), nil
}

func buildSocksUDPHeaderForAddr(addr net.Addr) ([]byte, error) {
	ip, port, err := normalizeAddr(addr)
	if err != nil {
		return nil, err
	}
	var hdr bytes.Buffer
	hdr.Write([]byte{0x00, 0x00, 0x00})
	if ip4 := ip.To4(); ip4 != nil {
		hdr.WriteByte(0x01)
		hdr.Write(ip4)
	} else {
		if ip == nil {
			ip = net.IPv6zero
		}
		hdr.WriteByte(0x04)
		hdr.Write(ip.To16())
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	hdr.Write(portBuf[:])
	return hdr.Bytes(), nil
}

func normalizeAddr(addr net.Addr) (net.IP, int, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP, a.Port, nil
	case *net.TCPAddr:
		return a.IP, a.Port, nil
	default:
		h, p, e := net.SplitHostPort(addr.String())
		if e != nil {
			return nil, 0, e
		}
		port64, e := parsePort(p)
		if e != nil {
			return nil, 0, e
		}
		ip := net.ParseIP(strings.Trim(h, "[]"))
		if ip == nil {
			ips, _ := net.LookupIP(h)
			if len(ips) > 0 {
				ip = ips[0]
			}
		}
		return ip, int(port64), nil
	}
}

func (c *socksPacketConn) Close() error {
	_ = c.udp.Close()
	return c.tcp.Close()
}

func (c *socksPacketConn) LocalAddr() net.Addr { return c.udp.LocalAddr() }

func (c *socksPacketConn) SetDeadline(t time.Time) error {
	c.readDeadline, c.writeDeadline = t, t
	if err := c.udp.SetDeadline(t); err != nil {
		return err
	}
	return c.tcp.SetDeadline(t)
}

func (c *socksPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	if err := c.udp.SetReadDeadline(t); err != nil {
		return err
	}
	return c.tcp.SetReadDeadline(t)
}

func (c *socksPacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	if err := c.udp.SetWriteDeadline(t); err != nil {
		return err
	}
	return c.tcp.SetWriteDeadline(t)
}
