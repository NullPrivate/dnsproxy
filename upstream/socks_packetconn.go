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
    // 读取自中继的 UDP 数据并剥离 SOCKS5 头
    buf := make([]byte, 65535)
    n, _, err = c.udp.ReadFromUDP(buf)
    if err != nil {
        return 0, nil, err
    }
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
    atyp := buf[off]
    off++

    var ip net.IP
    switch atyp {
    case 0x01: // IPv4
        if off+4 > n { return 0, nil, io.ErrUnexpectedEOF }
        ip = net.IP(buf[off:off+4])
        off += 4
    case 0x04: // IPv6
        if off+16 > n { return 0, nil, io.ErrUnexpectedEOF }
        ip = net.IP(buf[off:off+16])
        off += 16
    case 0x03: // DOMAIN
        if off >= n { return 0, nil, io.ErrUnexpectedEOF }
        l := int(buf[off])
        off++
        if off+l > n { return 0, nil, io.ErrUnexpectedEOF }
        // 尽量解析域名为 IP（返回的域名较少见）；解析失败时返回 0.0.0.0
        name := string(buf[off : off+l])
        off += l
        ips, _ := net.LookupIP(name)
        if len(ips) > 0 { ip = ips[0] } else { ip = net.IPv4zero }
    default:
        return 0, nil, fmt.Errorf("socks udp: unsupported ATYP 0x%02x", atyp)
    }

    if off+2 > n { return 0, nil, io.ErrUnexpectedEOF }
    port := int(binary.BigEndian.Uint16(buf[off : off+2]))
    off += 2

    data := buf[off:n]
    if len(data) > len(b) {
        copy(b, data[:len(b)])
        return len(b), &net.UDPAddr{IP: ip, Port: port}, io.ErrShortBuffer
    }
    copy(b, data)
    return len(data), &net.UDPAddr{IP: ip, Port: port}, nil
}

func (c *socksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
    // 将真实目标地址编码进 SOCKS5 UDP 头，发往中继
    var ip net.IP
    var port int

    switch a := addr.(type) {
    case *net.UDPAddr:
        ip, port = a.IP, a.Port
    case *net.TCPAddr:
        ip, port = a.IP, a.Port
    default:
        // 尝试从字符串解析
        h, p, e := net.SplitHostPort(addr.String())
        if e != nil { return 0, e }
        port64, e := parsePort(p)
        if e != nil { return 0, e }
        ip = net.ParseIP(strings.Trim(h, "[]"))
        if ip == nil { ips, _ := net.LookupIP(h); if len(ips) > 0 { ip = ips[0] } }
        port = int(port64)
    }

    var hdr bytes.Buffer
    hdr.Write([]byte{0x00, 0x00, 0x00})
    if ip4 := ip.To4(); ip4 != nil {
        hdr.WriteByte(0x01)
        hdr.Write(ip4)
    } else {
        // 为空或非 v4 时按 v6 处理。
        if ip == nil { ip = net.IPv6zero }
        hdr.WriteByte(0x04)
        hdr.Write(ip.To16())
    }
    var portBuf [2]byte
    binary.BigEndian.PutUint16(portBuf[:], uint16(port))
    hdr.Write(portBuf[:])

    pkt := make([]byte, 0, hdr.Len()+len(b))
    pkt = append(pkt, hdr.Bytes()...)
    pkt = append(pkt, b...)

    _, err = c.udp.Write(pkt)
    if err != nil { return 0, err }
    return len(b), nil
}

func (c *socksPacketConn) Close() error {
    _ = c.udp.Close()
    return c.tcp.Close()
}

func (c *socksPacketConn) LocalAddr() net.Addr { return c.udp.LocalAddr() }

func (c *socksPacketConn) SetDeadline(t time.Time) error {
    c.readDeadline, c.writeDeadline = t, t
    if err := c.udp.SetDeadline(t); err != nil { return err }
    return c.tcp.SetDeadline(t)
}

func (c *socksPacketConn) SetReadDeadline(t time.Time) error {
    c.readDeadline = t
    if err := c.udp.SetReadDeadline(t); err != nil { return err }
    return c.tcp.SetReadDeadline(t)
}

func (c *socksPacketConn) SetWriteDeadline(t time.Time) error {
    c.writeDeadline = t
    if err := c.udp.SetWriteDeadline(t); err != nil { return err }
    return c.tcp.SetWriteDeadline(t)
}

