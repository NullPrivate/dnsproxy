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
    var methods []byte
    user := ""
    pass, _ := "", error(nil)
    if u.User != nil {
        user = u.User.Username()
        pass, _ = u.User.Password()
    }

    if user != "" || pass != "" {
        methods = []byte{0x02} // Username/Password
    } else {
        methods = []byte{0x00} // NoAuth
    }

    req := []byte{0x05, byte(len(methods))}
    req = append(req, methods...)
    if _, err := tcpConn.Write(req); err != nil {
        return fmt.Errorf("socks handshake write: %w", err)
    }

    resp := make([]byte, 2)
    if _, err := io.ReadFull(tcpConn, resp); err != nil {
        return fmt.Errorf("socks handshake read: %w", err)
    }
    if resp[0] != 0x05 {
        return fmt.Errorf("socks version mismatch: %d", resp[0])
    }

    switch resp[1] {
    case 0x00: // NoAuth
        return nil
    case 0x02: // Username/Password
        if user == "" && pass == "" {
            return fmt.Errorf("socks requested auth but no credentials provided")
        }
        // RFC1929: ver(1)=0x01, ulen(1), uname, plen(1), passwd
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
    case 0xFF:
        return fmt.Errorf("socks: no acceptable auth methods")
    default:
        return fmt.Errorf("socks: unsupported method 0x%02x", resp[1])
    }
}

// socks5UDPAssociate 发送 UDP ASSOCIATE 请求，返回服务器分配的中继地址与端口。
func socks5UDPAssociate(tcpConn net.Conn) (net.IP, uint16, error) {
    // 请求：VER=5, CMD=3(UDP ASSOCIATE), RSV=0, ATYP=1(IPv4), DST.ADDR=0.0.0.0, DST.PORT=0
    req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
    if _, err := tcpConn.Write(req); err != nil {
        return nil, 0, fmt.Errorf("socks udp associate write: %w", err)
    }

    // 响应：VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
    hdr := make([]byte, 4)
    if _, err := io.ReadFull(tcpConn, hdr); err != nil {
        return nil, 0, fmt.Errorf("socks udp associate read header: %w", err)
    }
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return nil, 0, fmt.Errorf("socks udp associate failed: rep=0x%02x", hdr[1])
    }
    atyp := hdr[3]

    var bndIP net.IP
    switch atyp {
    case 0x01: // IPv4
        addr := make([]byte, 4)
        if _, err := io.ReadFull(tcpConn, addr); err != nil {
            return nil, 0, fmt.Errorf("socks read bnd.addr v4: %w", err)
        }
        bndIP = net.IP(addr)
    case 0x03: // DOMAIN
        l := make([]byte, 1)
        if _, err := io.ReadFull(tcpConn, l); err != nil {
            return nil, 0, fmt.Errorf("socks read bnd.addr len: %w", err)
        }
        name := make([]byte, int(l[0]))
        if _, err := io.ReadFull(tcpConn, name); err != nil {
            return nil, 0, fmt.Errorf("socks read bnd.addr name: %w", err)
        }
        // 尝试解析域名为 IP（一般服务器会返回其自身地址，域名少见）
        ips, err := net.LookupIP(string(name))
        if err != nil || len(ips) == 0 {
            return nil, 0, fmt.Errorf("resolve bnd.addr %q: %w", string(name), err)
        }
        bndIP = ips[0]
    case 0x04: // IPv6
        addr := make([]byte, 16)
        if _, err := io.ReadFull(tcpConn, addr); err != nil {
            return nil, 0, fmt.Errorf("socks read bnd.addr v6: %w", err)
        }
        bndIP = net.IP(addr)
    default:
        return nil, 0, fmt.Errorf("socks: unsupported ATYP 0x%02x", atyp)
    }

    portBuf := make([]byte, 2)
    if _, err := io.ReadFull(tcpConn, portBuf); err != nil {
        return nil, 0, fmt.Errorf("socks read bnd.port: %w", err)
    }
    bndPort := binary.BigEndian.Uint16(portBuf)

    return bndIP, bndPort, nil
}

// socksUDPConn 封装 UDPConn 与保持映射用的 TCPConn。
type socksUDPConn struct {
    udp *net.UDPConn
    tcp net.Conn

    // 目标服务器（DNS 上游）的 host:port（可能是域名或 IP）
    targetHostPort string

    readDeadline  time.Time
    writeDeadline time.Time
}

func newSocksUDPConn(udp *net.UDPConn, tcp net.Conn, targetHostPort string) net.Conn {
    return &socksUDPConn{udp: udp, tcp: tcp, targetHostPort: targetHostPort}
}

func (c *socksUDPConn) Read(b []byte) (int, error) {
    // SOCKS5 UDP 响应：RSV(2)=0, FRAG(1)=0, ATYP, DST.ADDR, DST.PORT, DATA
    buf := make([]byte, 65535)
    n, _, err := c.udp.ReadFromUDP(buf)
    if err != nil {
        return 0, err
    }
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
    atyp := buf[off]
    off++
    switch atyp {
    case 0x01:
        off += 4
    case 0x04:
        off += 16
    case 0x03:
        if off >= n {
            return 0, io.ErrUnexpectedEOF
        }
        l := int(buf[off])
        off += 1 + l
    default:
        return 0, fmt.Errorf("socks udp: unsupported ATYP 0x%02x", atyp)
    }
    // 跳过端口
    off += 2
    if off > n {
        return 0, io.ErrUnexpectedEOF
    }
    data := buf[off:n]
    if len(data) > len(b) {
        copy(b, data[:len(b)])
        return len(b), io.ErrShortBuffer
    }
    copy(b, data)
    return len(data), nil
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

