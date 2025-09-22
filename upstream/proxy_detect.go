package upstream

import (
    "net"
    "os"
    "strconv"
    "strings"
)

// ProxyType 表示检测到的代理类型。
type ProxyType int

const (
    ProxyTypeNone ProxyType = iota
    ProxyTypeHTTP
    ProxyTypeSOCKS
)

// detectProxyTypeFor 根据目标主机（可含端口）与环境变量，返回代理类型与代理 URL。
// - 若 NO_PROXY/no_proxy 命中目标，则返回 ProxyTypeNone；
// - 否则优先读取 HTTP_PROXY/HTTPS_PROXY（含大小写），再读取 ALL_PROXY/all_proxy；
// - 对 ALL_PROXY 未带 scheme 的值按 SOCKS 处理。
func detectProxyTypeFor(targetHostPort string) (ProxyType, string) {
    host, port := splitHostPortBestEffort(targetHostPort)
    if matchesNOProxy(host, port) {
        return ProxyTypeNone, ""
    }

    // 显式 HTTP(S) 代理
    for _, env := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
        if v := os.Getenv(env); v != "" {
            if strings.HasPrefix(strings.ToLower(v), "socks") {
                return ProxyTypeSOCKS, v
            }
            return ProxyTypeHTTP, v
        }
    }

    // ALL_PROXY 兼容，同时兼容不带 scheme 的 SOCKS 常用写法
    for _, env := range []string{"ALL_PROXY", "all_proxy"} {
        if v := os.Getenv(env); v != "" {
            low := strings.ToLower(v)
            switch {
            case strings.HasPrefix(low, "socks"):
                return ProxyTypeSOCKS, v
            case strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://"):
                return ProxyTypeHTTP, v
            default:
                return ProxyTypeSOCKS, v
            }
        }
    }

    return ProxyTypeNone, ""
}

// detectProxyType 保留旧接口；不考虑 NO_PROXY 目标匹配，仅按是否设置代理返回。
func detectProxyType() (ProxyType, string) { return detectProxyTypeFor("") }

// matchesNOProxy 判断 NO_PROXY/no_proxy 是否命中目标主机。
// 支持：
// - 逗号分隔的 token；
// - 通配符 "*"；
// - 域名后缀（示例：example.com 命中 example.com 与 foo.example.com）；
// - 可选端口（token 含端口时需与目标端口一致）；
// - IP/CIDR（如 10.0.0.0/8）。
func matchesNOProxy(host string, port int) bool {
    if host == "" {
        return false
    }
    np := os.Getenv("NO_PROXY")
    if np == "" {
        np = os.Getenv("no_proxy")
    }
    if np == "" {
        return false
    }

    hLower := strings.ToLower(trimBrackets(host))
    for _, raw := range strings.Split(np, ",") {
        token := strings.TrimSpace(raw)
        if token == "" {
            continue
        }
        if token == "*" {
            return true
        }

        thost := token
        tport := -1

        // 先处理带括号的 IPv6（可选端口，如 [fd00::1]:853）
        if strings.HasPrefix(thost, "[") {
            rb := strings.Index(thost, "]")
            if rb > 0 {
                after := thost[rb+1:]
                if strings.HasPrefix(after, ":") {
                    if p, err := strconv.Atoi(after[1:]); err == nil { tport = p }
                }
                thost = thost[:rb+1]
            }
        } else if ip := net.ParseIP(thost); ip != nil {
            // 裸 IP（IPv4/IPv6）不解析端口
        } else {
            // 普通域名或可能的 host:port，尝试按最后一个冒号拆分端口
            if i := strings.LastIndex(thost, ":"); i > 0 && !strings.Contains(thost, "]") {
                if p, err := strconv.Atoi(thost[i+1:]); err == nil {
                    thost, tport = thost[:i], p
                }
            }
        }

        thost = strings.ToLower(trimBrackets(strings.TrimSpace(thost)))

        // 端口要求
        if tport >= 0 && port >= 0 && tport != port {
            continue
        }

        // CIDR
        if _, ipnet, err := net.ParseCIDR(thost); err == nil {
            if ip := net.ParseIP(hLower); ip != nil && ipnet.Contains(ip) {
                return true
            }
            continue
        }

        // IP 精确匹配
        if net.ParseIP(thost) != nil {
            if hLower == thost {
                return true
            }
            continue
        }

        // 域名后缀匹配：example.com 命中 example.com 与 *.example.com
        if hLower == thost || strings.HasSuffix(hLower, "."+thost) {
            return true
        }
    }

    return false
}

func splitHostPortBestEffort(hostport string) (host string, port int) {
    host = strings.TrimSpace(hostport)
    port = -1
    if host == "" {
        return
    }
    // 尝试标准解析
    if h, p, err := net.SplitHostPort(host); err == nil {
        host = h
        if v, err2 := strconv.Atoi(p); err2 == nil { port = v }
        return
    }
    // 可能是纯主机名或 IP（含 [] 的 IPv6）
    host = trimBrackets(host)
    return
}

func trimBrackets(h string) string {
    if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
        return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
    }
    return h
}
