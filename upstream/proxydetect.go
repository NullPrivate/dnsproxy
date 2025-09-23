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

	if v := firstNonEmptyEnv("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"); v != "" {
		return classifyProxy(v), v
	}

	if v := firstNonEmptyEnv("ALL_PROXY", "all_proxy"); v != "" {
		return classifyProxy(v), v
	}

	return ProxyTypeNone, ""
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func classifyProxy(v string) ProxyType {
	low := strings.ToLower(v)
	switch {
	case strings.HasPrefix(low, "socks"):
		return ProxyTypeSOCKS
	case strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://"):
		return ProxyTypeHTTP
	default:
		// ALL_PROXY 常见写法为 host:port 表示 SOCKS。
		if strings.Contains(low, ":") && !strings.Contains(low, "/") {
			return ProxyTypeSOCKS
		}
		return ProxyTypeHTTP
	}
}

// （已弃用）保留旧接口，为向后兼容而存在。
// 当前项目未使用，移除可降低 lint 噪声。
// func detectProxyType() (ProxyType, string) { return detectProxyTypeFor("") }

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

	np := getenvNoProxy()
	if np == "" {
		return false
	}

	hLower := strings.ToLower(trimBrackets(host))
	for _, token := range splitNoProxy(np) {
		if token == "*" {
			return true
		}
		if matchNoProxyToken(hLower, port, token) {
			return true
		}
	}

	return false
}

// getenvNoProxy 返回 NO_PROXY/no_proxy 的值。
func getenvNoProxy() string {
	if v := os.Getenv("NO_PROXY"); v != "" {
		return v
	}
	return os.Getenv("no_proxy")
}

// splitNoProxy 将 NO_PROXY 字符串拆分为 token 列表，过滤空白项。
func splitNoProxy(v string) (out []string) {
	for _, raw := range strings.Split(v, ",") {
		if t := strings.TrimSpace(raw); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// matchNoProxyToken 判断单个 token 是否命中目标 host:port。
func matchNoProxyToken(hostLower string, port int, token string) bool {
	thost, tport := parseNoProxyTokenHostPort(token)

	// 端口要求
	if tport >= 0 && port >= 0 && tport != port {
		return false
	}

	// CIDR
	if _, ipnet, err := net.ParseCIDR(thost); err == nil {
		if ip := net.ParseIP(hostLower); ip != nil && ipnet.Contains(ip) {
			return true
		}
		return false
	}

	// IP 精确匹配
	if net.ParseIP(thost) != nil {
		return hostLower == thost
	}

	// 域名后缀匹配
	return hostLower == thost || strings.HasSuffix(hostLower, "."+thost)
}

// parseNoProxyTokenHostPort 解析 token 中的 host 与可选端口，返回标准化的小写 host 与端口（无端口为 -1）。
func parseNoProxyTokenHostPort(token string) (host string, port int) {
	s := strings.TrimSpace(token)
	host, port = s, -1

	if strings.HasPrefix(s, "[") {
		if h, p, ok := parseBracketHostPort(s); ok {
			host, port = h, p
		}
	} else if net.ParseIP(s) == nil {
		if h, p, ok := splitHostPortLastColon(s); ok {
			host, port = h, p
		}
	}

	host = strings.ToLower(trimBrackets(host))
	return host, port
}

// parseBracketHostPort 解析形如 "[ipv6]" 或 "[ipv6]:port"。
func parseBracketHostPort(s string) (host string, port int, ok bool) {
	rb := strings.IndexByte(s, ']')
	if rb <= 0 {
		return s, -1, false
	}
	port = -1
	after := s[rb+1:]
	if strings.HasPrefix(after, ":") {
		if p, err := strconv.Atoi(after[1:]); err == nil {
			port = p
		}
	}
	return s[:rb+1], port, true
}

// splitHostPortLastColon 使用最后一个冒号分隔 host:port，避免 IPv6 干扰。
func splitHostPortLastColon(s string) (host string, port int, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || strings.Contains(s, "]") {
		return s, -1, false
	}
	if p, err := strconv.Atoi(s[i+1:]); err == nil {
		return s[:i], p, true
	}
	return s, -1, false
}

func splitHostPortBestEffort(hostport string) (host string, port int) {
	host = strings.TrimSpace(hostport)
	port = -1
	if host == "" {
		return host, port
	}
	// 尝试标准解析
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		if v, err2 := strconv.Atoi(p); err2 == nil {
			port = v
		}
		return host, port
	}
	// 可能是纯主机名或 IP（含 [] 的 IPv6）
	host = trimBrackets(host)
	return host, port
}

func trimBrackets(h string) string {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	return h
}
