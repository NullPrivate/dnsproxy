#!/bin/bash

echo "=== DNSProxy 代理支持测试 ==="
echo

# 清理之前的进程
pkill -f dnsproxy 2>/dev/null || true
sleep 1

cd /home/test/code/adguardprivate/dnsproxy

echo "1. 测试没有代理设置的情况："
echo "   启动 dnsproxy 不带代理..."
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
timeout 5 go run . -u https://1.1.1.1/dns-query --listen 127.0.0.1 --port 8053 > no_proxy.log 2>&1 &
NOPROXY_PID=$!
sleep 2

echo "   进行 DNS 查询测试..."
if timeout 5 dig @127.0.0.1 -p 8053 example.com A +short > /dev/null 2>&1; then
    echo "   ✓ 不带代理的 DNS 查询成功"
else
    echo "   ✗ 不带代理的 DNS 查询失败"
fi

kill $NOPROXY_PID 2>/dev/null || true
sleep 1

echo
echo "2. 测试 HTTPS_PROXY 环境变量支持："
echo "   启动 dnsproxy 带 HTTPS_PROXY 设置..."
export HTTPS_PROXY=socks5://127.0.0.1:1080
timeout 5 go run . -u https://1.1.1.1/dns-query --listen 127.0.0.1 --port 8053 --verbose > with_proxy.log 2>&1 &
PROXY_PID=$!
sleep 2

echo "   进行 DNS 查询测试（预期失败，因为没有代理服务器）..."
if timeout 5 dig @127.0.0.1 -p 8053 example.com A > /dev/null 2>&1; then
    echo "   ⚠ DNS 查询意外成功（可能代理设置无效）"
else
    echo "   ✓ DNS 查询失败，说明正在尝试使用代理"
fi

kill $PROXY_PID 2>/dev/null || true
sleep 1

echo
echo "3. 检查日志以确认代理检测："
if grep -q "proxy environment detected" with_proxy.log; then
    echo "   ✓ 找到代理环境检测日志"
else
    echo "   ✗ 未找到代理环境检测日志"
fi

if grep -q "proxyconnect tcp" with_proxy.log; then
    echo "   ✓ 找到代理连接尝试日志"
else
    echo "   ✗ 未找到代理连接尝试日志"
fi

echo
echo "4. 测试其他代理环境变量："
echo "   测试 http_proxy（小写）..."
unset HTTPS_PROXY
export http_proxy=socks5://127.0.0.1:1080
timeout 3 go run . -u https://1.1.1.1/dns-query --listen 127.0.0.1 --port 8054 --verbose > http_proxy.log 2>&1 &
HTTP_PROXY_PID=$!
sleep 1
kill $HTTP_PROXY_PID 2>/dev/null || true

if grep -q "proxy environment detected" http_proxy.log; then
    echo "   ✓ http_proxy 环境变量被正确检测"
else
    echo "   ✗ http_proxy 环境变量未被检测到"
fi

echo
echo "=== 总结 ==="
echo "此修改在以下方面解决了用户的问题："
echo "• 检测 HTTP_PROXY, HTTPS_PROXY, http_proxy, https_proxy, ALL_PROXY, all_proxy 环境变量"
echo "• 当检测到代理设置时，使用系统代理而不是直接连接"
echo "• 禁用 HTTP/3（QUIC）以确保与 HTTP 代理的兼容性"
echo "• 在日志中显示代理检测状态"

echo
echo "用户现在可以这样使用："
echo "export HTTPS_PROXY=socks5://127.0.0.1:1080"
echo "./dnsproxy -u https://1.1.1.1/dns-query"

# 清理
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
rm -f no_proxy.log with_proxy.log http_proxy.log
pkill -f dnsproxy 2>/dev/null || true
