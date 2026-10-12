#!/bin/sh
# End-to-end TUN check inside a Linux container as root (just test-linux-tun):
# a local shadowsocks server, the real daemon in TUN mode, then traffic,
# IPv6 handling, DNS hijack, live mode switches and cleanup.
# Mounts: /b = linux binaries (berylliumd, beryl), /c = cores.
set -eu
fail() { echo "FAIL: $*"; tail -20 /tmp/d.log; exit 1; }

cat >/tmp/ss.json <<'JSON'
{"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":8388,"method":"aes-128-gcm","password":"pw"}],"outbounds":[{"type":"direct"}]}
JSON
/c/sing-box run -c /tmp/ss.json >/tmp/ss.log 2>&1 &
/b/berylliumd -config-dir /tmp/st -log-dir /tmp/st/logs -socket /tmp/d.sock -cores-dir /c >/tmp/d.log 2>&1 &
sleep 1
export BERYLLIUM_SOCKET=/tmp/d.sock
B=/b/beryl

$B import 'ss://YWVzLTEyOC1nY206cHc@127.0.0.1:8388#Local SS' >/dev/null
$B connect local --mode tun | grep -q "mode:     tun" || fail "connect --mode tun"
ip link | grep -q tun0 || fail "no tun0"
[ "$(curl -4 -sS -m 8 -o /dev/null -w '%{http_code}' https://1.1.1.1/)" = 301 ] || fail "IPv4 through the tunnel"
# IPv6 is blocked by default and must be refused before the handshake,
# not reset after it (browsers would show "connection reset").
out=$(curl -6 -sS -m 5 -o /dev/null https://[2606:4700:4700::1111]/ 2>&1 || true)
echo "$out" | grep -q "Could not connect" || fail "IPv6 not refused: $out"
getent hosts example.com >/dev/null || fail "DNS through the tunnel"
ok=""
for _ in 1 2 3 4 5; do
	if $B status | grep -q "traffic"; then ok=1; break; fi
	sleep 1
done
[ -n "$ok" ] || { $B status; fail "no traffic counters"; }

$B mode local >/dev/null
$B status | grep -q "mode:     local" || fail "switch to local"
! ip link | grep -q tun0 || fail "tun0 left after switching to local"
$B mode tun >/dev/null
$B status | grep -q "mode:     tun" || fail "switch back to tun"

$B disconnect >/dev/null
sleep 1
! ip link | grep -q tun0 || fail "tun0 left after disconnect"
! ip rule | grep -q 2022 || fail "routing rules left after disconnect"
echo "TUN e2e: ok"
