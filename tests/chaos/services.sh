#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "BLOCKED: service chaos tests require root"; exit 77; fi
for tool in systemctl curl python3 runuser; do command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool"; exit 77; }; done

wait_active() {
    local unit=$1
    for _ in $(seq 1 100); do systemctl is-active --quiet "$unit" && return 0; sleep 0.1; done
    return 1
}
wait_inactive() {
    local unit=$1
    for _ in $(seq 1 100); do ! systemctl is-active --quiet "$unit" && return 0; sleep 0.1; done
    return 1
}
wait_http() {
    for _ in $(seq 1 100); do [[ $(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/ 2>/dev/null) == 200 ]] && return 0; sleep 0.1; done
    return 1
}
wait_sockets() {
    for _ in $(seq 1 100); do [[ -S /run/nftfw/status.sock && -S /run/nftfw/control.sock ]] && return 0; sleep 0.1; done
    return 1
}

systemctl reset-failed nftfwd.service nftfw-web.service
systemctl start nftfwd.service nftfw-web.service nftfw-rollback.timer
wait_active nftfwd.service && wait_active nftfw-web.service && wait_http

daemon_pid=$(systemctl show -p MainPID --value nftfwd.service)
kill -TERM "$daemon_pid"
wait_inactive nftfwd.service || { echo "FAIL: nftfwd did not terminate cleanly"; exit 1; }
systemctl start nftfwd.service
wait_active nftfwd.service || { echo "FAIL: nftfwd did not start after SIGTERM"; exit 1; }
wait_sockets || { echo "FAIL: nftfwd sockets were not reconstructed"; exit 1; }
echo "NFTFWD SIGTERM/EXPLICIT RECOVERY: PASS"

daemon_pid=$(systemctl show -p MainPID --value nftfwd.service)
kill -KILL "$daemon_pid"
for _ in $(seq 1 100); do
    replacement=$(systemctl show -p MainPID --value nftfwd.service)
    [[ "$replacement" =~ ^[0-9]+$ && "$replacement" -gt 1 && "$replacement" != "$daemon_pid" ]] && systemctl is-active --quiet nftfwd.service && break
    sleep 0.1
done
[[ "$replacement" != "$daemon_pid" ]] || { echo "FAIL: nftfwd did not auto-restart after SIGKILL"; exit 1; }
echo "NFTFWD SIGKILL AUTO-RECOVERY: PASS"

web_pid=$(systemctl show -p MainPID --value nftfw-web.service)
kill -TERM "$web_pid"
wait_inactive nftfw-web.service || { echo "FAIL: dashboard did not terminate cleanly"; exit 1; }
systemctl start nftfw-web.service
if ! wait_active nftfw-web.service || ! wait_http; then echo "FAIL: dashboard did not start after SIGTERM"; exit 1; fi
echo "DASHBOARD SIGTERM/EXPLICIT RECOVERY: PASS"

web_pid=$(systemctl show -p MainPID --value nftfw-web.service)
kill -KILL "$web_pid"
for _ in $(seq 1 100); do
    replacement=$(systemctl show -p MainPID --value nftfw-web.service)
    [[ "$replacement" =~ ^[0-9]+$ && "$replacement" -gt 1 && "$replacement" != "$web_pid" ]] && systemctl is-active --quiet nftfw-web.service && break
    sleep 0.1
done
if [[ "$replacement" == "$web_pid" ]] || ! wait_http; then echo "FAIL: dashboard did not auto-restart after SIGKILL"; exit 1; fi
echo "DASHBOARD SIGKILL AUTO-RECOVERY: PASS"

for _ in $(seq 1 5); do
    systemctl restart nftfwd.service
    wait_active nftfwd.service
    wait_sockets
done
wait_http || { echo "FAIL: dashboard did not reconnect after repeated daemon restarts"; exit 1; }
echo "REPEATED SERVICE/SOCKET RECONSTRUCTION: PASS"

python3 - <<'PY'
import json
import socket

def request(path, payload):
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(path)
    client.sendall(payload)
    response = client.recv(65536)
    client.close()
    return json.loads(response)

unknown = request('/run/nftfw/status.sock', b'{"op":"status","unknown":true}\n')
if unknown.get('ok') or 'invalid request' not in unknown.get('error', ''):
    raise SystemExit('strict JSON request was accepted')
oversize = request('/run/nftfw/status.sock', b'{' + (b' ' * 70000) + b'}\n')
if oversize.get('ok') or 'size' not in oversize.get('error', ''):
    raise SystemExit('oversized request was accepted')
PY
echo "MALFORMED/OVERSIZED SOCKET REQUESTS: PASS"

runuser -u nftfw-web -- /usr/sbin/nftfw status --json >/dev/null
if runuser -u nftfw-web -- python3 - <<'PY' >/dev/null 2>&1
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/nftfw/control.sock')
PY
then
    echo "FAIL: dashboard user connected to the control socket"
    exit 1
fi
echo "STATUS GROUP READ/CONTROL DENIAL: PASS"

systemctl is-active --quiet nftfwd.service nftfw-web.service nftfw-rollback.timer
echo "SERVICE CHAOS ACCEPTANCE: PASS"
