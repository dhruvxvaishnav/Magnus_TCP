#!/bin/bash

echo "========================================"
echo "  Magnum-TCP  Live End-to-End Test"
echo "========================================"
echo ""

# ── TAP setup ─────────────────────────────────────────────────────────────────
echo "[SETUP] Creating tap0 (Layer 2 TAP device)..."
if ! ip tuntap add dev tap0 mode tap 2>&1; then
    echo ""
    echo "ERROR: Could not create tap0."
    echo "Run the container with:  --cap-add NET_ADMIN --device /dev/net/tun"
    exit 1
fi

ip link set tap0 up
ip addr add 192.168.100.1/24 dev tap0
echo "[SETUP] tap0 ready — host side is 192.168.100.1, stack side will be 192.168.100.2"
echo ""

# ── Launch stack ──────────────────────────────────────────────────────────────
echo "[START] magnum-tcp --bind-ip 192.168.100.2 --port 80"
cd /tmp
RUST_LOG=info magnum-tcp --bind-ip 192.168.100.2 --port 80 > /tmp/stack.log 2>&1 &
STACK_PID=$!

sleep 1

if ! kill -0 "$STACK_PID" 2>/dev/null; then
    echo "[FAIL]  Stack crashed at startup. Log:"
    cat /tmp/stack.log
    exit 1
fi
echo "[START] Stack is running (pid $STACK_PID)"
echo ""

# ── HTTP tests ────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

run_test() {
    local label="$1"
    local url="$2"
    echo "[TEST]  $label"
    local out
    if out=$(curl -s --max-time 5 "$url" 2>&1); then
        echo "[PASS]  Response: $out"
        PASS=$((PASS + 1))
    else
        echo "[FAIL]  curl exited $? — response: $out"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

run_test "GET http://192.168.100.2/" "http://192.168.100.2/"
run_test "Second connection (connection reuse test)" "http://192.168.100.2/"

# ── PCAP ─────────────────────────────────────────────────────────────────────
if [ -f /tmp/capture.pcap ]; then
    BYTES=$(wc -c < /tmp/capture.pcap)
    echo "[PCAP]  capture.pcap written ($BYTES bytes)"
    tcpdump -r /tmp/capture.pcap -n 2>/dev/null | head -20 || true
else
    echo "[PCAP]  capture.pcap not found"
fi
echo ""

# ── Stack log ─────────────────────────────────────────────────────────────────
echo "=== Stack Log (RUST_LOG=info) ==="
cat /tmp/stack.log

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"

kill "$STACK_PID" 2>/dev/null || true
wait "$STACK_PID" 2>/dev/null || true

[ "$FAIL" -eq 0 ]
