#!/bin/sh
set -e

TOR_LOG="/var/log/tor.log"
I2P_LOG="/var/log/i2pd.log"

_term() {
    echo "[entrypoint] Caught SIGTERM/SIGINT. Shutting down gracefully..."
    
    if [ -n "$GAUNTER_PID" ]; then
        echo "[entrypoint] Stopping Gaunter (PID: $GAUNTER_PID)..."
        kill -INT "$GAUNTER_PID" 2>/dev/null || true
    fi

    if [ -n "$TOR_PID" ]; then
        echo "[entrypoint] Stopping Tor (PID: $TOR_PID)..."
        kill -TERM "$TOR_PID" 2>/dev/null || true
    fi

    if [ -n "$I2P_PID" ]; then
        echo "[entrypoint] Stopping i2pd (PID: $I2P_PID)..."
        kill -TERM "$I2P_PID" 2>/dev/null || true
    fi

    echo "[entrypoint] Waiting for processes to exit..."
    wait $GAUNTER_PID $TOR_PID $I2P_PID 2>/dev/null || true
    echo "[entrypoint] Shutdown complete."
    exit 0
}

trap _term SIGTERM SIGINT

touch $TOR_LOG
chown tor:root $TOR_LOG

echo "[entrypoint] Setting up permissions..."
if [ -d "/var/lib/tor" ]; then
    echo "[entrypoint] Securing Tor permissions..."
    chown -R tor:root /var/lib/tor
    chmod 700 /var/lib/tor
    if [ -d "/var/lib/tor/hidden_service" ]; then
        echo "[entrypoint] Fixing hidden_service permissions..."
        chown -R tor:root /var/lib/tor/hidden_service
        chmod 700 /var/lib/tor/hidden_service
    fi
fi

echo "[entrypoint] Starting Tor..."
su-exec tor sh -c "tor -f /etc/tor/torrc > $TOR_LOG 2>&1" &
TOR_PID=$!

tail -f $TOR_LOG &
TAIL_PID=$!

echo "[entrypoint] Waiting for Tor to bootstrap..."
timeout=180
count=0
bootstrapped=0

while [ $count -lt $timeout ]; do
    if grep -q "Bootstrapped 100%" $TOR_LOG; then
        echo "[entrypoint] Tor bootstrapped successfully!"
        bootstrapped=1
        break
    fi
    sleep 1
    count=$((count+1))
done

if [ $bootstrapped -eq 0 ]; then
    echo "[entrypoint] WARNING: Tor bootstrap timeout! Check logs."
fi

kill "$TAIL_PID" 2>/dev/null || true
wait "$TAIL_PID" 2>/dev/null || true

I2P_PID=""
if [ "$I2P_ENABLED" = "true" ]; then
    echo "[entrypoint] Setting up i2pd..."
    
    if [ -d "/var/lib/i2pd" ]; then
        echo "[entrypoint] Securing i2pd permissions..."
        chown -R i2pd:i2pd /var/lib/i2pd
        chmod 700 /var/lib/i2pd
        find /var/lib/i2pd -name "*.dat" -exec chmod 600 {} \;
        find /var/lib/i2pd -name "*.keys" -exec chmod 600 {} \;
    fi
    if [ ! -d "/var/lib/i2pd/certificates" ] && [ -d "/usr/share/i2pd/certificates" ]; then
        echo "[entrypoint] Missing certificates detected via volume mount. Restoring defaults..."
        mkdir -p /var/lib/i2pd/certificates
        cp -r /usr/share/i2pd/certificates/* /var/lib/i2pd/certificates/
        chown -R i2pd:i2pd /var/lib/i2pd/certificates
        echo "[entrypoint] Certificates restored."
    fi
    

    truncate -s 0 $I2P_LOG
    chown i2pd:i2pd $I2P_LOG
    
    echo "[entrypoint] Starting i2pd..."
    su-exec i2pd sh -c "i2pd --conf=/etc/i2pd/i2pd.conf --tunconf=/etc/i2pd/tunnels.conf --datadir=/var/lib/i2pd > $I2P_LOG 2>&1" &
    I2P_PID=$!
    
    tail -f $I2P_LOG | awk '!/NetDb|SSU2|NTCP2|Profiling/ { print $0; fflush() }' &
    I2P_TAIL_PID=$!

    echo "[entrypoint] Waiting for i2pd to start..."
    while ! grep -q "i2pd v.* starting" $I2P_LOG; do
        sleep 0.5
    done

    echo "[entrypoint] Waiting for i2pd initialization..."
    i2p_timeout=180
    i2p_count=0
    i2p_ready=0

    while [ $i2p_count -lt $i2p_timeout ]; do
        if grep -q "I2P server tunnels created" $I2P_LOG && \
           grep -qE "Tunnel: .* tunnel .* has been created" $I2P_LOG; then
            i2p_ready=1
            break
        fi
        sleep 1
        i2p_count=$((i2p_count+1))
    done

    sleep 1
    kill "$I2P_TAIL_PID" 2>/dev/null || true
    wait "$I2P_TAIL_PID" 2>/dev/null || true

    if [ $i2p_ready -eq 1 ]; then
        echo "[entrypoint] i2pd initialization complete!"
    else
        echo "[entrypoint] WARNING: i2pd initialization timeout! Check logs."
    fi
fi

echo "[entrypoint] Starting Gaunter..."
su-exec gaunter /app/gaunter &
GAUNTER_PID=$!

wait_pids="$GAUNTER_PID $TOR_PID"
[ -n "$I2P_PID" ] && wait_pids="$wait_pids $I2P_PID"
while true; do
    for pid in $wait_pids; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[entrypoint] Process $pid exited. Shutting down..."
            _term
        fi
    done
    sleep 2
done
