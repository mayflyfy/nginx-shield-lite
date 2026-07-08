#!/bin/sh
cd "$(dirname "$0")" || exit 1
mkdir -p var

if [ -f var/main.pid ]; then
    kill "$(cat var/main.pid)" 2>/dev/null || true
    rm -f var/main.pid
    sleep 1
fi

nohup python3 -u main.py >var/main.log 2>&1 &
PID=$!
echo "$PID" >var/main.pid
sleep 1

if kill -0 "$PID" 2>/dev/null; then
    echo "nginx-shield-lite started: PID $PID"
else
    echo "nginx-shield-lite failed to start:"
    tail -n 20 var/main.log
    rm -f var/main.pid
    exit 1
fi
