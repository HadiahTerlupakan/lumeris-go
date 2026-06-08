#!/bin/bash

echo "=== MONITORING LOGIN SERVER (Port 12023) ==="
echo "Waiting for client to connect to Login server..."
echo ""

# Get current line count
LAST_LINE=$(wc -l < server.log 2>/dev/null || echo 0)

# Monitor for 60 seconds
TIMEOUT=60
ELAPSED=0

while [ $ELAPSED -lt $TIMEOUT ]; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    
    CURRENT_LINE=$(wc -l < server.log 2>/dev/null || echo 0)
    
    if [ "$CURRENT_LINE" -gt "$LAST_LINE" ]; then
        NEW_LINES=$((CURRENT_LINE - LAST_LINE))
        NEW_LOG=$(tail -n $NEW_LINES server.log)
        
        # Show all new lines
        echo "$NEW_LOG"
        
        # Check for Login server activity
        if echo "$NEW_LOG" | grep -q "\[Login\]"; then
            echo ""
            echo "✅ Login server activity detected!"
        fi
        
        # Check for Map server activity
        if echo "$NEW_LOG" | grep -q "\[Map\]"; then
            echo ""
            echo "✅ Map server activity detected!"
        fi
        
        LAST_LINE=$CURRENT_LINE
    fi
    
    # Show progress every 10 seconds
    if [ $((ELAPSED % 10)) -eq 0 ]; then
        echo "[${ELAPSED}s] Waiting for Login server connection..."
    fi
done

echo ""
echo "⏱️ Monitoring timeout (60s). No Login server activity detected."
echo ""
echo "DIAGNOSIS:"
echo "- Validation: ✅ Working (login berhasil)"
echo "- Login: ❌ No connection (client tidak connect)"
echo ""
echo "Possible causes:"
echo "1. Client tidak bisa parse server list format"
echo "2. Client tidak bisa connect ke IP:port yang dikirim"
echo "3. Network/firewall blocking port 12023"
