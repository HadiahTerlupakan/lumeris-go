#!/bin/bash

echo "=== MONITORING SERVER LOG (LIVE) ==="
echo "Waiting for login attempts..."
echo ""

LAST_LINE=$(wc -l < server.log 2>/dev/null || echo 0)

while true; do
    sleep 1
    CURRENT_LINE=$(wc -l < server.log 2>/dev/null || echo 0)
    
    if [ "$CURRENT_LINE" -gt "$LAST_LINE" ]; then
        # Ada log baru
        NEW_LINES=$((CURRENT_LINE - LAST_LINE))
        tail -n $NEW_LINES server.log
        LAST_LINE=$CURRENT_LINE
        
        # Check for success/failure
        if tail -n $NEW_LINES server.log | grep -q "Login berhasil"; then
            echo ""
            echo "✅ ============================================"
            echo "✅ LOGIN SUCCESS DETECTED!"
            echo "✅ ============================================"
            break
        fi
        
        if tail -n $NEW_LINES server.log | grep -q "Login gagal"; then
            echo ""
            echo "❌ ============================================"
            echo "❌ LOGIN FAILED - Analyzing..."
            echo "❌ ============================================"
            # Continue monitoring untuk attempt berikutnya
        fi
    fi
done

echo ""
echo "Monitoring stopped. Type 'coba kamu chek' untuk full analysis."
