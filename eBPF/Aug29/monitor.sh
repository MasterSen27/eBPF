#!/bin/bash

echo "DNS Query Rate Monitor (using bpftool)"
echo "Press Ctrl+C to exit"

while true; do
    clear
    echo "=== DNS Query Statistics - $(date) ==="
    echo ""
    
    # Get map IDs with shorter names
    TOTAL_MAP_ID=$(sudo bpftool map list 2>/dev/null | grep total_q_min | awk '{print $1}' | cut -d: -f1)
    TYPE_MAP_ID=$(sudo bpftool map list 2>/dev/null | grep query_by_type | awk '{print $1}' | cut -d: -f1)
    RATE_MAP_ID=$(sudo bpftool map list 2>/dev/null | grep query_rate_min | awk '{print $1}' | cut -d: -f1)
    
    if [ -z "$TOTAL_MAP_ID" ] || [ -z "$TYPE_MAP_ID" ] || [ -z "$RATE_MAP_ID" ]; then
        echo "ERROR: BPF maps not found!"
        echo "Make sure './loader eno1' is running in another terminal."
        echo ""
        echo "Available maps:"
        sudo bpftool map list 2>/dev/null | head -10
        sleep 3
        continue
    fi
    
    echo "Map IDs found: Total=$TOTAL_MAP_ID, Type=$TYPE_MAP_ID, Rate=$RATE_MAP_ID"
    echo ""
    
    # Display total queries
    echo "=== Total Queries Per Minute ==="
    sudo bpftool map dump id $TOTAL_MAP_ID 2>/dev/null | grep -v "Found 0 elements" | grep -v "^$"
    
    echo ""
    echo "=== Queries By Type ==="
    sudo bpftool map dump id $TYPE_MAP_ID 2>/dev/null | grep -v "Found 0 elements" | grep -v "^$"
    
    echo ""
    echo "=== Query Rate (per domain) - First 5 entries ==="
    sudo bpftool map dump id $RATE_MAP_ID 2>/dev/null | grep -v "Found 0 elements" | grep -v "^$" | head -10
    
    echo ""
    echo "=== Refresh in 5 seconds ==="
    sleep 5
done
