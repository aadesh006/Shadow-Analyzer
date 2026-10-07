#!/bin/bash
# Test: Benign package analysis - chalk
# Expected: CLEAN verdict, minimal network activity

set -e

SHADOW_BIN="../../build/shadow"
TEST_NAME="chalk_benign"
RESULTS_DIR="../results"

mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "TEST: Benign Package - chalk"
echo "=========================================="
echo "Package: chalk (terminal color library)"
echo "Expected: CLEAN verdict with CDN traffic only"
echo ""

if $SHADOW_BIN analyze chalk > "$RESULTS_DIR/${TEST_NAME}.log" 2>&1; then
    if grep -q "CLEAN" "$RESULTS_DIR/${TEST_NAME}.log"; then
        echo "✅ PASS: chalk returned CLEAN verdict"
        
        # Verify no suspicious process spawns
        if grep -q "\[ALERT\]" "$RESULTS_DIR/${TEST_NAME}.log"; then
            echo "⚠️  WARNING: Suspicious process detected (unexpected)"
            echo "--- Suspicious Activity ---"
            grep "\[ALERT\]" "$RESULTS_DIR/${TEST_NAME}.log"
        fi
        
        exit 0
    else
        echo "❌ FAIL: chalk did not return CLEAN verdict"
        echo "--- Output ---"
        cat "$RESULTS_DIR/${TEST_NAME}.log"
        exit 1
    fi
else
    echo "❌ FAIL: Shadow analysis failed"
    cat "$RESULTS_DIR/${TEST_NAME}.log"
    exit 1
fi
