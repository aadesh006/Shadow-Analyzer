#!/bin/bash
# Test: Benign package analysis - lodash
# Expected: CLEAN verdict, no threats detected

set -e

SHADOW_BIN="../../build/shadow"
TEST_NAME="lodash_benign"
RESULTS_DIR="../results"

mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "TEST: Benign Package - lodash"
echo "=========================================="
echo "Package: lodash (pure utility library)"
echo "Expected: CLEAN verdict"
echo ""

# Run Shadow analysis
if $SHADOW_BIN analyze lodash > "$RESULTS_DIR/${TEST_NAME}.log" 2>&1; then
    # Check if output contains CLEAN verdict
    if grep -q "CLEAN" "$RESULTS_DIR/${TEST_NAME}.log"; then
        echo "✅ PASS: lodash returned CLEAN verdict"
        exit 0
    else
        echo "❌ FAIL: lodash did not return CLEAN verdict"
        echo "--- Output ---"
        cat "$RESULTS_DIR/${TEST_NAME}.log"
        exit 1
    fi
else
    exit_code=$?
    echo "❌ FAIL: Shadow analysis failed with exit code $exit_code"
    echo "--- Output ---"
    cat "$RESULTS_DIR/${TEST_NAME}.log"
    exit 1
fi
