#!/bin/bash
# Nextest Runner Script for InferaDB Management API
# Runs tests using cargo-nextest for faster, more reliable test execution
#
# Usage:
#   ./scripts/test-nextest.sh              # Run all tests
#   ./scripts/test-nextest.sh ci           # CI mode
#   ./scripts/test-nextest.sh core         # Run core tests only
#   ./scripts/test-nextest.sh api          # Run API tests only

set -e

cd "$(dirname "$0")/.."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0;0m' # No Color

echo -e "${BLUE}=== InferaDB Management API Tests (nextest) ===${NC}"
echo ""

# Check if nextest is installed
if ! command -v cargo-nextest &> /dev/null; then
    echo -e "${YELLOW}cargo-nextest not found. Installing...${NC}"
    cargo install cargo-nextest --locked
    echo ""
fi

# Determine mode
MODE="${1:-all}"
EXTRA_ARGS="${@:2}"

case "$MODE" in
    ci)
        echo -e "${YELLOW}Running tests in CI mode...${NC}"
        cargo nextest run \
            --profile ci \
            --workspace \
            --all-targets \
            --no-fail-fast \
            $EXTRA_ARGS
        ;;

    core)
        echo -e "${YELLOW}Running core library tests...${NC}"
        cargo nextest run \
            -p infera-management-core \
            --lib \
            $EXTRA_ARGS
        ;;

    api)
        echo -e "${YELLOW}Running API tests...${NC}"
        cargo nextest run \
            -p infera-management-api \
            --lib \
            $EXTRA_ARGS
        ;;

    storage)
        echo -e "${YELLOW}Running storage tests...${NC}"
        cargo nextest run \
            -p infera-management-storage \
            --lib \
            $EXTRA_ARGS
        ;;

    integration)
        echo -e "${YELLOW}Running integration tests...${NC}"
        cargo nextest run \
            --workspace \
            --test '*' \
            $EXTRA_ARGS
        ;;

    all|*)
        echo -e "${YELLOW}Running all tests...${NC}"
        cargo nextest run \
            --workspace \
            --all-targets \
            $EXTRA_ARGS
        ;;
esac

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed${NC}"

    # Show JUnit report location if exists
    if [ -f "target/nextest/junit.xml" ]; then
        echo ""
        echo -e "${BLUE}JUnit Report: target/nextest/junit.xml${NC}"
    fi
else
    echo -e "${RED}✗ Tests failed${NC}"

    # Show how to run failed tests only
    echo ""
    echo -e "${YELLOW}To re-run only failed tests:${NC}"
    echo "  cargo nextest run --failed"
fi

exit $EXIT_CODE
