#!/bin/bash
# Code Coverage Script for InferaDB Management API
# Generates code coverage reports using tarpaulin
#
# Usage:
#   ./scripts/coverage.sh           # HTML report
#   ./scripts/coverage.sh ci        # CI mode (lcov)
#   ./scripts/coverage.sh clean     # Clean coverage data

set -e

cd "$(dirname "$0")/.."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0;0m' # No Color

echo -e "${BLUE}=== InferaDB Management API Code Coverage ===${NC}"
echo ""

# Check if tarpaulin is installed
if ! command -v cargo-tarpaulin &> /dev/null; then
    echo -e "${YELLOW}cargo-tarpaulin not found. Installing...${NC}"
    cargo install cargo-tarpaulin
    echo ""
fi

# Determine mode
MODE="${1:-html}"

case "$MODE" in
    clean)
        echo -e "${YELLOW}Cleaning coverage data...${NC}"
        rm -rf target/coverage
        rm -f cobertura.xml
        rm -f tarpaulin-report.html
        echo -e "${GREEN}✓ Coverage data cleaned${NC}"
        exit 0
        ;;

    ci)
        echo -e "${YELLOW}Running coverage in CI mode...${NC}"
        cargo tarpaulin \
            --config ci \
            --workspace \
            --exclude-files 'crates/*/tests/*' \
            --timeout 600 \
            --out Lcov \
            --output-dir target/coverage
        ;;

    json)
        echo -e "${YELLOW}Running coverage with JSON output...${NC}"
        cargo tarpaulin \
            --config json \
            --workspace \
            --exclude-files 'crates/*/tests/*' \
            --timeout 300
        ;;

    html|*)
        echo -e "${YELLOW}Running coverage with HTML output...${NC}"
        cargo tarpaulin \
            --workspace \
            --exclude-files 'crates/*/tests/*' \
            --timeout 300 \
            --out Html \
            --output-dir target/coverage
        ;;
esac

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage generation complete${NC}"

    # Show coverage summary if available
    if [ -f "target/coverage/tarpaulin-report.html" ]; then
        echo ""
        echo -e "${BLUE}HTML Report: file://$(pwd)/target/coverage/tarpaulin-report.html${NC}"
    fi

    if [ -f "target/coverage/lcov.info" ]; then
        echo -e "${BLUE}LCOV Report: target/coverage/lcov.info${NC}"
    fi

    # Try to open HTML report if in interactive mode
    if [ "$MODE" = "html" ] && [ -f "target/coverage/tarpaulin-report.html" ]; then
        if command -v open &> /dev/null; then
            echo ""
            echo -e "${YELLOW}Opening HTML report...${NC}"
            open "target/coverage/tarpaulin-report.html"
        elif command -v xdg-open &> /dev/null; then
            echo ""
            echo -e "${YELLOW}Opening HTML report...${NC}"
            xdg-open "target/coverage/tarpaulin-report.html"
        fi
    fi
else
    echo -e "${RED}✗ Coverage generation failed${NC}"
fi

exit $EXIT_CODE
