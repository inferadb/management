#!/bin/bash
# Quick test script for FDB integration tests
# Usage: ./test.sh

set -e

cd "$(dirname "$0")"

echo "=== Running FDB Integration Tests ==="
echo ""

# Build and run tests
docker-compose up --build --abort-on-container-exit --exit-code-from test-runner

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✓ Tests passed!"
else
    echo "✗ Tests failed with exit code $EXIT_CODE"
    echo ""
    echo "To view logs:"
    echo "  docker-compose logs foundationdb"
    echo "  docker-compose logs test-runner"
fi

# Cleanup
docker-compose down

exit $EXIT_CODE
