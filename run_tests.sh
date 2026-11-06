#!/bin/bash
# Test runner script for WebRecon scanner utilities

set -e

echo "WebRecon Scanner - Test Suite"
echo "=============================="
echo ""

# Check if pytest is available
if ! command -v pytest &> /dev/null; then
    echo "pytest not found. Installing test dependencies..."
    python3 -m pip install -q pytest pytest-mock pytest-cov pytest-timeout
fi

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Parse command line arguments
RUN_COVERAGE=false
VERBOSE="-v"
TEST_PATH="tests/"

while [[ $# -gt 0 ]]; do
    case $1 in
        --coverage)
            RUN_COVERAGE=true
            shift
            ;;
        --quiet)
            VERBOSE=""
            shift
            ;;
        --module)
            TEST_PATH="tests/test_utils/$2"
            shift 2
            ;;
        --help)
            echo "Usage: ./run_tests.sh [options]"
            echo ""
            echo "Options:"
            echo "  --coverage      Generate coverage report"
            echo "  --quiet         Reduce output verbosity"
            echo "  --module <name> Test specific module (e.g., test_helpers)"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            TEST_PATH="$1"
            shift
            ;;
    esac
done

# Run tests
echo -e "${YELLOW}Running tests from: $TEST_PATH${NC}"
echo ""

if [ "$RUN_COVERAGE" = true ]; then
    echo -e "${YELLOW}Running with coverage report...${NC}"
    pytest "$TEST_PATH" $VERBOSE \
        --cov=web_app/utils \
        --cov-report=html \
        --cov-report=term-missing \
        --tb=short
    echo ""
    echo -e "${GREEN}Coverage report generated in htmlcov/index.html${NC}"
else
    pytest "$TEST_PATH" $VERBOSE --tb=short
fi

# Check exit status
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo ""
    echo -e "${RED}✗ Tests failed!${NC}"
    exit 1
fi
