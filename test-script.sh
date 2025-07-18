#!/bin/bash

# Recon-Enum NSE Script Test Suite
# This script tests the recon-enum.nse script functionality

echo "========================================"
echo "Recon-Enum NSE Script Test Suite"
echo "========================================"
echo "Date: $(date)"
echo "Testing recon-enum.nse script..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"
    
    echo -e "${YELLOW}Test: $test_name${NC}"
    echo "Command: $command"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    # Run the command and capture output
    output=$(eval "$command" 2>&1)
    exit_code=$?
    
    # Check if the command executed successfully
    if [ $exit_code -eq 0 ]; then
        # Check if expected pattern is found in output
        if echo "$output" | grep -q "$expected_pattern"; then
            echo -e "${GREEN}✓ PASSED${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}✗ FAILED - Expected pattern not found${NC}"
            echo "Expected: $expected_pattern"
            echo "Output excerpt:"
            echo "$output" | head -10
        fi
    else
        echo -e "${RED}✗ FAILED - Command failed with exit code $exit_code${NC}"
        echo "Error output:"
        echo "$output" | head -10
    fi
    
    echo ""
}

# Check if recon-enum.nse exists
echo "Checking if recon-enum.nse script exists..."
if [ ! -f "recon-enum.nse" ]; then
    echo -e "${RED}Error: recon-enum.nse not found in current directory${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Script file found${NC}"
echo ""

# Check if nmap is available
echo "Checking if nmap is available..."
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}Error: nmap is not installed or not in PATH${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Nmap is available${NC}"
echo ""

# Test 1: Script syntax validation
run_test "Script Syntax Validation" \
         "nmap --script-help recon-enum.nse" \
         "recon-enum"

# Test 2: Script loading test
run_test "Script Loading Test" \
         "nmap --script-help recon-enum" \
         "Advanced Network Reconnaissance"

# Test 3: Test against localhost (if available)
if command -v nc &> /dev/null; then
    echo "Starting test HTTP server on port 8080..."
    # Start a simple HTTP server for testing
    (echo -e "HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\n\r\nTest Page" | nc -l -p 8080) &
    server_pid=$!
    sleep 2
    
    run_test "Localhost HTTP Test" \
             "timeout 10 nmap -p 8080 --script recon-enum localhost" \
             "recon-enum"
    
    # Clean up test server
    kill $server_pid 2>/dev/null
    wait $server_pid 2>/dev/null
fi

# Test 4: Script description test
run_test "Script Description Test" \
         "nmap --script-help recon-enum" \
         "banner grabbing"

# Test 5: Service enumeration test (syntax check)
run_test "Service Enumeration Syntax" \
         "nmap --script-help recon-enum" \
         "enumeration"

# Test 6: Security testing purpose test (syntax check)
run_test "Security Testing Purpose" \
         "nmap --script-help recon-enum" \
         "security testing"

# Test 7: SSL/TLS certificate test
run_test "SSL/TLS Certificate Test" \
         "nmap --script-help recon-enum" \
         "SSL/TLS certificate"

# Test 8: HTTP analysis test
run_test "HTTP Analysis Test" \
         "nmap --script-help recon-enum" \
         "HTTP header analysis"

# Test 9: Category validation
run_test "Script Categories" \
         "nmap --script-help recon-enum" \
         "discovery"

# Test 10: Author and license check
run_test "Script Metadata" \
         "nmap --script-help recon-enum" \
         "author"

echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Tests Run: $TESTS_RUN"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $((TESTS_RUN - TESTS_PASSED))"

if [ $TESTS_PASSED -eq $TESTS_RUN ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
