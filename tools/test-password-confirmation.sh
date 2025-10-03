#!/bin/bash
# Test script for password confirmation feature

echo "=== Test 1: Password confirmation with matching passwords ==="
echo "This will create a database with password 'test123' confirmed correctly"
echo ""
echo -e "test123\ntest123" | ./bin/secrets init -f --ignore-git-repository 2>&1 | grep -E "(password|Password|created|Database)"
echo ""

echo "=== Cleaning up test 1 ==="
rm -rf .secrets_yohnah
echo ""

echo "=== Test 2: Password confirmation with mismatching passwords ==="
echo "This should FAIL with 'passwords do not match' error"
echo ""
echo -e "test123\nwrong456" | ./bin/secrets init -f --ignore-git-repository 2>&1 | grep -E "(password|match|error|failed)"
echo ""

echo "=== Cleaning up test 2 ==="
rm -rf .secrets_yohnah
echo ""

echo "=== Test 3: Using environment variable (should skip confirmation) ==="
echo "This should succeed without asking for confirmation"
echo ""
SECRETS_YOHNAH_PASSWORD=test123 ./bin/secrets init -f --ignore-git-repository 2>&1 | grep -E "(Database|created|password)"
echo ""

echo "=== Cleaning up test 3 ==="
rm -rf .secrets_yohnah
echo ""

echo "=== Test 4: Existing database (should only ask once) ==="
echo "First create the database with confirmation"
echo -e "test123\ntest123" | ./bin/secrets init -f --ignore-git-repository > /dev/null 2>&1

echo "Now opening existing database should only ask for password once"
echo "test123" | ./bin/secrets init -f --ignore-git-repository 2>&1 | grep -E "(already exists|Password)"
echo ""

echo "=== Cleaning up test 4 ==="
rm -rf .secrets_yohnah
echo ""

echo "=== All tests completed ==="
