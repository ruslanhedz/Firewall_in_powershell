#!/usr/bin/env bash
# =============================================================================
# test-fw-server.sh  -  Unit tests for the Linux backup server (fw-server.sh)
# =============================================================================
# Safe, isolated unit tests running in a temporary sandbox directory.
# Tests client configuration parsing, path traversal protection, restore
# verification, and backup retention (pruning) without external SSH/network.
#
# Run: bash tests/test-fw-server.sh
# =============================================================================
set -uo pipefail

PASSED=0
FAILED=0

assert() {
    local condition=$1
    local message=$2
    if eval "$condition"; then
        ((PASSED++))
        printf "  [ok]   %s\n" "$message"
    else
        ((FAILED++))
        printf "  [FAIL] %s\n" "$message"
    fi
}

section() {
    printf "\n== %s\n" "$1"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_SERVER_SRC="$SCRIPT_DIR/../fw-server.sh"

if [ ! -f "$FW_SERVER_SRC" ]; then
    echo "ERROR: fw-server.sh not found at $FW_SERVER_SRC" >&2
    exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Extract functions and variables from fw-server.sh without the bottom dispatcher
TMP_SRC="$TMP_DIR/fw-server-functions.sh"
sed -e '/^case "\${1:-}" in/,$d' "$FW_SERVER_SRC" | tr -d '\r' > "$TMP_SRC"

# shellcheck disable=SC1090
source "$TMP_SRC"

# Override storage locations to the temporary sandbox
CONF="$TMP_DIR/clients.conf"
BASE="$TMP_DIR/srv"
LOCKDIR="$TMP_DIR/locks"
LOG="$TMP_DIR/server.log"

# -----------------------------------------------------------------------------
section "Client configuration & setup_user validation"

cat << 'EOF' > "$CONF"
student 10.0.2.20 Student
john_doe 192.168.1.50 AdminUser
bad_ip 999.999.999.999 InvalidIpUser
bad_user 10.0.2.25 Invalid!User*Name
EOF

# Valid user setup
setup_user "student"
assert '[ "$?" -eq 0 ] && [ "$HOST" = "10.0.2.20" ] && [ "$WINUSER" = "Student" ]' "Valid client 'student' parsed correctly"
assert '[ -d "$STORE" ] && [ -d "$LOCKDIR" ]' "Client store and lock directory created"

setup_user "john_doe"
assert '[ "$?" -eq 0 ] && [ "$HOST" = "192.168.1.50" ] && [ "$WINUSER" = "AdminUser" ]' "Valid client 'john_doe' parsed correctly"

# Path traversal attack in username
assert '! setup_user "../../etc"' "Path traversal '../../etc' rejected"
assert '! setup_user "../student"' "Path traversal '../student' rejected"

# Uppercase or invalid characters in SFTP username
assert '! setup_user "Student"' "Uppercase username 'Student' rejected"
assert '! setup_user "student;rm -rf"' "Command injection characters in username rejected"
assert '! setup_user "student name"' "Space in username rejected"

# Unregistered client
assert '! setup_user "unknown_user"' "Unregistered client returns failure"

# Malformed config entries in clients.conf
assert '! setup_user "bad_ip"' "Client with invalid IP (999.999.999.999) rejected"
assert '! setup_user "bad_user"' "Client with invalid Windows username rejected"

# -----------------------------------------------------------------------------
section "Restore preparation & SHA-256 integrity check"

setup_user "student"
VALID_FILE="DESKTOP-TEST_20261104_120000_manual.wfw"
echo "TEST_FIREWALL_POLICY_CONTENT" > "$STORE/$VALID_FILE"
CALC_SHA=$(sha256sum "$STORE/$VALID_FILE" | cut -d' ' -f1)
printf "%s  %s\n" "$CALC_SHA" "$VALID_FILE" > "$STORE/$VALID_FILE.sha256"

# Valid restore verification
prepare_restore "$VALID_FILE"
assert '[ "$?" -eq 0 ]' "Valid backup file passes integrity check"

# Missing .sha256 file
NO_SHA_FILE="DESKTOP-TEST_20261104_130000_manual.wfw"
echo "POLICY_WITHOUT_SHA" > "$STORE/$NO_SHA_FILE"
assert '! prepare_restore "$NO_SHA_FILE" && [ "$BK_MSG" = "backup not found on server" ]' "Backup without .sha256 is rejected"

# Tampered backup file
TAMPERED_FILE="DESKTOP-TEST_20261104_140000_manual.wfw"
echo "ORIGINAL_CONTENT" > "$STORE/$TAMPERED_FILE"
printf "%s  %s\n" "$CALC_SHA" "$TAMPERED_FILE" > "$STORE/$TAMPERED_FILE.sha256"
assert '! prepare_restore "$TAMPERED_FILE" && [ "$BK_MSG" = "stored backup failed integrity check" ]' "Tampered backup with mismatched SHA-256 is rejected"

# Invalid backup file names
assert '! prepare_restore "../evil.wfw"' "Path traversal in backup name rejected"
assert '! prepare_restore "file with spaces.wfw"' "Spaces in backup filename rejected"
assert '! prepare_restore "backup.tar.gz"' "Non-.wfw extension rejected"

# -----------------------------------------------------------------------------
section "Backup pruning (retention limit of 30 backups)"

# Clean the store directory
rm -rf "${STORE:?}"/*

# Create 35 mock backups with valid timestamp progression
for i in $(seq -w 1 35); do
    f="$STORE/PC_20261104_${i}0000_auto-add.wfw"
    echo "data $i" > "$f"
    touch -t "2026110400$i" "$f"
    touch -t "2026110400$i" "$f.sha256"
done

KEEP_AUTO=30
PROTECT=""
prune_backups

REMAINING_COUNT=$(find "$STORE" -name "*_auto-add.wfw" | wc -l)
assert '[ "$REMAINING_COUNT" -eq 30 ]' "Pruning retained exactly 30 newest auto backups (from 35)"

# Verify PROTECT parameter prevents pruning of old backup during restore
rm -rf "${STORE:?}"/*
for i in $(seq -w 1 35); do
    f="$STORE/PC_20261104_${i}0000_auto-add.wfw"
    echo "data $i" > "$f"
    touch -t "2026110400$i" "$f"
    touch -t "2026110400$i" "$f.sha256"
done

PROTECTED_FILE="PC_20261104_010000_auto-add.wfw"
PROTECT="$PROTECTED_FILE"
prune_backups

assert '[ -f "$STORE/$PROTECTED_FILE" ] && [ -f "$STORE/$PROTECTED_FILE.sha256" ]' "Protected file ($PROTECTED_FILE) was preserved despite being the oldest"

# -----------------------------------------------------------------------------
section "Reason argument sanitization"

RAW_REASON="auto-add!@#\$%^&*()_+=12345"
CLEAN_REASON=$(printf '%s' "$RAW_REASON" | tr -cd 'a-z-' | cut -c1-20)
assert '[ "$CLEAN_REASON" = "auto-add" ]' "Special characters and numbers stripped from reason string"

printf "\nPassed: %d   Failed: %d\n" "$PASSED" "$FAILED"
if [ "$FAILED" -gt 0 ]; then
    exit 1
else
    exit 0
fi

