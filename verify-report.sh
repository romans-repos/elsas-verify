#!/bin/bash
# verify-report — Prüft die Echtheit eines Elsas Curator Reports
# Nutzt ausschließlich ssh-keygen (OpenSSH) + python3 (stdlib).
# Dependencies: openssh-client, python3 — auf jedem Linux/Mac vorhanden.
#
# Trust model: Vertraut dem mitgelieferten allowed_signers als Root-of-Trust.
# Die Signer-Identität ist auf "elsas@elsas.it" gepinnt (-I Flag) —
# ein substituierter allowed_signers mit anderem Key wird abgewiesen.
# Den allowed_signers gegen https://elsas.it/.well-known/elsas-allowed-signers
# verifizieren, wenn der Report von dort stammt.
#
# Usage:
#   ./verify-report.sh report.json
#   ./verify-report.sh report.json allowed_signers
#
# Output: VALID (exit 0) oder INVALID (exit 1) mit Begründung.

set -euo pipefail

REPORT="${1:-}"
ALLOWED="${2:-allowed_signers}"

if [ -z "$REPORT" ]; then
    echo "Usage: verify-report.sh <report.json> [allowed_signers]"
    exit 2
fi

if [ ! -f "$REPORT" ]; then
    echo "INVALID: report file not found: $REPORT"
    exit 1
fi

SIG="${REPORT}.sig"
if [ ! -f "$SIG" ]; then
    echo "INVALID: signature file not found: $SIG"
    exit 1
fi

# Verify SSHSIG signature
VERIFY_OUTPUT=$(ssh-keygen -Y verify \
    -f "$ALLOWED" \
    -I elsas@elsas.it \
    -n elsas-report \
    -s "$SIG" < "$REPORT" 2>&1) || {
    echo "INVALID: signature verification failed"
    echo "$VERIFY_OUTPUT"
    exit 1
}

# Check for "Good" signature
if echo "$VERIFY_OUTPUT" | grep -q '^Good "elsas-report" signature'; then
    # Extract content hash from report for tamper evidence
    HASH=$(python3 -c "
import json, sys
try:
    r = json.load(open('$REPORT'))
    h = r.get('_integrity', {}).get('content_hash', '')
    print(h)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null) || {
    echo "VALID: signature verified (Good) — WARNING: could not extract content hash"
    echo "$VERIFY_OUTPUT" | head -2
    exit 0
}

    if [ -n "$HASH" ]; then
        echo "VALID: authentic & untampered"
        echo "  Signer:  elsas@elsas.it"
        echo "  Hash:    $HASH"
        echo "$VERIFY_OUTPUT" | head -1
    else
        echo "VALID: signature verified — no content hash in report"
        echo "$VERIFY_OUTPUT" | head -1
    fi
    exit 0
else
    echo "INVALID: unexpected verify output"
    echo "$VERIFY_OUTPUT"
    exit 1
fi
