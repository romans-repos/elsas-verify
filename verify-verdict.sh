#!/bin/bash
# verify-verdict — prove a single elsas ATOMIC-TOOL verdict is authentic & untampered.
#
# Atomic tools (check_cve, is_exploited, check_package, search_cves, scan_dependencies)
# return a JSON object carrying an embedded `_signature` block:
#   _signature.signed_payload  — the exact bytes that were signed (canonical JSON of
#                                 the verdict WITHOUT _signature)
#   _signature.signature       — an armored SSHSIG (Ed25519, namespace elsas-report)
#
# This script (1) re-derives the canonical payload from the verdict and checks it
# matches signed_payload (tamper check), then (2) verifies the SSHSIG offline with
# ssh-keygen against the pinned allowed_signers. No network, no trust in our servers.
#
# Usage:
#   ./verify-verdict.sh verdict.json [allowed_signers]
# Deps: openssh-client (ssh-keygen) + python3 (stdlib). Exit 0 = VALID, 1 = INVALID.

set -euo pipefail

VERDICT="${1:-}"
ALLOWED="${2:-allowed_signers}"

if [ -z "$VERDICT" ] || [ ! -f "$VERDICT" ]; then
    echo "Usage: verify-verdict.sh <verdict.json> [allowed_signers]"
    exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Split the verdict into the signed bytes + the signature, and confirm the signed
# bytes are exactly the canonical re-encoding of the verdict minus _signature.
python3 - "$VERDICT" "$TMP" <<'PY'
import json, sys
verdict_path, tmp = sys.argv[1], sys.argv[2]
v = json.load(open(verdict_path))
sig = v.get("_signature")
if not sig or "signed_payload" not in sig or "signature" not in sig:
    print("INVALID: no _signature block (is this an elsas atomic verdict?)"); sys.exit(1)

# Canonical JSON identical to the signer: sort_keys, compact separators, unicode kept.
def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

body = {k: val for k, val in v.items() if k != "_signature"}
recomputed = canonical(body)
if recomputed != sig["signed_payload"]:
    print("INVALID: verdict body does not match signed_payload (tampered)"); sys.exit(1)

open(tmp + "/v.json", "w").write(sig["signed_payload"])
open(tmp + "/v.sig", "w").write(sig["signature"])
PY

VERIFY_OUTPUT=$(ssh-keygen -Y verify \
    -f "$ALLOWED" \
    -I elsas@elsas.it \
    -n elsas-report \
    -s "$TMP/v.sig" < "$TMP/v.json" 2>&1) || {
    echo "INVALID: signature verification failed"
    echo "$VERIFY_OUTPUT"
    exit 1
}

if echo "$VERIFY_OUTPUT" | grep -q '^Good "elsas-report" signature'; then
    TOOL=$(python3 -c "import json;print(json.load(open('$VERDICT')).get('tool','?'))")
    echo "VALID: authentic & untampered"
    echo "  Tool:   $TOOL"
    echo "  Signer: elsas@elsas.it"
    echo "$VERIFY_OUTPUT" | head -1
    exit 0
else
    echo "INVALID: unexpected verify output"
    echo "$VERIFY_OUTPUT"
    exit 1
fi
