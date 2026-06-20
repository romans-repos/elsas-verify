# Signature Verification Recipe — elsas.it Reports

## Trust Model

Elsas reports are Ed25519-signed via `ssh-keygen -Y sign`. Verification is
offline, zero-trust: no Elsas server needed. You hold the payload, you
verify locally.

## Artifacts (3 public URLs)

| Artifact        | URL                                              |
|-----------------|--------------------------------------------------|
| Report payload  | https://elsas.it/sample                          |
| Detached sig    | https://elsas.it/.well-known/report.json.sig     |
| Allowed signers | https://elsas.it/.well-known/allowed_signers     |

All three share one inode via hardlinks — modifying one modifies all. Drift
impossible. Verify with `ls -li`: identical first column = same inode.

## Canonical Verify Command

```bash
# 1. Fetch artifacts
curl -s https://elsas.it/.well-known/allowed_signers > allowed_signers
curl -s https://elsas.it/sample > report.json
curl -s https://elsas.it/.well-known/report.json.sig > report.json.sig

# 2. Verify signature
ssh-keygen -Y verify \
  -f allowed_signers \
  -I elsas@elsas.it \
  -n elsas-report \
  -s report.json.sig \
  < report.json

# Expected output:
# Good "elsas-report" signature for elsas@elsas.it with ED25519 key SHA256:gLVNll72kb8Iyni2vNMR6oHGqVh0Ynz+lBMhbS+cSa4
```

## Parameters Explained

| Parameter            | Value             | Meaning                                          |
|----------------------|-------------------|--------------------------------------------------|
| `-f allowed_signers` | (file)            | Allowed signers list — maps identity to pubkey   |
| `-I elsas@elsas.it`  | `elsas@elsas.it`  | Identity string from allowed_signers line 1      |
| `-n elsas-report`    | `elsas-report`    | Signature namespace — signed with `-n elsas-report` |
| `-s report.json.sig` | (file)            | Detached signature file (SSHSIG format)          |
| `< report.json`       | (stdin)           | The canonical payload bytes — verbatim report    |

## Public Key

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBlNFX/FUJB+jXCTeiMQQyJnlybI+FOXGPe+uKvd0FK0 elsas-signing-key
```

Key fingerprint: `SHA256:gLVNll72kb8Iyni2vNMR6oHGqVh0Ynz+lBMhbS+cSa4`

## Content Hash vs Signature

The report carries `_integrity.content_hash` — a sha256 over the canonical
content fields of the `data` object (report_id, schema_version, generated_at,
trigger_reason, total_items, items, sources_summary, _tldr). The signature
covers the ENTIRE served payload (all bytes), not just the hash. This means:

- `content_hash` detects content drift (items changed, reordered, injected)
- `signature` proves authorship (the bytes came from elsas@elsas.it)
- Both MUST match. A valid signature on an unexpected content_hash =
  report was re-signed after tampering → reject.

## Verify content_hash (secondary check)

```bash
curl -s https://elsas.it/sample | python3 -c "
import json, sys, hashlib
r = json.load(sys.stdin)
d = r['data']                       # report payload lives under the 'data' key
fields = ['report_id','schema_version','generated_at','trigger_reason',
          'total_items','items','sources_summary','_tldr']
subset = {k: d.get(k) for k in fields}
# canonicalization: compact JSON, sorted keys, UTF-8 (ensure_ascii=False)
canon = json.dumps(subset, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()
computed = 'sha256:' + hashlib.sha256(canon).hexdigest()
claimed = r['_integrity']['content_hash']
print(f'claimed:  {claimed}')
print(f'computed: {computed}')
print(f'match:    {claimed == computed}')
"
```

## Cross-Surface Consistency Proof

The free report is published byte-identically on two public surfaces. They must
hash the same — if they ever diverge, treat the report as untrusted:

```bash
a=$(curl -s https://elsas.it/sample | sha256sum | cut -d' ' -f1)
b=$(curl -s https://elsas.it/.well-known/report.json | sha256sum | cut -d' ' -f1)
[ "$a" = "$b" ] && echo "consistent: $a" || echo "DRIFT DETECTED — reject"
# Identical sha256 on both surfaces = same bytes delivered. Together with the
# signature check above, the payload is authentic and consistently served.
```

## Recovery / Key Rotation Path

If the signing key must be rotated:
1. New key pair generated: `ssh-keygen -t ed25519 -f ~/.ssh/elsas_sign_new -C elsas-signing-key-v2`
2. New allowed_signers published at `/.well-known/allowed_signers`
3. Old key retired 30 days after rotation (overlap window for cached clients)
4. Any report signed with the old key after rotation window = reject

## Current Run (R31a)

```
run_id:       48709d71-72f1-45be-a927-c8d2a9037930
content_hash: sha256:4492955209f5d158061a90920a82465fe19b4cb9d006b307f5c1c635b6497147
generated_at: 2026-06-15T00:46:xxZ
items:        50 (48 GHSA, 2 arxiv)
signature:    Good (extern verifiziert)
```
