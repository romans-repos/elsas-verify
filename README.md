# elsas-verify

**Independently verify the daily security-intelligence reports published by
[elsas.it](https://elsas.it) — offline, with no trust in our servers and no
access to our keys.**

[elsas.it](https://elsas.it) is signed security intelligence for **AI agents**,
served over MCP and paid per call with [x402](https://elsas.it/docs) (USDC on Base —
accountless, your wallet is your identity). Two shapes:

- **Atomic primitives** (high-frequency, sub-cent): `is_exploited` (is this CVE in
  CISA-KEV? $0.001), `check_cve` (CVSS + KEV + EPSS, $0.01), `check_package` (OSV
  verdict for one package@version, $0.002), `search_cves` ($0.01), `scan_dependencies`
  (whole-lockfile OSV scan, pay-per-vuln, free when clean).
- **Premium digest**: `get_today` — the daily curated, cross-validated report ($0.10).

**Every response is Ed25519-signed** (SSHSIG, namespace `elsas-report`) — so you can
prove it's authentic and untampered *without trusting our servers and without our
keys*. That's the differentiator: unsigned CVE APIs ask you to trust them; we let you
verify. This repo is everything you need to do that offline.

> **Don't trust us — verify.**

---

## Verify in 30 seconds

Requirements: `openssh-client` (`ssh-keygen`) and `python3` — present on any
Linux/macOS. No install, no network needed for the verification itself.

```bash
git clone https://github.com/romans-repos/elsas-verify.git
cd elsas-verify
./verify-report.sh examples/sample-report.json allowed_signers
```

Expected output:

```
VALID: authentic & untampered
  Signer:  elsas@elsas.it
  Hash:    sha256:…
Good "elsas-report" signature for elsas@elsas.it with ED25519 key SHA256:gLVNll72kb8Iyni2vNMR6oHGqVh0Ynz+lBMhbS+cSa4
```

## Verify a live report

```bash
# Fetch the current public sample + its detached signature
curl -s https://elsas.it/sample                          > report.json
curl -s https://elsas.it/.well-known/report.json.sig     > report.json.sig
# Verify against the pinned key in this repo
./verify-report.sh report.json allowed_signers
```

You can also verify by hand with stock OpenSSH:

```bash
ssh-keygen -Y verify \
  -f allowed_signers \
  -I elsas@elsas.it \
  -n elsas-report \
  -s report.json.sig < report.json
```

## Verify an atomic-tool verdict

The atomic tools return a JSON verdict with an embedded `_signature` block
(`signed_payload` = the exact signed bytes; `signature` = an armored SSHSIG). Verify
it offline — by shell, or with the drop-in library for your language:

```bash
# shell (ssh-keygen + python3 stdlib)
./verify-verdict.sh examples/sample-verdict.json allowed_signers
```

```js
// Node — zero dependencies (built-in crypto). npm i @elsas/verify
import { verifyVerdict } from '@elsas/verify';
const { ok, reason } = verifyVerdict(verdict);   // pinned elsas key, offline
if (!ok) throw new Error(`unverified elsas verdict: ${reason}`);
```

```python
# Python — pip install elsas-verify  (only dep: cryptography)
from elsas_verify import verify_verdict
ok, info = verify_verdict(verdict)
assert ok, info["reason"]
```

Each verifier does two independent checks: (1) the verdict body matches the signed
bytes (tamper-evidence), and (2) the SSHSIG verifies under the **pinned** elsas key
(a signature by any other key is rejected). No network call is needed to verify.

## Trust model

- Signatures use **SSHSIG (Ed25519)** via `ssh-keygen -Y sign`. Verification is
  offline and zero-trust: you hold the payload, you verify locally.
- The **root of trust** is [`allowed_signers`](./allowed_signers) — our public
  key, identity-pinned to `elsas@elsas.it`. A substituted signers file with a
  different key is rejected by the `-I` flag.
- Confirm the pinned key independently against the live copy:
  ```bash
  curl -s https://elsas.it/.well-known/allowed_signers
  ```
  Key fingerprint: `SHA256:gLVNll72kb8Iyni2vNMR6oHGqVh0Ynz+lBMhbS+cSa4`
- Each report also carries a `_integrity.content_hash` (sha256 over the
  canonical JSON) for tamper evidence — see [`SIGNATURE-VERIFY.md`](./SIGNATURE-VERIFY.md).

## What's in here

| File | Purpose |
|---|---|
| `verify-report.sh` | Dependency-free report verifier (ssh-keygen + python3 stdlib) |
| `verify-verdict.sh` | Dependency-free **atomic-verdict** verifier |
| `packages/node/` | `@elsas/verify` — zero-dep Node library + CLI |
| `packages/python/` | `elsas-verify` — Python library + CLI (`pip install`) |
| `allowed_signers` | Our public signing key — the root of trust |
| `schemas/report-v4.json` | JSON schema of a report payload |
| `examples/sample-report.json` (+ `.sig`) | A real, signed report to verify against |
| `examples/sample-verdict.json` | A real, signed atomic-tool verdict to verify against |
| `SIGNATURE-VERIFY.md` | The full verification recipe and trust details |

## What's *not* here

This repo is the **verification surface only**. The curation pipeline, scoring
prompts, relevance taxonomy, infrastructure and any operational configuration are
intentionally not published — they are neither needed to verify a report nor
useful to a third party. Verifiability does not require disclosing how the
sausage is made; it requires that the result is checkable. That's what this is.

## License

Tooling in this repository is released under the [MIT License](./LICENSE).
Report payloads themselves carry their own license terms inside the report
(`_integrity._license_coverage`).

---

Service: **https://elsas.it** · Docs: **https://elsas.it/docs** · Sample: **https://elsas.it/sample**
