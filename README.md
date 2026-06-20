# elsas-verify

**Independently verify the daily security-intelligence reports published by
[elsas.it](https://elsas.it) — offline, with no trust in our servers and no
access to our keys.**

[elsas.it](https://elsas.it) is a daily, signed security-intelligence service for
**AI-agent stack operators**: CVEs, supply-chain incidents and advisories
(GHSA · CISA-KEV · OSV · NVD · national-CERT feeds) assessed for impact on MCP
servers, LLM proxies and agent orchestration — curated, cross-validated, and
**Ed25519-signed**. Served as a paid MCP tool for $0.10 USDC via the
[x402](https://elsas.it/docs) payment protocol.

This repository contains everything a third party needs to **prove a report is
authentic and untampered** — our public key, the JSON schema, a real signed
sample report, and a dependency-free verification script. Nothing here is secret;
every file is also served live from elsas.it. The point is simple:

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
| `verify-report.sh` | Dependency-free verifier (ssh-keygen + python3 stdlib) |
| `allowed_signers` | Our public signing key — the root of trust |
| `schemas/report-v4.json` | JSON schema of a report payload |
| `examples/sample-report.json` (+ `.sig`) | A real, signed report to verify against |
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
