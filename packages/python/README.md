# elsas-verify

Offline Ed25519 verification of [elsas.it](https://elsas.it) signed security
verdicts. Pure-Python (only dependency: `cryptography`). Prove an elsas atomic-tool
verdict (`check_cve`, `is_exploited`, `check_package`, `search_cves`,
`scan_dependencies`) is authentic and untampered — without trusting elsas's servers
and without `ssh-keygen`.

```python
from elsas_verify import verify_verdict

ok, info = verify_verdict(verdict)   # verdict = the tool's JSON result (dict)
assert ok, info["reason"]
```

It checks (1) the verdict body re-canonicalizes to exactly the embedded
`signed_payload` (tamper evidence) and (2) the SSHSIG verifies under the **pinned**
elsas key (`SHA256:gLVNll72kb8Iyni2vNMR6oHGqVh0Ynz+lBMhbS+cSa4`). A signature by any
other key is rejected.

CLI:

```bash
python -m elsas_verify verdict.json   # → "VALID: good signature (tool=check_cve)"
```

Don't trust us — verify. Source & sibling tools:
<https://github.com/romans-repos/elsas-verify>. MIT.
