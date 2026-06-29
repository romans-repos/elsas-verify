# @elsas/verify

Offline Ed25519 verification of [elsas.it](https://elsas.it) signed security
verdicts. **Zero runtime dependencies** (Node's built-in `crypto`). Prove an elsas
atomic-tool verdict (`check_cve`, `is_exploited`, `check_package`, `search_cves`,
`scan_dependencies`) is authentic and untampered — without trusting elsas's servers
and without `ssh-keygen`.

```js
import { verifyVerdict } from '@elsas/verify';

const { ok, reason, tool } = verifyVerdict(verdict);  // verdict = the tool's JSON result
if (!ok) throw new Error(`unverified elsas verdict: ${reason}`);
```

It checks (1) the verdict body matches the embedded `signed_payload` (tamper
evidence) and (2) the SSHSIG verifies under the **pinned** elsas key
(`SHA256:gLVNll72kb8Iyni2vNMR6oHGqVh0Ynz+lBMhbS+cSa4`). A signature by any other key
is rejected. To pin a different key (e.g. for testing), pass it as the 2nd arg.

CLI:

```bash
node index.mjs verdict.json   # → "VALID: good signature (tool=check_cve)"
```

Don't trust us — verify. Source & sibling tools:
<https://github.com/romans-repos/elsas-verify>. MIT.
