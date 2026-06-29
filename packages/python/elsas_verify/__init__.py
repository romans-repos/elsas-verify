"""elsas-verify — offline verification of elsas.it signed verdicts & reports.

Pure-Python, dependency-light (only `cryptography`). Verifies the Ed25519 SSHSIG
signature elsas embeds in every atomic-tool verdict, WITHOUT trusting elsas's
servers and WITHOUT ssh-keygen. The point: don't trust us — verify.

    from elsas_verify import verify_verdict
    ok, info = verify_verdict(verdict_dict)   # uses the pinned elsas public key
    assert ok

A verdict is the JSON returned by check_cve / is_exploited / check_package /
search_cves / scan_dependencies. It carries `_signature.signed_payload` (the exact
signed bytes) and `_signature.signature` (armored SSHSIG).
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

__all__ = ["verify_verdict", "verify_signed_bytes", "ELSAS_PUBKEY", "NAMESPACE"]

NAMESPACE = "elsas-report"
SIGNER_ID = "elsas@elsas.it"
# Pinned elsas signing key (also at https://elsas.it/.well-known/allowed_signers).
# Fingerprint: SHA256:gLVNll72kb8Iyni2vNMR6oHGqVh0Ynz+lBMhbS+cSa4
ELSAS_PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBlNFX/FUJB+jXCTeiMQQyJnlybI+FOXGPe+uKvd0FK0"

_MAGIC = b"SSHSIG"


def _rd_str(buf: bytes, off: int) -> Tuple[bytes, int]:
    (n,) = struct.unpack(">I", buf[off:off + 4])
    off += 4
    return buf[off:off + n], off + n


def _ed25519_from_openssh(line: str) -> Ed25519PublicKey:
    parts = line.split()
    # accept "ssh-ed25519 AAAA..." or a full allowed_signers line "<id> ssh-ed25519 AAAA..."
    blob_b64 = None
    for i, p in enumerate(parts):
        if p == "ssh-ed25519" and i + 1 < len(parts):
            blob_b64 = parts[i + 1]
            break
    if blob_b64 is None:
        raise ValueError("no ssh-ed25519 key found")
    blob = base64.b64decode(blob_b64)
    typ, off = _rd_str(blob, 0)
    if typ != b"ssh-ed25519":
        raise ValueError("not an ed25519 key")
    raw, _ = _rd_str(blob, off)
    return Ed25519PublicKey.from_public_bytes(raw)


def _parse_sshsig(armored: str):
    body = "".join(
        l for l in armored.strip().splitlines()
        if not l.startswith("-----")
    )
    blob = base64.b64decode(body)
    if blob[:6] != _MAGIC:
        raise ValueError("bad SSHSIG magic")
    off = 6
    (_ver,) = struct.unpack(">I", blob[off:off + 4]); off += 4
    pub_wire, off = _rd_str(blob, off)
    namespace, off = _rd_str(blob, off)
    _reserved, off = _rd_str(blob, off)
    hash_alg, off = _rd_str(blob, off)
    sig_blob, off = _rd_str(blob, off)
    # inner signature blob: string("ssh-ed25519") + string(raw_sig)
    styp, so = _rd_str(sig_blob, 0)
    raw_sig, _ = _rd_str(sig_blob, so)
    # inner pubkey: string("ssh-ed25519") + string(raw_pub)
    ptyp, po = _rd_str(pub_wire, 0)
    raw_pub, _ = _rd_str(pub_wire, po)
    return {
        "namespace": namespace.decode(),
        "hash_alg": hash_alg.decode(),
        "raw_sig": raw_sig,
        "raw_pub": raw_pub,
    }


def _tbs(message: bytes, namespace: str, hash_alg: str) -> bytes:
    h = (hashlib.sha512 if hash_alg == "sha512" else hashlib.sha256)(message).digest()

    def s(b: bytes) -> bytes:
        return struct.pack(">I", len(b)) + b

    return _MAGIC + s(namespace.encode()) + s(b"") + s(hash_alg.encode()) + s(h)


def canonical(obj) -> str:
    """Same canonical JSON the signer used (sort_keys, compact, unicode kept)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_signed_bytes(message: bytes, armored_sig: str,
                        pubkey: str = ELSAS_PUBKEY,
                        namespace: str = NAMESPACE) -> Tuple[bool, str]:
    """Verify a raw SSHSIG over `message`. Returns (ok, reason)."""
    try:
        sig = _parse_sshsig(armored_sig)
    except Exception as e:  # noqa: BLE001
        return False, f"unparseable signature: {e}"
    if sig["namespace"] != namespace:
        return False, f"namespace mismatch: {sig['namespace']!r} != {namespace!r}"
    try:
        expected = _ed25519_from_openssh(pubkey)
        exp_raw = expected.public_bytes_raw() if hasattr(expected, "public_bytes_raw") else None
    except Exception as e:  # noqa: BLE001
        return False, f"bad expected pubkey: {e}"
    # The signature must be by the pinned key, not just any key.
    if exp_raw is not None and exp_raw != sig["raw_pub"]:
        return False, "signature is by a different key than the pinned elsas key"
    try:
        key = Ed25519PublicKey.from_public_bytes(sig["raw_pub"])
        key.verify(sig["raw_sig"], _tbs(message, namespace, sig["hash_alg"]))
        return True, "good signature"
    except InvalidSignature:
        return False, "invalid signature"
    except Exception as e:  # noqa: BLE001
        return False, f"verify error: {e}"


def verify_verdict(verdict: dict, pubkey: str = ELSAS_PUBKEY) -> Tuple[bool, dict]:
    """Verify an elsas atomic-tool verdict end to end.

    Checks (1) the body re-canonicalizes to exactly _signature.signed_payload
    (tamper-evidence), and (2) the SSHSIG verifies under the pinned elsas key.
    Returns (ok, info).
    """
    s = verdict.get("_signature")
    if not isinstance(s, dict) or "signed_payload" not in s or "signature" not in s:
        return False, {"reason": "no _signature block"}
    body = {k: v for k, v in verdict.items() if k != "_signature"}
    if canonical(body) != s["signed_payload"]:
        return False, {"reason": "body does not match signed_payload (tampered)"}
    ok, reason = verify_signed_bytes(s["signed_payload"].encode("utf-8"), s["signature"],
                                     pubkey=pubkey, namespace=s.get("namespace", NAMESPACE))
    return ok, {"reason": reason, "tool": verdict.get("tool"), "signer": SIGNER_ID}


def _cli() -> int:
    import sys
    if len(sys.argv) < 2:
        print("usage: python -m elsas_verify <verdict.json>")
        return 2
    verdict = json.load(open(sys.argv[1]))
    ok, info = verify_verdict(verdict)
    print(("VALID" if ok else "INVALID") + f": {info['reason']} (tool={info.get('tool')})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
