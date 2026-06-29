// @elsas/verify — offline Ed25519 verification of elsas.it signed verdicts & reports.
//
// Zero runtime dependencies (Node's built-in `crypto` only). Verifies the SSHSIG
// signature elsas embeds in every atomic-tool verdict, WITHOUT trusting elsas's
// servers and WITHOUT ssh-keygen. Don't trust us — verify.
//
//   import { verifyVerdict } from '@elsas/verify';
//   const { ok, reason } = verifyVerdict(verdict);   // pinned elsas key
//
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';

export const NAMESPACE = 'elsas-report';
export const SIGNER_ID = 'elsas@elsas.it';
// Pinned elsas signing key (also at https://elsas.it/.well-known/allowed_signers).
// Fingerprint SHA256:gLVNll72kb8Iyni2vNMR6oHGqVh0Ynz+lBMhbS+cSa4
export const ELSAS_PUBKEY =
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBlNFX/FUJB+jXCTeiMQQyJnlybI+FOXGPe+uKvd0FK0';

const MAGIC = Buffer.from('SSHSIG');

function readStr(buf, off) {
  const n = buf.readUInt32BE(off);
  off += 4;
  return [buf.subarray(off, off + n), off + n];
}

function sshStr(b) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, b]);
}

// Raw 32-byte Ed25519 public key → Node KeyObject via SPKI DER wrapper.
function ed25519FromRaw(raw32) {
  const der = Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'),
    raw32,
  ]);
  return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function rawFromOpenssh(line) {
  const parts = line.trim().split(/\s+/);
  const i = parts.indexOf('ssh-ed25519');
  if (i === -1 || !parts[i + 1]) throw new Error('no ssh-ed25519 key');
  const blob = Buffer.from(parts[i + 1], 'base64');
  let [typ, off] = readStr(blob, 0);
  if (typ.toString() !== 'ssh-ed25519') throw new Error('not ed25519');
  const [raw] = readStr(blob, off);
  return raw;
}

function parseSshsig(armored) {
  const body = armored
    .trim()
    .split(/\r?\n/)
    .filter((l) => !l.startsWith('-----'))
    .join('');
  const blob = Buffer.from(body, 'base64');
  if (!blob.subarray(0, 6).equals(MAGIC)) throw new Error('bad SSHSIG magic');
  let off = 6 + 4; // magic + version
  let pubWire, namespace, reserved, hashAlg, sigBlob;
  [pubWire, off] = readStr(blob, off);
  [namespace, off] = readStr(blob, off);
  [reserved, off] = readStr(blob, off);
  [hashAlg, off] = readStr(blob, off);
  [sigBlob, off] = readStr(blob, off);
  let [, so] = readStr(sigBlob, 0);
  const [rawSig] = readStr(sigBlob, so);
  let [, po] = readStr(pubWire, 0);
  const [rawPub] = readStr(pubWire, po);
  return { namespace: namespace.toString(), hashAlg: hashAlg.toString(), rawSig, rawPub };
}

function tbs(message, namespace, hashAlg) {
  const h = createHash(hashAlg === 'sha512' ? 'sha512' : 'sha256').update(message).digest();
  return Buffer.concat([
    MAGIC,
    sshStr(Buffer.from(namespace)),
    sshStr(Buffer.alloc(0)),
    sshStr(Buffer.from(hashAlg)),
    sshStr(h),
  ]);
}

// Semantic deep-equality. Used for the tamper check instead of re-serializing:
// JSON.stringify can't reproduce the signer's float formatting (Python emits "1.0",
// JS emits "1"), so we compare the PARSED signed_payload to the verdict body by
// value. The signature itself is verified over the authoritative signed_payload bytes.
export function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (typeof a === 'number' && typeof b === 'number') return a === b; // 1.0 === 1
  if (typeof a !== 'object') return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  const ka = Object.keys(a), kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k]));
}

export function verifySignedBytes(message, armoredSig, pubkey = ELSAS_PUBKEY, namespace = NAMESPACE) {
  let sig;
  try {
    sig = parseSshsig(armoredSig);
  } catch (e) {
    return { ok: false, reason: `unparseable signature: ${e.message}` };
  }
  if (sig.namespace !== namespace) {
    return { ok: false, reason: `namespace mismatch: ${sig.namespace} != ${namespace}` };
  }
  try {
    const expRaw = rawFromOpenssh(pubkey);
    if (!expRaw.equals(sig.rawPub)) {
      return { ok: false, reason: 'signature is by a different key than the pinned elsas key' };
    }
  } catch (e) {
    return { ok: false, reason: `bad expected pubkey: ${e.message}` };
  }
  try {
    const key = ed25519FromRaw(sig.rawPub);
    const ok = cryptoVerify(null, tbs(Buffer.from(message), namespace, sig.hashAlg), key, sig.rawSig);
    return { ok, reason: ok ? 'good signature' : 'invalid signature' };
  } catch (e) {
    return { ok: false, reason: `verify error: ${e.message}` };
  }
}

export function verifyVerdict(verdict, pubkey = ELSAS_PUBKEY) {
  const s = verdict?._signature;
  if (!s || !s.signed_payload || !s.signature) return { ok: false, reason: 'no _signature block' };
  const { _signature, ...body } = verdict;
  let signedObj;
  try {
    signedObj = JSON.parse(s.signed_payload);
  } catch {
    return { ok: false, reason: 'signed_payload is not valid JSON' };
  }
  if (!deepEqual(signedObj, body)) {
    return { ok: false, reason: 'body does not match signed_payload (tampered)' };
  }
  const r = verifySignedBytes(s.signed_payload, s.signature, pubkey, s.namespace || NAMESPACE);
  return { ...r, tool: verdict.tool, signer: SIGNER_ID };
}

// CLI: node index.mjs <verdict.json>
if (import.meta.url === `file://${process.argv[1]}`) {
  const fs = await import('node:fs');
  const path = process.argv[2];
  if (!path) {
    console.log('usage: node index.mjs <verdict.json>');
    process.exit(2);
  }
  const verdict = JSON.parse(fs.readFileSync(path, 'utf8'));
  const r = verifyVerdict(verdict);
  console.log((r.ok ? 'VALID' : 'INVALID') + `: ${r.reason} (tool=${r.tool})`);
  process.exit(r.ok ? 0 : 1);
}
