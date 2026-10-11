#!/usr/bin/env python3
"""Sign a litebox-organelle-host manifest with an Ed25519 key.

Usage:
  sign-manifest.py genkey <keyfile>              # generate keypair (hex)
  sign-manifest.py sign <keyfile> <manifest.json> # print signed manifest JSON

The signature covers the canonical manifest bytes with auth.signature
blanked — the same canonical() algorithm as src/manifest.rs (sorted keys,
no whitespace). A successful --trusted-key run against the Rust binary
proves the two implementations agree.
"""
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


def canonical(v):
    if isinstance(v, dict):
        parts = [json.dumps(k) + ":" + canonical(v[k]) for k in sorted(v.keys())]
        return "{" + ",".join(parts) + "}"
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    # scalars: match serde_json (ASCII manifests; no float edge cases here)
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    return repr(v)


def main():
    cmd = sys.argv[1]
    if cmd == "genkey":
        sk = Ed25519PrivateKey.generate()
        priv_hex = sk.private_bytes_raw().hex()
        pub_hex = sk.public_key().public_bytes_raw().hex()
        with open(sys.argv[2], "w") as f:
            f.write(priv_hex + "\n" + pub_hex + "\n")
        print("pubkey:", pub_hex)
    elif cmd == "sign":
        priv_hex = open(sys.argv[2]).read().split()[0]
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        m = json.load(open(sys.argv[3]))
        # Fill serde defaults so the signed bytes match what the Rust host
        # parses (serde_json::to_value serializes ALL struct fields).
        # MUST stay in sync with src/manifest.rs defaults.
        m.setdefault("stdout_limit_bytes", 16 * 1024 * 1024)
        m.setdefault("stderr_limit_bytes", 16 * 1024 * 1024)
        m.setdefault("max_processes", 64)
        m.setdefault("allow_clone", False)
        m.setdefault("keep_workdir", False)
        m.setdefault("auth", None)
        m.setdefault("program_sha256", None)
        m["auth"]["signature"] = ""
        msg = canonical(m).encode()
        sig = sk.sign(msg)
        m["auth"]["signature"] = sig.hex()
        # Drop the filled defaults that weren't in the original? No — keep
        # them: the file is explicit and the bytes are what was signed.
        print(json.dumps(m, indent=2))
    else:
        sys.exit("unknown cmd")


main()
