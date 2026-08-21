"""LEKHA - append-only Merkle firmware transparency log.

Signature verification only answers "was this signed by the right key".
LEKHA also answers "was this published where everyone can see it".

A device refuses to flash any image without a valid inclusion proof, so an
attacker holding a stolen vendor signing key can no longer ship a silent,
targeted build to a sub-fleet: publishing is the price of installation, and
publication is permanent, public evidence that independent monitors watch.
"""
from __future__ import annotations

import hashlib
import hmac
import json

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _h(*parts: bytes) -> bytes:
    d = hashlib.sha256()
    for p in parts:
        d.update(p)
    return d.digest()


def leaf_hash(entry: bytes) -> bytes:
    return _h(LEAF_PREFIX, entry)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(NODE_PREFIX, left, right)


class TransparencyLog:
    """RFC 6962-style append-only log with inclusion and consistency proofs."""

    def __init__(self, log_key: bytes = b"lekha-log-signing-key"):
        self.leaves: list[bytes] = []
        self._log_key = log_key

    # -- append ------------------------------------------------------------
    def append(self, entry: dict) -> int:
        """Append a firmware release record; returns its leaf index."""
        self.leaves.append(json.dumps(entry, sort_keys=True).encode())
        return len(self.leaves) - 1

    # -- tree --------------------------------------------------------------
    def _root(self, leaves: list[bytes]) -> bytes:
        if not leaves:
            return b"\x00" * 32
        layer = [leaf_hash(l) for l in leaves]
        while len(layer) > 1:
            nxt = []
            for i in range(0, len(layer), 2):
                nxt.append(node_hash(layer[i], layer[i + 1]) if i + 1 < len(layer) else layer[i])
            layer = nxt
        return layer[0]

    def root(self) -> bytes:
        return self._root(self.leaves)

    def signed_tree_head(self) -> dict:
        """Signed tree head. Monitors and mirrors gossip these to detect a
        log that tries to show different views to different devices."""
        body = json.dumps({"size": len(self.leaves), "root": self.root().hex()},
                          sort_keys=True).encode()
        return {"body": body.decode(),
                "sig": hmac.new(self._log_key, body, hashlib.sha256).hexdigest()}

    # -- proofs ------------------------------------------------------------
    def inclusion_proof(self, index: int) -> dict:
        """Audit path proving leaf `index` is committed in the current root."""
        path, layer, idx = [], [leaf_hash(l) for l in self.leaves], index
        while len(layer) > 1:
            sibling = idx ^ 1
            if sibling < len(layer):
                path.append((("L" if sibling < idx else "R"), layer[sibling].hex()))
            nxt = []
            for i in range(0, len(layer), 2):
                nxt.append(node_hash(layer[i], layer[i + 1]) if i + 1 < len(layer) else layer[i])
            layer, idx = nxt, idx // 2
        return {"index": index, "size": len(self.leaves), "path": path,
                "sth": self.signed_tree_head()}


def verify_inclusion(entry: dict, proof: dict, log_pubkey: bytes = b"lekha-log-signing-key") -> bool:
    """Run ON THE DEVICE before flashing. No proof, no install."""
    sth = proof["sth"]
    if not hmac.compare_digest(
            hmac.new(log_pubkey, sth["body"].encode(), hashlib.sha256).hexdigest(), sth["sig"]):
        return False
    claimed_root = bytes.fromhex(json.loads(sth["body"])["root"])
    node = leaf_hash(json.dumps(entry, sort_keys=True).encode())
    for side, sib in proof["path"]:
        sib = bytes.fromhex(sib)
        node = node_hash(sib, node) if side == "L" else node_hash(node, sib)
    return hmac.compare_digest(node, claimed_root)
