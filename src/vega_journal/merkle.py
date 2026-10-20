"""merkle.py - a Merkle tree over the journal's record hashes, with inclusion proofs a third party can check without the rest of the journal (RFC 6962 layout: leaf = H(0x00 || h), node = H(0x01 || left || right), the tree
splits at the largest power of two below the size)."""
import hashlib


def _leaf(h: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + h).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(hashes) -> str:
    hs = [bytes.fromhex(h) for h in hashes]
    if not hs:
        return hashlib.sha256(b"").hexdigest()

    def r(items):
        if len(items) == 1:
            return _leaf(items[0])
        k = _split(len(items))
        return _node(r(items[:k]), r(items[k:]))
    return r(hs).hex()


def proof(hashes, index: int):
    """-> list of (side, hash hex) from the leaf up; side 'L' means the sibling is on the left."""
    hs = [bytes.fromhex(h) for h in hashes]
    if not 0 <= index < len(hs):
        raise IndexError("no such leaf")

    def p(items, i):
        if len(items) == 1:
            return []
        k = _split(len(items))
        if i < k:
            return p(items[:k], i) + [("R", root([x.hex() for x in items[k:]]))]
        return p(items[k:], i - k) + [("L", root([x.hex() for x in items[:k]]))]
    return p(hs, index)


def verify(root_hex: str, leaf_hex: str, path) -> bool:
    try:
        node = _leaf(bytes.fromhex(leaf_hex))
        for side, sib in path:
            if side not in ("L", "R"):
                return False
            s = bytes.fromhex(sib)
            node = _node(s, node) if side == "L" else _node(node, s)
        return node.hex() == root_hex
    except (ValueError, TypeError):
        return False
