def xor_for_bytes(x: bytes, y: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(x, y))
