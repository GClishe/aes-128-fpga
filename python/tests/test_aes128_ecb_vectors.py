from python.aes128 import aes_encrypt
import json
from pathlib import Path

VECTORS_PATH = (
    Path(__file__).resolve()
    .parents[2]          
    / "vectors"
    / "aes128_ecb_nist_examples.json"
)

def _load_vectors() -> dict:
    assert VECTORS_PATH.exists(), f"Vector file not found: {VECTORS_PATH}"
    with open(VECTORS_PATH, "r") as f:
        return json.load(f)
    
def _hx(s: str) -> bytes:
    return bytes.fromhex("".join(s.split()))

def test_vectors_file_loads():
    data = _load_vectors()
    assert "vectors" in data
    assert len(data["vectors"]) >= 1

def test_ecb_aes128_vectors_encrypt():
    data = _load_vectors()
    tc = data["vectors"][0]

    key = _hx(tc["key_hex"])
    pts = [_hx(b) for b in tc["plaintext_blocks_hex"]]
    cts = [_hx(b) for b in tc["ciphertext_blocks_hex"]]

    assert len(pts) == len(cts)
    assert all(len(b) == 16 for b in pts)
    assert all(len(b) == 16 for b in cts)
    assert len(key) == 16

    for pt, expected_ct in zip(pts, cts):
        out = aes_encrypt(pt, key)
        assert out == expected_ct