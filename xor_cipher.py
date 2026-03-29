#!/usr/bin/env python3
"""xor_cipher - XOR cipher with repeating key and frequency analysis cracker."""
import sys
from collections import Counter

def xor_encrypt(data, key):
    if isinstance(data, str): data = data.encode()
    if isinstance(key, str): key = key.encode()
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

def xor_decrypt(data, key):
    return xor_encrypt(data, key)  # symmetric

def hamming_distance(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def guess_key_length(ciphertext, max_len=40):
    scores = []
    for kl in range(2, min(max_len, len(ciphertext)//2)):
        chunks = [ciphertext[i:i+kl] for i in range(0, len(ciphertext)-kl, kl)][:4]
        if len(chunks) < 2: continue
        dists = []
        for i in range(len(chunks)-1):
            dists.append(hamming_distance(chunks[i], chunks[i+1]) / kl)
        scores.append((sum(dists)/len(dists), kl))
    scores.sort()
    return [kl for _, kl in scores[:3]]

def crack_single_xor(data):
    best = (-999, 0, b"")
    for key in range(256):
        dec = bytes(b ^ key for b in data)
        score = 0
        for c in dec:
            if c == 32 or 65 <= c <= 90 or 97 <= c <= 122: score += 1
            elif c < 32 or c > 126: score -= 3
        if score > best[0]:
            best = (score, key, dec)
    return best[1], best[2]

def test():
    msg = b"Hello, World! This is a secret message."
    key = b"KEY"
    enc = xor_encrypt(msg, key)
    assert enc != msg
    dec = xor_decrypt(enc, key)
    assert dec == msg
    # Single byte XOR crack
    single_enc = xor_encrypt(b"the quick brown fox jumps over the lazy dog", bytes([42]))
    k, plaintext = crack_single_xor(single_enc)
    assert k == 42
    # Hamming distance
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37
    print("xor_cipher: all tests passed")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("Usage: xor_cipher.py --test")
