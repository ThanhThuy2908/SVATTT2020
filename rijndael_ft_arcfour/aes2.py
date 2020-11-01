from typing import List
import os
import aes  # https://github.com/boppreh/aes, added support for custom S-box.


def ksa(key: bytes) -> List[int]:
    """Arcfour (RC4) key scheduling algorithm."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        if i != j:
            # swap S[i] and S[j]
            S[i] += S[j]
            S[j] = S[i] - S[j]
            S[i] -= S[j]
    return S


def encrypt(msg: bytes, rc4_key: bytes, aes_key: bytes) -> bytes:
    """Rijndael (AES) ft. Arcfour (RC4) encryption routine."""
    sbox = ksa(rc4_key)

    # Since the sbox should look like a random table, we can check for weak
    # keys by counting the number of elements smaller than 128 in the first 128
    # entries. This number should be around 64.
    assert 64 - 8 <= [c < 128 for c in sbox[:128]].count(True) <= 64 + 8

    aes.set_s_box(sbox)
    iv = os.urandom(16)
    return iv + aes.AES(aes_key).encrypt_cbc(msg, iv)


if __name__ == '__main__':
    # # give us a key
    # key = bytes.fromhex(input())

    # # here's a gift for you :)
    # from secret import flag
    # print(encrypt(f"The flag is: {flag}".encode(), key, os.urandom(16)).hex())
    key = bytes.fromhex('00')
    print(key[0])
    print(key[1])
