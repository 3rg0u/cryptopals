from Crypto.Cipher import AES
import random
from base64 import *

KEY = b"3rg0u3rg0u3rg0u3rg0u"[:16]
PREFIX = b"s0m3_r34d4bl3_571ng_l1k3_7h15"[: random.randint(5, 25)]
RAW = b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
)


# Base
def hex2b64(data: str) -> bytearray:
    return b64encode(bytes.fromhex(data))


# XOR


def fixed_xor(d1: bytearray, d2: bytearray) -> bytearray:
    """
    - params:
        d1: first byte-array
        d2: second byte-array
    - return:
        d1 xor d2
    """
    assert len(d1) == len(d2)
    return bytes([x ^ y for x, y in zip(d1, d2)])


def repeat_xor(data: bytearray, key: bytearray) -> bytearray:
    """
    - params:
        data: plaintext
        key: key to be xor
    - return:
        repeating-key xored ciphertext
    """
    data, key = bytes.fromhex(data), bytes.fromhex(key)
    key = key * (1 + len(data) // len(key))
    return bytes([x ^ y for x, y in zip(data, key)])


# Radom
def get_random_bytes(size: int) -> bytearray:
    return random.randbytes(size)


# Padding
def pkcs7_pad(data: bytearray, block_size: int) -> bytearray:
    """
    - params:
        data: raw data
        block_size: block size, must be in range(1, 256)
    - return:
        padded data of a multiple-length of block_size
    """
    try:
        assert block_size in range(1, 256)
    except Exception as e:
        raise Exception("block_size must be in range(1, 256)")
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding


def pkcs7_unpad(data: bytearray, block_size: int) -> bytearray:
    """
    - params:
        data: padded data under pkcs#7
        block_size: block size, must be in range(1, 256)
    - return:
        unpadded data
    """
    try:
        assert block_size in range(1, 256)
    except Exception as e:
        raise Exception("block_size must be in range(1, 256)")
    padding = data[-1] * bytes([data[-1]]) if data[-1] in range(1, 256) else None
    if not padding or data[-data[-1] :] != padding:
        raise Exception("Invalid padding!")
    return data[: -data[-1]]


def pkcs7_pad_validate(data: bytearray, block_size: int) -> bool:
    assert block_size in range(1, 256)
    padding = data[-1] * bytes([data[-1]]) if data[-1] in range(1, 256) else None
    if not padding or data[-data[-1] :] != padding:
        return False
    return True


# AES ECB
def aes_ecb_encrypt(
    data: bytearray, block_size: int = 16, random: bool = True, key: bytearray = None
) -> bytearray:
    """
    - params:
        data: plaintext
        block_size: block-size, must be in [16, 24, 32]
        radom: using random key or not
        key: given key if not random
    - return:
        encrypted data with aes-ecb mode
    """
    key = key
    if random:
        key = get_random_bytes(block_size)
    assert key is not None
    data = pkcs7_pad(data=data, block_size=block_size)
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    return cipher.encrypt(data)


def aes_ecb_decrypt(data: bytearray, key: bytearray, unpad: bool = True) -> bytearray:
    """
    - params:
        data: ciphertext encrypted under aes-ecb mode
        key: cipher-key
    - return:
        unpadded plaintext
    """
    assert len(key) in (16, 24, 32)
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    return (
        pkcs7_unpad(cipher.decrypt(data), len(key)) if unpad else cipher.decrypt(data)
    )


# AES CBC
IV = get_random_bytes(16)


def aes_cbc_encrypt(
    data: bytearray,
    block_size: int = 16,
    random: bool = True,
    key: bytearray = None,
    iv: bytearray = None,
) -> bytearray:
    """
    - params:
        data: plaintext
        block_size: block-size in [16, 24, 32]
        radom: using random key or not
        key: given key if not random
        iv: initial vector
    - return:
        encrypted data under aes-cbc mode
    """
    assert block_size in (16, 24, 32)
    key, iv = key, iv
    if random:
        key = get_random_bytes(block_size)
        iv = get_random_bytes(block_size)
    assert all(
        [key is not None, iv is not None, len(key) == len(iv), len(key) in (16, 24, 32)]
    )
    data = pkcs7_pad(data=data, block_size=block_size)
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    return cipher.encrypt(data)


def aes_cbc_decrypt(
    data: bytearray, key: bytearray, iv: bytearray, unpad: bool = True
) -> bytearray:
    """
    - params:
        data: ciphertext encrypted under aes-cbc mode
        key: cipher-key
        iv: initial vector
    - return:
        unpadded plaintext
    """
    assert all([len(key) == len(iv), len(key) in (16, 24, 32)])
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    return (
        pkcs7_unpad(cipher.decrypt(data), len(key)) if unpad else cipher.decrypt(data)
    )
