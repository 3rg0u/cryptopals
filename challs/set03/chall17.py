import sys, os

path = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
)

if sys.path[1] != path:
    sys.path.insert(1, path)

from utils.functions import *
import random


def get_random_string():
    strings = "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=\nMDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=\nMDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==\nMDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==\nMDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl\nMDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==\nMDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==\nMDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=\nMDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=\nMDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    return b64decode(random.choice(strings.split("\n")))


def chall17_encrypt() -> bytearray:
    global KEY, IV
    return IV, aes_cbc_encrypt(get_random_string(), random=False, key=KEY, iv=IV)


def chall17_decrypt(data: bytearray, iv: bytearray) -> bool:
    global KEY
    return pkcs7_pad_validate(
        aes_cbc_decrypt(data=data, key=KEY, iv=iv, unpad=False), 16
    )


def get_padding_block(size: int) -> bytearray:
    return bytes([size]) * size


def padding_attack(oracle, ct: bytearray, iv: bytearray) -> bytearray:
    dk_s = bytes()
    for c in [ct[i : i + 16] for i in range(0, len(ct), 16)]:
        suffix = bytes()
        for i in reversed(range(0, 16)):
            for byte in range(0, 256):
                iv_fake = bytes(i) + bytes([byte]) + suffix
                if oracle(c, iv_fake):
                    pad = 16 - i
                    dk_c = fixed_xor(get_padding_block(pad), iv_fake[-pad:])
                    suffix = fixed_xor(get_padding_block(pad + 1)[:pad], dk_c[-pad:])
                    break
        dk_s += dk_c
    return dk_s


def main():
    iv, ct = chall17_encrypt()

    print(f"{iv=}")
    print(f"{ct=}")

    dk_s = padding_attack(chall17_decrypt, ct, iv)

    print(fixed_xor(dk_s, iv + ct[:-16]))


if __name__ == "__main__":
    main()
