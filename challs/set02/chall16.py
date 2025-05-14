import sys, os

path = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
)

if sys.path[1] != path:
    sys.path.insert(1, path)


from utils.functions import *


def bit_flipping(
    data: bytearray, pos: int, raw: bytearray, repl: bytearray
) -> bytearray:
    """
    - params:
        data: data to be manipulated under bit-flipping
        pos: starting postition
        raw: original data to be replaced
        repl: data used to replace raw
    - return:
        scrumbled data with replace(raw, repl)
    """

    assert len(raw) == len(repl)
    forgery = bytes([x ^ y for x, y in zip(raw, repl)])
    forgery = bytes([x ^ y for x, y in zip(data[pos : pos + len(raw)], forgery)])

    data = data[:pos] + forgery + data[pos + len(raw) :]

    return data


def chall16_encrypt(data: bytearray) -> bytearray:
    global KEY, IV
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    data = pkcs7_pad(prefix + data.replace(b"=", b"").replace(b";", b"") + suffix, 16)
    return aes_cbc_encrypt(data=data, random=False, key=KEY, iv=IV)


def chall16_decrypt(data: bytearray) -> bytearray:
    global KEY, IV
    return pkcs7_unpad(aes_cbc_decrypt(data=data, key=KEY, iv=IV), 16)


def chall16_check(ciphertext: bytearray) -> bool:
    plaintext = chall16_decrypt(ciphertext)
    if b"admin=true" in plaintext.split(b";"):
        return True
    return False


def main():
    payload = b"a" * 16
    repl = b";admin=true;"
    raw = payload[: len(repl)]
    ct = chall16_encrypt(payload)
    forgery = bit_flipping(ct, 16, raw, repl)
    print(chall16_check(forgery))


if __name__ == "__main__":
    main()
