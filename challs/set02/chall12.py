import sys, os

path = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
)

if sys.path[1] != path:
    sys.path.insert(1, path)


from utils.functions import *
import string


def chall12_ecb_encrypt(data: bytearray) -> bytearray:
    """
    - params:
        data: plaintext
    - return:
        encrypted ciphertext of (data + raw) in ecb mode
    """
    global KEY, RAW
    return aes_ecb_encrypt(data=data + RAW, random=False, key=KEY)


def aes_ecb_byte_at_a_time(oracle) -> bytearray:
    """
    - params:
        oracle: the encryption oracle function
    - return:
        hidden plaintext of oracle
    """
    l1 = len(oracle(b"a"))
    res = b""
    doms = string.printable
    for i in range(l1):
        p1 = (l1 - i - 1) * b"a"
        ct = oracle(p1)[:l1]
        for c in doms:
            p2 = (l1 - i - 1) * b"a" + res + c.encode()
            if oracle(p2)[:l1] == ct:
                res += c.encode()
                break
    return res


def main():
    print(aes_ecb_byte_at_a_time(chall12_ecb_encrypt))


if __name__ == "__main__":
    main()
