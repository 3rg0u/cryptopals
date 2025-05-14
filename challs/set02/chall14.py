import sys, os

path = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
)

if sys.path[1] != path:
    sys.path.insert(1, path)

from utils.functions import *
import string


def chall14_ecb_encrypt(data: bytearray) -> bytearray:
    global KEY, PREFIX, RAW
    return aes_ecb_encrypt(data=PREFIX + data + RAW, random=False, key=KEY)


def aes_ecb_byte_at_a_time_ver_2(oracle) -> bytearray:
    """
    - params:
        oracle: the encryption oracle function
    - return:
        hidden plaintext of oracle
    """
    doms = string.printable
    l = len(oracle(b"a"))
    barrier = l + 32
    cnt = 2
    while l < barrier:
        l = len(oracle(cnt * b"a"))
        cnt += 1
    ct = oracle((cnt - 1) * b"a")
    while ct[barrier - 32 : barrier - 16] != ct[barrier - 16 : barrier]:
        ct = oracle(cnt * b"a")
        cnt += 1
    ct_len = len(ct[barrier:])
    pay_len = cnt - 1 + ct_len
    res = b""
    for i in range(ct_len):
        p1 = (pay_len - i - 1) * b"a"
        ref = oracle(p1)[barrier : barrier + ct_len]
        for c in doms:
            p2 = (pay_len - i - 1) * b"a" + res + c.encode()
            if oracle(p2)[barrier : barrier + ct_len] == ref:
                res += c.encode()
                break
    return res


def main():
    print(aes_ecb_byte_at_a_time_ver_2(chall14_ecb_encrypt))


if __name__ == "__main__":
    main()
