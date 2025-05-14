import sys, os

path = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
)

if sys.path[1] != path:
    sys.path.insert(1, path)


from utils.functions import *


def aes_oracle(data: bytearray) -> bytearray:
    """
    - params:
        data: plaintext
    - return:
        ciphertext encrypted in random mode aes-cbc or aes-ecb with 16-byte block
    """
    mode = random.randint(0, 1)
    key = get_random_bytes(16)
    match mode:
        case 0:
            cipher = AES.new(key=key, mode=AES.MODE_ECB)
        case 1:
            iv = get_random_bytes(16)
            cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    data = (
        get_random_bytes(random.randint(5, 10))
        + data
        + get_random_bytes(random.randint(5, 10))
    )
    data = pkcs7_pad(data=data, b_size=16)
    return cipher.encrypt(data)


def aes_mode_detection(oracle, plaintext: bytearray) -> dict:
    """
    - params:
        oracle: the encryption oracle function
        plaintext: raw data
    - return:
        ciphertext and predicted aes mode
    """
    payload = b"a" * 64 + plaintext
    ct = oracle(payload)
    if ct[16:32] == ct[32:48]:
        return {"plaintext": payload, "ciphertext": ct.hex(), "predicted": "AES-ECB"}
    return {"plaintext": payload, "ciphertext": ct.hex(), "predicted": "AES-CBC"}


def main():
    print(aes_mode_detection())


if __name__ == "__main__":
    main()
