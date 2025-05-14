import sys, os

path = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
)

if sys.path[1] != path:
    sys.path.insert(1, path)


from utils.functions import *


def parsing_uri(uri: str) -> dict:
    """
    - params:
        uri: encoded string in form '<key>=<value>[&<key>=<value>]*'
    - return:
        a dictionary {key: value}
    """
    uri = uri.split("&")
    return dict([token.split("=") for token in uri])


def encode_cookie(cookie: dict) -> str:
    """
    - params:
        cookie: a dictionary {key: value}
    - return:
        a string in form '<key>=<value>[&<key>=<value>]*'
    """
    return "&".join([f"{k}={v}" for k, v in cookie.items()])


def profile_for(email: str) -> str:
    """
    - params:
        email: normal email
    - return:
        information in form 'email=email&uid=10&role=user'
    """
    cookie = {
        "email": email.replace("&", "").replace("=", ""),
        "uid": 10,
        "role": "user",
    }
    return encode_cookie(cookie=cookie)


def chall13_ecb_encrypt(data: bytearray) -> bytearray:
    global KEY
    return aes_ecb_encrypt(data, random=False, key=KEY)


def chall13_ecb_decrypt(data: bytearray) -> bytearray:
    global KEY
    cipher = AES.new(key=KEY, mode=AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(data), 16)


def aes_cut_and_paste(encryptor, decryptor) -> bytearray:
    """
    - params:
        encryptor: the oracle encryption function
        decryptor: the oracle decryption function
    - return:
        fake account ciphertext
    """
    email = (16 - len(b"email=")) * b"a"
    admin = pkcs7_pad(b"admin", 16)
    suff = b"a" * (16 - len(b"&uid=10&role="))
    payload = email + admin + suff
    ct = encryptor(profile_for(payload.decode()).encode())
    admin = ct[16:32]
    ct = ct[:-16] + admin
    assert decryptor(ct)
    return ct


def main():
    print(aes_cut_and_paste(chall13_ecb_encrypt, chall13_ecb_decrypt))


if __name__ == "__main__":
    main()
