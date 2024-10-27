'''双重加密'''
from S_AES import encrypt, decrypt

# 双重加密函数
def double_encrypt(plaintext, key1, key2):
    # 第一次加密
    first_encryption = encrypt(plaintext, key1)
    # 第二次加密
    second_encryption = encrypt(first_encryption, key2)
    return second_encryption

# 双重解密函数
def double_decrypt(ciphertext, key1, key2):
    # 第一次解密
    first_decryption = decrypt(ciphertext, key2)
    # 第二次解密
    second_decryption = decrypt(first_decryption, key1)
    return second_decryption

