"""三重加密"""
from S_AES import encrypt, decrypt

# 三重加密函数
def triple_encrypt(plaintext, key1, key2, key3):
    # 第一次加密
    first_encryption = encrypt(plaintext, key1)
    # 第二次加密
    second_encryption = encrypt(first_encryption, key2)
    # 第三次加密
    third_encryption = encrypt(second_encryption, key3)
    return third_encryption

# 三重解密函数
def triple_decrypt(ciphertext, key1, key2, key3):
    # 第一次解密
    first_decryption = decrypt(ciphertext, key3)
    # 第二次解密
    second_decryption = decrypt(first_decryption, key2)
    # 第三次解密
    thrid_decryption = decrypt(second_decryption, key1)
    return thrid_decryption