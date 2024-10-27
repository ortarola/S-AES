import random

from S_AES import encrypt, decrypt

def xor_bits(bits1, bits2):
    return bits1 ^ bits2

# 生成16位随机初始向量
def generate_iv():
    return random.randint(0, 2**16 - 1)

# 使用CBC模式的S-AES加密
def s_aes_cbc_encrypt(plaintext, key):
    # 将明文分成16位的分组
    blocks = [(plaintext >> (16 * i)) & 0xFFFF for i in range((len(bin(plaintext)) - 2 + 15) // 16)][::-1]
    iv = generate_iv()
    cipher_text = []
    previous_cipher_block = iv

    # 每个分组分别加密
    for block in blocks:
        xor_block = xor_bits(block, previous_cipher_block)
        cipher_block = encrypt(xor_block, key)
        cipher_text.append(cipher_block)
        previous_cipher_block = cipher_block  # 更新前一密文分组

    # 返回初始向量和加密后的密文分组
    return iv, cipher_text

# 使用CBC模式的S-AES解密
def s_aes_cbc_decrypt(ciphertext, key, iv):

    plain_text = 0
    previous_cipher_block = iv

    # 每个分组分别解密
    for i, block in enumerate(ciphertext):
        decrypted_block = decrypt(block, key)
        plain_text_block = xor_bits(decrypted_block, previous_cipher_block)
        plain_text = (plain_text << 16) | plain_text_block  # 合并解密后的分组
        previous_cipher_block = block  # 更新前一密文分组

    return plain_text

def test():
    key = 0b1010011100111011  
    plaintext = int("1101011100101000" * 3, 2)  

    # 加密过程
    iv, cipher_text = s_aes_cbc_encrypt(plaintext, key)
    print("初始向量 (IV):", bin(iv))
    print("加密后的密文:", [bin(c) for c in cipher_text])

    # 修改密文的一个分组
    tampered_cipher_text = cipher_text[:]
    tampered_cipher_text[1] ^= 0b1111111111111111 

    # 解密篡改前后的密文
    decrypted_text_original = s_aes_cbc_decrypt(cipher_text, key, iv)
    decrypted_text_tampered = s_aes_cbc_decrypt(tampered_cipher_text, key, iv)

    print("\n解密原密文结果:", bin(decrypted_text_original))
    print("解密篡改密文结果:", bin(decrypted_text_tampered))

test()