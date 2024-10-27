'''基本算法'''
import numpy as np

# 添加轮密钥
def add_round_key(state, key):
    return np.bitwise_xor(state, key)

# S盒替换
def s_box(nibble):
    sbox = [
        0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7
    ]
    return sbox[nibble]

# 逆S盒替换
def inverse_s_box(nibble):
    inv_sbox = [
        0xA, 0x5, 0x9, 0xB,
        0x1, 0x7, 0x8, 0xF,
        0x6, 0x0, 0x2, 0x3,
        0xC, 0x4, 0xD, 0xE
    ]
    return inv_sbox[nibble]

# S盒层
def s_box_layer(state):
    return [s_box(n) for n in state]

# 逆S盒层
def inverse_s_box_layer(state):
    return [inverse_s_box(n) for n in state]

# 行移位
def shift_rows(state):
    return [state[0], state[1], state[3], state[2]]

# 逆行移位
def inverse_shift_rows(state):
    return [state[0], state[1], state[3], state[2]]

# 列混合
def mix_columns(state):
    return [
        state[0] ^ state[2], state[1] ^ state[3],
        state[2], state[3]
    ]

# 逆列混合
def inverse_mix_columns(state):
    return [
        state[0] ^ state[2], state[1] ^ state[3],
        state[2], state[3]
    ]

# 密钥扩展
def key_expansion(key):
    rcon1, rcon2 = 0b10000000, 0b00110000
    w = [key >> 8, key & 0xFF]
    w.append(w[0] ^ rcon1 ^ s_box(w[1] >> 4) << 4 | s_box(w[1] & 0xF))
    w.append(w[2] ^ w[1])
    w.append(w[2] ^ rcon2 ^ s_box(w[3] >> 4) << 4 | s_box(w[3] & 0xF))
    w.append(w[4] ^ w[3])
    return w

# 加密过程
def encrypt(plaintext, key):
    state = [(plaintext >> i) & 0xF for i in (12, 8, 4, 0)]
    round_keys = key_expansion(key)
    state = add_round_key(state, [(round_keys[0] >> 4) & 0xF, round_keys[0] & 0xF, (round_keys[1] >> 4) & 0xF, round_keys[1] & 0xF])
    state = s_box_layer(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, [(round_keys[2] >> 4) & 0xF, round_keys[2] & 0xF, (round_keys[3] >> 4) & 0xF, round_keys[3] & 0xF])
    state = s_box_layer(state)
    state = shift_rows(state)
    state = add_round_key(state, [(round_keys[4] >> 4) & 0xF, round_keys[4] & 0xF, (round_keys[5] >> 4) & 0xF, round_keys[5] & 0xF])
    ciphertext = (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]
    return ciphertext

# 解密过程
def decrypt(ciphertext, key):
    state = [(ciphertext >> i) & 0xF for i in (12, 8, 4, 0)]
    round_keys = key_expansion(key)
    state = add_round_key(state, [(round_keys[4] >> 4) & 0xF, round_keys[4] & 0xF, (round_keys[5] >> 4) & 0xF, round_keys[5] & 0xF])
    state = inverse_shift_rows(state)
    state = inverse_s_box_layer(state)
    state = add_round_key(state, [(round_keys[2] >> 4) & 0xF, round_keys[2] & 0xF, (round_keys[3] >> 4) & 0xF, round_keys[3] & 0xF])
    state = inverse_mix_columns(state)
    state = inverse_shift_rows(state)
    state = inverse_s_box_layer(state)
    state = add_round_key(state, [(round_keys[0] >> 4) & 0xF, round_keys[0] & 0xF, (round_keys[1] >> 4) & 0xF, round_keys[1] & 0xF])
    plaintext = (state[0] << 12) | (state[1] << 8) | (state[2] << 4) | state[3]
    return plaintext

# 将字符串转换为二进制列表
def str_to_bin_list(input_str):
    bin_list = []
    for char in input_str:
        bin_list.append(format(ord(char), '08b'))
    return bin_list

# 将二进制列表转换为字符串
def bin_list_to_str(bin_list):
    output_str = ""
    for bin_value in bin_list:
        output_str += chr(int(bin_value, 2))
    return output_str

# 加密ASCII字符串
def encrypt_ascii(plaintext_str, key):
    ciphertext = []
    for i in range(0, len(plaintext_str), 2):
        block = plaintext_str[i:i+2].ljust(2, '\x00')  # 每次取2字节，不足补0
        plaintext = int.from_bytes(block.encode('ascii'), 'big')
        ciphertext_block = encrypt(plaintext, key)
        ciphertext.append(ciphertext_block)
    return ciphertext

# 解密ASCII字符串
def decrypt_ascii(ciphertext_blocks, key):
    plaintext_str = ""
    for block in ciphertext_blocks:
        plaintext_block = int(decrypt(block, key))  
        plaintext_str += plaintext_block.to_bytes(2, 'big').decode('ascii', errors='ignore')
    return plaintext_str

# 测试函数
def test_encryption_decryption():
    # 定义测试数据
    plaintext_str = "HelloAES"  # 明文字符串
    key = 0b1010101010101010   # 16位密钥
    
    # 加密
    print(f"原始明文: {plaintext_str}")
    ciphertext_blocks = encrypt_ascii(plaintext_str, key)
    print(f"加密后的密文块: {ciphertext_blocks}")
    
    # 解密
    decrypted_str = decrypt_ascii(ciphertext_blocks, key)
    print(f"解密后的明文: {decrypted_str}")
    
    # 验证结果
    if plaintext_str == decrypted_str:
        print("加密和解密成功!")
    else:
        print("加密或解密失败!")

# test_encryption_decryption()