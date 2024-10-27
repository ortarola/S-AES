from S_AES import encrypt

def find_key_from_intermediates(plaintexts, ciphertexts):
    key_candidates = []  

    # 遍历所有明文和密文组合
    for i in range(len(plaintexts)):
        for j in range(len(plaintexts)):
            if i != j:
                plaintext1 = int(plaintexts[i], 2)
                ciphertext1 = int(ciphertexts[i], 2)
                plaintext2 = int(plaintexts[j], 2)
                ciphertext2 = int(ciphertexts[j], 2)
                # 穷举 key1 使得它能将 plaintext1 加密成 ciphertext1
                for key1 in range(0x0000, 0xFFFF + 1):
                    if encrypt(plaintext1, key1) == ciphertext1:
                        # 穷举 key2 使得它能将 plaintext2 加密成 ciphertext2
                        for key2 in range(0x0000, 0xFFFF + 1):
                            if encrypt(plaintext2, key2) == ciphertext2:
                                full_key = (key1 << 16) | key2   
                                key_candidates.append(bin(full_key))
        return key_candidates

def test_find_key_from_intermediates():
    plaintexts=['1010001110110000', '0000011010101011']
    bin_ciphertexts=['1001100101100101', '1100011110100100']
    
    key_candidates = find_key_from_intermediates(plaintexts, bin_ciphertexts)
    
    print("候选密钥列表:", key_candidates)

test_find_key_from_intermediates()
