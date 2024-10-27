'''GUI界面'''
import tkinter as tk
from tkinter import messagebox
from S_AES import encrypt, decrypt, encrypt_ascii, decrypt_ascii
import numpy as np
from double import double_encrypt, double_decrypt
from attack import find_key_from_intermediates
from CBC_work import s_aes_cbc_encrypt, s_aes_cbc_decrypt
from triple import triple_decrypt, triple_encrypt

window = tk.Tk()
window.title('欢迎使用S_AES')
window.geometry = ('800x800')

# 设置字体样式
title_font = ("Microsoft YaHei", 16, "bold")
label_font = ("Microsoft YaHei", 12)
button_font = ("Microsoft YaHei", 12, "bold")
result_font = ("Microsoft YaHei", 12, "italic")

main_frame = tk.Frame(window)
main_frame.grid(row=0, column=0, padx=10, pady=10)

# 显示主页
def show_home():
    for widget in main_frame.winfo_children():
        widget.destroy()  # 清空当前页面
    tk.Label(main_frame, text="请选择操作模式：", font=title_font).grid(row=0, column=0, columnspan=2, pady=20)
    
    ascii_button = tk.Button(main_frame, text="二进制加密/解密", width=20, font=button_font, command=show_binary_mode)
    ascii_button.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

    binary_button = tk.Button(main_frame, text="ASCII加密/解密", width=20, font=button_font, command=show_ascii_mode)
    binary_button.grid(row=1, column=1, padx=20, pady=10, sticky="ew")

    expand_button = tk.Button(main_frame, text="多重加密/解密", width=20, font=button_font, command=show_expand_mode)
    expand_button.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
    
    work_button = tk.Button(main_frame, text="工作模式", width=20, font=button_font, command=show_work_mode)
    work_button.grid(row=2, column=1, padx=20, pady=10, sticky="ew")

# ascii界面
def show_ascii_mode():
    for widget in main_frame.winfo_children():
        widget.destroy()
    tk.Label(main_frame, text="输入ASCII编码字符串：", width=20, font=label_font).grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font)
    text_entry.grid(row=0, column=1, padx=10)
    
    tk.Label(main_frame, text="输入 16 位密钥：", font=label_font).grid(row=1, column=0, pady=10)
    key_entry = tk.Entry(main_frame, font=label_font)
    key_entry.grid(row=1, column=1, padx=10)
    
    res_label = tk.Label(main_frame, text="加密结果为：", font=result_font)
    res_label.grid(row=3, columnspan=2, pady=10)
    
    
    def encrypt_ascii_action():
        # 获取明文和密钥
        plaintext = text_entry.get()
        key = key_entry.get()
        
        if len(key) != 16:
            messagebox.showerror('错误', '密钥的长度必须为16位')
        
        key = int(key, 2)
                
        res = encrypt_ascii(plaintext, key)
        res_label.config(text=f"加密后的ASCII密文：{res[0]}")
        
    def decrypt_ascii_action():
        # 获取密文和密钥
        plaintext = text_entry.get()
        key = key_entry.get()
        
        if len(key) != 16:
            messagebox.showerror('错误', '密钥的长度必须为16位')
        plaintext = [np.int32(plaintext)]
        key = int(key, 2)

        res = decrypt_ascii(plaintext, key)
        res_label.config(text=f"解密后的ASCII密文：{res}")
        
    tk.Button(main_frame, text="加密", font=button_font, width=10, command=encrypt_ascii_action).grid(row=2, column=0, padx=20, pady=10, sticky="ew")
    tk.Button(main_frame, text="解密", font=button_font, width=10, command=decrypt_ascii_action).grid(row=2, column=1, padx=20, pady=10, sticky="ew")
    tk.Button(main_frame, text="返回主页", font=button_font, command=show_home).grid(row=4, columnspan=2, pady=10, sticky="ew")

# 二进制界面
def show_binary_mode():
    for widget in main_frame.winfo_children():
        widget.destroy()
        
    tk.Label(main_frame, text="输入 16 位明文或密文：", width=20, font=label_font).grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font)
    text_entry.grid(row=0, column=1, padx=10)
    
    tk.Label(main_frame, text="输入 16 位密钥：", font=label_font).grid(row=1, column=0, pady=10)
    key_entry = tk.Entry(main_frame, font=label_font)
    key_entry.grid(row=1, column=1, padx=10)
    
    res_label = tk.Label(main_frame, text="加密结果为：", font=result_font)
    res_label.grid(row=3, columnspan=2, pady=10)
    def encrypt_binary_action():
        # 获取明文和密钥
        plaintext = text_entry.get()
        key = key_entry.get()
        
        if len(key) != 16 or len(plaintext) != 16:
            messagebox.showerror('错误', '密钥或明文必须是16位二进制！')
            return
        
        plaintext, key = int(plaintext, 2), int(key, 2)
        
        res = encrypt(plaintext, key)
        res_label.config(text=f"加密后的二进制密文：{res:016b}")
        
    def decrypt_binary_action():
        # 获取密文和密钥
        plaintext = text_entry.get()
        key = key_entry.get()
        
        if len(key) != 16 or len(plaintext) != 16:
            messagebox.showerror('错误', '密钥或密文必须是16位二进制！')
            return
        
        plaintext, key = int(plaintext, 2), int(key, 2)
        
        res = decrypt(plaintext, key)
        res_label.config(text=f"解密后的二进制明文：{res:016b}")
        
    tk.Button(main_frame, text="加密", font=button_font, command=encrypt_binary_action).grid(row=2, column=0, padx=10, pady=10, sticky="ew")
    tk.Button(main_frame, text="解密", font=button_font, command=decrypt_binary_action).grid(row=2, column=1, padx=10, pady=10, sticky="ew")
    tk.Button(main_frame, text="返回主页", font=button_font, command=show_home).grid(row=4, columnspan=2, pady=10, sticky="ew")

# 多重加密界面
def show_expand_mode():
    for widget in main_frame.winfo_children():
        widget.destroy()  
    # 布局按钮
    tk.Label(main_frame, text="请选择多重加密模式", font=title_font).grid(row=0, column=0, columnspan=2, pady=20)
    double_encrypt_button = tk.Button(main_frame, text="双重加密", width=20, font=button_font, command=show_double_encrypt)
    double_encrypt_button.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
    attack_button = tk.Button(main_frame, text="中间相遇攻击", width=20, font=button_font, command=show_attack)
    attack_button.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
    triple_encrypt_button = tk.Button(main_frame, text="三重加密", width=20, font=button_font, command=show_triple_encrypt)
    triple_encrypt_button.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
    back_home = tk.Button(main_frame, text="返回主页", width=20, font=button_font, command=show_home)
    back_home.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
    
# 双重加密界面
def show_double_encrypt():
    for widget in main_frame.winfo_children():
        widget.destroy()
        
    tk.Label(main_frame, text="输入 16 位明文或密文：", width=20, font=label_font).grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font, width=20)
    text_entry.grid(row=0, column=1, padx=10)
    
    tk.Label(main_frame, text="输入 32 位密钥：", font=label_font).grid(row=1, column=0, columnspan=2, pady=10)
    key_entry = tk.Entry(main_frame, font=label_font, width=40)
    key_entry.grid(row=2, column=0, columnspan=2, padx=10)
    
    res_label = tk.Label(main_frame, text="加密结果为：", font=result_font)
    res_label.grid(row=4, columnspan=2, pady=10)
    
    def encrypt_double_action():
        # 获取明文和密钥
        plaintext = text_entry.get()
        key = key_entry.get()
        
        if len(key) != 32:
            messagebox.showerror('错误', '密钥必须是32位二进制！')
            return
        
        if len(plaintext) != 16:
            messagebox.showerror('错误', '明文必须是16位二进制！')
            return
        
        key1 = key[:15]
        key2 = key[16:]
        
        plaintext, key1, key2 = int(plaintext, 2), int(key1, 2), int(key2, 2)
        
        res = double_encrypt(plaintext, key1, key2)
        res_label.config(text=f"加密后的二进制密文：{res:016b}")
        
    def decrypt_double_action():
        # 获取密文和密钥
        plaintext = text_entry.get()
        key = key_entry.get()
        
        if len(key) != 32:
            messagebox.showerror('错误', '密钥必须是32位二进制！')
            return
        
        if len(plaintext) != 16:
            messagebox.showerror('错误', '密文必须是16位二进制！')
            return
        
        key1 = key[:15]
        key2 = key[16:]
        
        plaintext, key1, key2 = int(plaintext, 2), int(key1, 2), int(key2, 2)
        
        res = double_decrypt(plaintext, key1, key2)
        res_label.config(text=f"解密后的二进制明文：{res:016b}")
        
    tk.Button(main_frame, text="加密", font=button_font, command=encrypt_double_action).grid(row=3, column=0, padx=10, pady=10, sticky="ew")
    tk.Button(main_frame, text="解密", font=button_font, command=decrypt_double_action).grid(row=3, column=1, padx=10, pady=10, sticky="ew")
    tk.Button(main_frame, text="返回主页", font=button_font, command=show_home).grid(row=5, columnspan=2, pady=10, sticky="ew")

# 中间相遇攻击
def show_attack():
    for widget in main_frame.winfo_children():
        widget.destroy()
        
    tk.Label(main_frame, text="输入两对 16 位明文", width=20, font=label_font).grid(row=0, rowspan=2, column=0)
    text_entry1 = tk.Entry(main_frame, font=label_font, width=20)
    text_entry1.grid(row=0, column=1, padx=10, pady=5)
    text_entry1_ = tk.Entry(main_frame, font=label_font, width=20)
    text_entry1_.grid(row=1, column=1, padx=10, pady=5)
    tk.Label(main_frame, text="输入两对 16 位密文", width=20, font=label_font).grid(row=2, rowspan=2, column=0)
    text_entry2 = tk.Entry(main_frame, text="key1", font=label_font, width=20)
    text_entry2.grid(row=2, column=1, padx=10, pady=5)
    text_entry2_ = tk.Entry(main_frame, font=label_font, width=20)
    text_entry2_.grid(row=3, column=1, padx=10, pady=5)
    res_label = tk.Label(main_frame, text="破解结果为", font=result_font)
    res_label.grid(row=5, columnspan=2, pady=10)
    def attack():
        plaintext1 = text_entry1.get()
        plaintext2 = text_entry1_.get()
        ciphertext1 = text_entry2.get()
        ciphertext2 = text_entry2_.get()
        plaintext = [plaintext1, plaintext2]
        ciphertext = [ciphertext1, ciphertext2]
        key_candidates = find_key_from_intermediates(plaintext, ciphertext)
        res_label.config(text=f"找到密钥：{key_candidates[0][2:]}")
        
    
    tk.Button(main_frame, text="获取key1和key2", font=button_font, command=attack).grid(row=4, column=0, padx=10, pady=10, columnspan=2, sticky="ew")
    
    back_home = tk.Button(main_frame, text="返回主页", width=20, font=button_font, command=show_home)
    back_home.grid(row=8, column=0, padx=20, pady=10, sticky="ew", columnspan=2)
    
# 三重加密
def show_triple_encrypt():
    for widget in main_frame.winfo_children():
        widget.destroy()
        
    tk.Label(main_frame, text="输入 16 位明文或密文：", width=20, font=label_font).grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font, width=20)
    text_entry.grid(row=0, column=1, padx=10)
    
    tk.Label(main_frame, text="输入 3 个 16 位密钥", font=label_font).grid(row=1, column=0, columnspan=2, pady=10)
    tk.Label(main_frame, text="key1：", width=20, font=label_font).grid(row=2, column=0, pady=10)
    key_entry1 = tk.Entry(main_frame, font=label_font, width=20)
    key_entry1.grid(row=2, column=1,  padx=10)
    tk.Label(main_frame, text="key2：", width=20, font=label_font).grid(row=3, column=0, pady=10)
    key_entry2 = tk.Entry(main_frame, font=label_font, width=20)
    key_entry2.grid(row=3, column=1,  padx=10)
    tk.Label(main_frame, text="key3：", width=20, font=label_font).grid(row=4, column=0, pady=10)
    key_entry3 = tk.Entry(main_frame, font=label_font, width=20)
    key_entry3.grid(row=4, column=1,  padx=10)
    
    res_label = tk.Label(main_frame, text="加密结果为：", font=result_font)
    res_label.grid(row=5, columnspan=2, pady=10)
    
    def encrypt_triple_action():
        # 获取明文和密钥
        plaintext = text_entry.get()
        key1 = key_entry1.get()
        key2= key_entry2.get()
        key3 = key_entry3.get()
        
        key = key1 + key2 + key3
        
        if len(key) != 48:
            messagebox.showerror('错误', '密钥必须是32位二进制！')
            return
        
        if len(plaintext) != 16:
            messagebox.showerror('错误', '明文必须是16位二进制！')
            return
        
        key1 = key[:15]
        key2 = key[16:31]
        key3 = key[32:]
        
        plaintext, key1, key2, key3 = int(plaintext, 2), int(key1, 2), int(key2, 2), int(key3, 2)        
        res = triple_encrypt(plaintext, key1, key2, key3)
        res_label.config(text=f"加密后的二进制密文：{res:016b}")
        
    def decrypt_triple_action():
        # 获取密文和密钥
        plaintext = text_entry.get()
        key1 = key_entry1.get()
        key2= key_entry2.get()
        key3 = key_entry3.get()
        
        key = key1 + key2 + key3
        
        if len(key) != 48:
            messagebox.showerror('错误', '密钥必须是48位二进制！')
            return
        
        if len(plaintext) != 16:
            messagebox.showerror('错误', '密文必须是16位二进制！')
            return
        
        key1 = key[:15]
        key2 = key[16:31]
        key3 = key[32:]
        
        
        plaintext, key1, key2, key3 = int(plaintext, 2), int(key1, 2), int(key2, 2), int(key3, 2)
        
        res = triple_decrypt(plaintext, key1, key2, key3)
        res_label.config(text=f"解密后的二进制明文：{res:016b}")
        
    tk.Button(main_frame, text="加密", font=button_font, command=encrypt_triple_action).grid(row=6, column=0, padx=10, pady=10, sticky="ew")
    tk.Button(main_frame, text="解密", font=button_font, command=decrypt_triple_action).grid(row=6, column=1, padx=10, pady=10, sticky="ew")
    tk.Button(main_frame, text="返回主页", font=button_font, command=show_home).grid(row=7, columnspan=2, pady=10, sticky="ew")

# 工作模式
def show_work_mode():
    for widget in main_frame.winfo_children():
        widget.destroy()
        
    tk.Label(main_frame, text="在右侧输入 16 位密钥：", width=25, font=label_font).grid(row=0, column=0, pady=10)
    text_entry = tk.Entry(main_frame, font=label_font)
    text_entry.grid(row=0, column=1, padx=10)
    
    tk.Label(main_frame, text="在下方输入长密文（16整数倍）：", font=label_font).grid(row=1, columnspan=2, pady=10)
    text_entry1 = tk.Entry(main_frame, width=50, font=label_font)
    text_entry1.grid(row=2, columnspan=2, padx=10)
    def work():
        key = text_entry.get()
        plaintext = text_entry1.get()
        key = int(key, 2)
        plaintext = int(plaintext, 2)
        iv, cipher_text = s_aes_cbc_encrypt(plaintext, key)
        res_label.config(text=f'初始向量 (IV): {str(bin(iv))[:2]}')
        res_label1.config(text=f'加密后的密文: {[bin(c) for c in cipher_text]}')
        # 修改密文的一个分组
        tampered_cipher_text = cipher_text[:]
        tampered_cipher_text[1] ^= 0b1111111111111111 

        # 解密篡改前后的密文
        decrypted_text_original = s_aes_cbc_decrypt(cipher_text, key, iv)
        decrypted_text_tampered = s_aes_cbc_decrypt(tampered_cipher_text, key, iv)
        
        res_label2.config(text=f'解密原密文结果: {str(bin(decrypted_text_original))[3:]}')
        res_label3.config(text=f'解密篡改密文结果: {str(bin(decrypted_text_tampered))[3:]}')
    tk.Button(main_frame, text="加密",width=50, font=button_font, command=work).grid(row=3, columnspan=2, padx=10, pady=10, sticky="ew")
    
    res_label = tk.Label(main_frame, text="初始向量 (IV): ", font=result_font)
    res_label.grid(row=4, columnspan=2, pady=10)
    res_label1 = tk.Label(main_frame, text="加密后的密文: ", font=result_font)
    res_label1.grid(row=5, columnspan=2, pady=10)
    res_label2 = tk.Label(main_frame, text="解密原密文结果: ", font=result_font)
    res_label2.grid(row=6, columnspan=2, pady=10)
    res_label3 = tk.Label(main_frame, text="解密篡改密文结果: ", font=result_font)
    res_label3.grid(row=7, columnspan=2, pady=10)

# 开启主循环
show_home()
window.mainloop()
