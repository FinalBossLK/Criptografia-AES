import tkinter as tk
from tkinter import scrolledtext, messagebox
import pyperclip
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_AES(key, plaintext):
    # Gerar um vetor de inicialização (IV) aleatório
    iv = os.urandom(16)

    # Criar um objeto AES com a chave fornecida e o modo de operação CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Criar um objeto de preenchimento
    padder = padding.PKCS7(128).padder()

    # Adicionar preenchimento ao texto plano
    plaintext = padder.update(plaintext) + padder.finalize()

    # Criptografar o texto plano
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return iv + ciphertext

def decrypt_AES(key, ciphertext):
    # Extrair o vetor de inicialização (IV) do início do texto cifrado
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Criar um objeto AES com a chave fornecida e o modo de operação CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Descriptografar o texto cifrado
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remover o preenchimento
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(plaintext) + unpadder.finalize()

    return plaintext

def encrypt_message():
    key = os.urandom(32)
    plaintext = input_text.get("1.0", "end-1c").encode()
    ciphertext = encrypt_AES(key, plaintext)
    key_text.delete("1.0", "end")
    key_text.insert("1.0", key.hex())
    output_text.delete("1.0", "end")
    output_text.insert("1.0", ciphertext.hex())

def decrypt_message():
    key = bytes.fromhex(key_text.get("1.0", "end-1c"))
    ciphertext = bytes.fromhex(output_text.get("1.0", "end-1c"))
    decrypted_text = decrypt_AES(key, ciphertext)
    decrypted_text = decrypted_text.decode()
    decrypted_text = decrypted_text.strip("\x00")
    input_text.delete("1.0", "end")
    input_text.insert("1.0", decrypted_text)

def copy_key():
    key = key_text.get("1.0", "end-1c")
    pyperclip.copy(key)

def copy_ciphertext():
    ciphertext = output_text.get("1.0", "end-1c")
    pyperclip.copy(ciphertext)

# Configuração da interface gráfica
root = tk.Tk()
root.title("Criptografia AES")

# Texto de entrada
input_text = scrolledtext.ScrolledText(root, width=50, height=10)
input_text.pack(pady=10)

# Botão de criptografia
encrypt_button = tk.Button(root, text="Criptografar Mensagem", command=encrypt_message)
encrypt_button.pack(pady=5)

# Chave gerada
key_text = scrolledtext.ScrolledText(root, width=50, height=3)
key_text.pack(pady=10)

# Mensagem criptografada
output_text = scrolledtext.ScrolledText(root, width=50, height=10)
output_text.pack(pady=10)

# Botão de descriptografia
decrypt_button = tk.Button(root, text="Descriptografar Mensagem", command=decrypt_message)
decrypt_button.pack(pady=5)

# Botão para copiar a chave
copy_key_button = tk.Button(root, text="Copiar Chave", command=copy_key)
copy_key_button.pack(pady=5)

# Botão para copiar o texto criptografado
copy_ciphertext_button = tk.Button(root, text="Copiar Texto Criptografado", command=copy_ciphertext)
copy_ciphertext_button.pack(pady=5)

root.mainloop()
