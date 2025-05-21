import streamlit as st
from Crypto.Cipher import AES, DES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from cryptography.fernet import Fernet
import hashlib
import base64
import os

# Helper functions

def pad(data, block_size):
    padding_len = block_size - len(data) % block_size
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def save_file(content):
    with open("temp_file", "wb") as f:
        f.write(content)
    return "temp_file"

# AES

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(enc_data, key):
    raw = base64.b64decode(enc_data)
    iv = raw[:AES.block_size]
    ct = raw[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))

# DES

def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def des_decrypt(enc_data, key):
    raw = base64.b64decode(enc_data)
    iv = raw[:DES.block_size]
    ct = raw[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))

# 3DES

def triple_des_encrypt(data, key):
    cipher = DES3.new(key, DES3.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, DES3.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def triple_des_decrypt(enc_data, key):
    raw = base64.b64decode(enc_data)
    iv = raw[:DES3.block_size]
    ct = raw[DES3.block_size:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct))

# RSA
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey()
private_key = rsa_key

rsa_cipher = PKCS1_OAEP.new(public_key)
rsa_decipher = PKCS1_OAEP.new(private_key)

def rsa_encrypt(data):
    return base64.b64encode(rsa_cipher.encrypt(data)).decode()

def rsa_decrypt(enc_data):
    return rsa_decipher.decrypt(base64.b64decode(enc_data))

# DSA (Signature only)
dsa_key = DSA.generate(2048)
dsa_signer = DSS.new(dsa_key, 'fips-186-3')
dsa_verifier = DSS.new(dsa_key.publickey(), 'fips-186-3')

def dsa_sign(data):
    h = SHA256.new(data)
    return base64.b64encode(dsa_signer.sign(h)).decode()

def dsa_verify(data, signature):
    h = SHA256.new(data)
    try:
        dsa_verifier.verify(h, base64.b64decode(signature))
        return "Signature valid"
    except ValueError:
        return "Signature invalid"

# Diffie-Hellman (simplified key exchange simulation)
def diffie_hellman_key():
    private = get_random_bytes(16)
    public = base64.b64encode(private).decode()
    return public

# Hashing

def hash_data(data, algo):
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()

# Streamlit UI

st.set_page_config(page_title="Applied Cryptography Application")
st.title("🔐 Applied Cryptography Application")
menu = ["Home", "Symmetric Encryption", "Asymmetric Encryption", "Hashing", "Algorithm Info"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.markdown("""
    ### Welcome
    This app demonstrates the use of **cryptographic algorithms** to secure text and files. 
    Navigate through the sidebar to try encryption, decryption, and hashing operations.
    """)

elif choice == "Symmetric Encryption":
    algo = st.selectbox("Choose Algorithm", ["AES", "DES", "3DES"])
    operation = st.radio("Operation", ["Encrypt", "Decrypt"])
    mode = st.radio("Mode", ["Text", "File"])

    if mode == "Text":
        data = st.text_area("Enter Text")
        key = st.text_input("Enter Key (16 bytes for AES, 8 bytes for DES, 24 bytes for 3DES)")

        if st.button("Submit"):
            if algo == "AES" and len(key) == 16:
                result = aes_encrypt(data.encode(), key.encode()) if operation == "Encrypt" else aes_decrypt(data, key.encode()).decode()
                st.code(result)
            elif algo == "DES" and len(key) == 8:
                result = des_encrypt(data.encode(), key.encode()) if operation == "Encrypt" else des_decrypt(data, key.encode()).decode()
                st.code(result)
            elif algo == "3DES" and len(key) == 24:
                result = triple_des_encrypt(data.encode(), key.encode()) if operation == "Encrypt" else triple_des_decrypt(data, key.encode()).decode()
                st.code(result)
            else:
                st.error("Invalid key length.")

    else:
        uploaded_file = st.file_uploader("Upload File")
        key = st.text_input("Enter Key (16 bytes for AES, 8 bytes for DES, 24 bytes for 3DES)")
        if uploaded_file and st.button("Submit"):
            file_data = uploaded_file.read()
            if algo == "AES" and len(key) == 16:
                result = aes_encrypt(file_data, key.encode()) if operation == "Encrypt" else aes_decrypt(file_data.decode(), key.encode()).decode()
                st.code(result)
            elif algo == "DES" and len(key) == 8:
                result = des_encrypt(file_data, key.encode()) if operation == "Encrypt" else des_decrypt(file_data.decode(), key.encode()).decode()
                st.code(result)
            elif algo == "3DES" and len(key) == 24:
                result = triple_des_encrypt(file_data, key.encode()) if operation == "Encrypt" else triple_des_decrypt(file_data.decode(), key.encode()).decode()
                st.code(result)
            else:
                st.error("Invalid key length.")

elif choice == "Asymmetric Encryption":
    algo = st.selectbox("Choose Algorithm", ["RSA", "DSA", "Diffie-Hellman"])
    operation = st.radio("Operation", ["Encrypt/Sign", "Decrypt/Verify"])
    data = st.text_area("Enter Text")

    if st.button("Submit"):
        if algo == "RSA":
            result = rsa_encrypt(data.encode()) if operation == "Encrypt/Sign" else rsa_decrypt(data).decode()
            st.code(result)
        elif algo == "DSA":
            result = dsa_sign(data.encode()) if operation == "Encrypt/Sign" else dsa_verify(data.encode(), st.text_input("Enter Signature"))
            st.code(result)
        elif algo == "Diffie-Hellman":
            result = diffie_hellman_key()
            st.code(f"Public Key (simulated): {result}")

elif choice == "Hashing":
    algo = st.selectbox("Choose Hash Function", ["md5", "sha1", "sha256", "blake2b"])
    mode = st.radio("Mode", ["Text", "File"])
    if mode == "Text":
        data = st.text_area("Enter Text")
        if st.button("Hash"):
            st.code(hash_data(data.encode(), algo))
    else:
        uploaded_file = st.file_uploader("Upload File")
        if uploaded_file and st.button("Hash"):
            st.code(hash_data(uploaded_file.read(), algo))

elif choice == "Algorithm Info":
    st.subheader("Cryptographic Algorithms Info")
    st.markdown("""
    - **AES**: Symmetric encryption standard (block size: 128 bits).
    - **DES**: Older symmetric encryption standard (56-bit key).
    - **3DES**: Enhanced DES with triple encryption.
    - **RSA**: Asymmetric encryption used for secure communication.
    - **DSA**: Asymmetric algorithm for digital signatures.
    - **Diffie-Hellman**: Key exchange method.
    - **MD5/SHA1/SHA256/BLAKE2**: Common hashing algorithms.
    """)
