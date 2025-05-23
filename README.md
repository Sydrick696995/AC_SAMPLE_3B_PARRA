# 🔐 Applied Cryptography Application

**Course:** BSCS 3B 
**Date:** [Submission Date]  
**Group Members:**  
- Julie Mae Bermudo
- Sydrick Parra
- Vladimir Ivan Pili

---

## 📌 Introduction
This project demonstrates the real-world application of cryptography to secure digital communication. By integrating various cryptographic methods—including symmetric encryption, asymmetric encryption, and hashing—the application allows users to explore how these techniques ensure the confidentiality, integrity, and authenticity of data. Users can encrypt/decrypt both text and files, as well as generate secure hashes.
---

## 🎯 Project Objectives
The primary goals of this application are:

✅ To implement commonly used cryptographic algorithms such as AES, RSA, and SHA-256.

✅ To provide an intuitive and interactive user interface using Streamlit.

✅ To educate users about the principles, history, and practical use cases of each cryptographic method.

---

## 🏗️ Application Architecture
This application is built using Streamlit, a Python-based web framework ideal for data-driven applications. It features:

📄 Multiple operational modes: Encryption, Decryption, and Hashing.

🧾 Text input and file upload support for comprehensive testing.

🧠 Informational tooltips and descriptions to help users understand each algorithm’s background and purpose.

---

## 🔐 Implemented Algorithms

### 🔸 AES (Advanced Encryption Standard)
- **Type:** Symmetric Encryption
- **History:** Standardized by NIST in 2001.
- **Use Cases:** Data-at-rest encryption, secure messaging, disk encryption.

### 🔸 DES (Data Encryption Standard)
- **Type:** Symmetric Encryption
- **History:** Developed in the 1970s and adopted as a federal standard in 1977.
- **Use Cases:** Legacy systems, secure data transfer (now considered insecure for sensitive data).

### 🔸 3DES (Triple DES)
- **Type:** Symmetric Encryption
- **History:** An enhancement of DES that applies the algorithm three times.
- **Use Cases:** Financial transactions, legacy applications requiring stronger encryption than DES.

### 🔸 RSA (Rivest-Shamir-Adleman)
- **Type:** Asymmetric Encryption
- **History:** Introduced in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman.
- **Use Cases:** Digital signatures, secure key exchange, SSL/TLS.

### 🔸 DSA (Digital Signature Algorithm)
- **Type:** Asymmetric Algorithm
- **History:** Proposed by NIST in 1991 as part of the Digital Signature Standard (DSS).
- **Use Cases:** Digital signatures, document verification, e-government systems.

### 🔸 Diffie-Hellman Key Exchange
- **Type:** Key Exchange Protocol
- **History:** Proposed by Whitfield Diffie and Martin Hellman in 1976.
- **Use Cases:** Secure key exchange over an insecure channel, basis for many encryption protocols.

### 🔸 SHA-256 (Secure Hash Algorithm 256-bit)
- **Type:** Cryptographic Hash Function
- **History:** Part of the SHA-2 family, released by NIST in 2001.
- **Use Cases:** Password hashing, digital signatures, integrity verification.

### 🔸 MD5 (Message Digest Algorithm 5)
- **Type:** Cryptographic Hash Function
- **History:** Designed by Ronald Rivest in 1992.
- **Use Cases:** Checksums and non-cryptographic data integrity checks (not recommended for security-critical purposes due to vulnerabilities).

### 🔸 SHA-1 (Secure Hash Algorithm 1)
- **Type:** Cryptographic Hash Function
- **History:** Developed by NSA in 1995, predecessor of SHA-2.
- **Use Cases:** Legacy systems (deprecated due to collision vulnerabilities).

### 🔸 BLAKE2
- **Type:** Cryptographic Hash Function
- **History:** Designed in 2012 as a faster and more secure alternative to MD5 and SHA-1.
- **Use Cases:** General-purpose cryptographic hashing, data integrity, digital signatures.

---

## 🚀 Install
Ensure Python is installed on your system. Then install the required libraries:
```bash
- pip install streamlit
- pip install pycryptodome
- pip install cryptography

## 🚀 Deployment
Once dependencies are installed, run the application with:
```bash
streamlit run app.py

The Streamlit interface will launch in your default browser, allowing you to start encrypting, decrypting, and hashing data interactively.

## 📚 Additional Notes
🛠️ The application is for educational purposes and should not be used for production-grade security.

💡 Each algorithm includes a brief description and history to enhance user understanding.