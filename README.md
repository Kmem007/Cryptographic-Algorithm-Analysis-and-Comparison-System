# 🔐 Cryptographic Algorithms — Web-Based Educational Tool

> A web-based interactive platform to demonstrate, visualize, and compare AES, RSA, and SHA-256 cryptographic algorithms.

---

## 📌 Project Overview

This project is an educational web application built using **Python (Flask)** that allows users to:
- Perform real **AES-128 encryption and decryption**
- Generate real **RSA key pairs** and perform encryption/decryption
- Generate **SHA-256 hash values**
- View **step-by-step visualizations** of each algorithm
- Run a **live performance comparison** (Speed, Memory, Time) across all three algorithms

---

## 🎯 Objectives

- Understand the working of symmetric and asymmetric cryptographic algorithms
- Demonstrate real encryption and decryption using AES and RSA
- Explain one-way hashing using SHA-256
- Compare algorithms based on speed, memory, and time consumption
- Provide an interactive and educational learning platform

---

## 🔐 Algorithms Implemented

### AES — Advanced Encryption Standard
- Type: Symmetric encryption
- Key size: 128-bit (AES-128-CBC mode)
- Pure Python implementation (no external crypto libraries)
- 10-round encryption with SubBytes, ShiftRows, MixColumns, AddRoundKey
- Step-by-step visualization with collapsible phase cards

### RSA — Rivest-Shamir-Adleman
- Type: Asymmetric encryption
- Key size: RSA-512
- Real prime number generation and key derivation (p, q, n, e, d)
- Encryption: `C = Mᵉ mod n`
- Decryption: `M = Cᵈ mod n`
- Step-by-step key generation and encryption/decryption visualization

### SHA-256 — Secure Hash Algorithm
- Type: Cryptographic hash function
- Output: Fixed 256-bit (64 hex character) hash
- One-way function — cannot be reversed
- Step-by-step visualization of padding, compression rounds, and output

---

## ⚡ Features

| Feature | Description |
|---|---|
| Real AES Encryption | AES-128-CBC with key expansion and 10 rounds |
| Real RSA Encryption | 512-bit key generation from primes |
| SHA-256 Hashing | Standard SHA-256 using Python hashlib |
| Step-by-Step Visualization | Phase-based, collapsible, human-readable steps |
| Live Performance Comparison | Speed (MB/s), Memory (MB), Time (seconds) with bar charts |
| Comparative Analysis Table | Side-by-side algorithm characteristics |

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| Frontend | HTML5, CSS3 (dark theme) |
| Cryptography | Pure Python (no pycryptodome needed) |
| Charts | Chart.js (CDN) |
| Deployment | Render (gunicorn) |

---

## 📁 Project Structure

```
PE2/
├── app.py                  # Flask routes and application logic
├── encryption.py           # AES, RSA, SHA-256 implementations
├── requirements.txt        # Python dependencies
├── Procfile                # Render deployment config
├── static/
│   ├── style.css           # Dark theme styles
│   └── images/             # Lock and key images
└── templates/
    ├── index.html          # Home page
    ├── demo.html           # Algorithm demonstrations menu
    ├── aes.html            # AES encrypt/decrypt + visualization
    ├── rsa.html            # RSA key gen + encrypt/decrypt + visualization
    ├── sha.html            # SHA-256 hashing + visualization
    ├── compare.html        # Live performance comparison + charts
    └── about.html          # Project information
```

---

## 🚀 How to Run Locally

**1. Clone the repository**
```bash
git clone https://github.com/shreyatiwari10001/PE2.git
cd PE2
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Run the Flask app**
```bash
python app.py
```

**4. Open in browser**
```
http://127.0.0.1:5000
```

> **Note for macOS users:** Port 5000 may be used by AirPlay Receiver.  
> Use `flask run --port 5001` and open `http://127.0.0.1:5001` instead.

---

## 🌐 Live Demo

**[https://cryptographic-algorithm-analysis-an.vercel.app/]**

---

## 📊 Performance Comparison (Sample)

| Algorithm | Speed (MB/s) | Memory (MB) | Time (seconds) |
|---|---|---|---|
| AES | Fast | Low | Very low |
| RSA | Slow (large key math) | Low | Higher |
| SHA-256 | Very Fast | Minimal | Extremely low |

> Run the Live Benchmark on the Compare page for real-time results on your input.

---

## 👩‍💻 How to Use

### AES
1. Enter any plaintext message
2. Enter a secret key
3. Click **Encrypt** → get ciphertext + step-by-step visualization
4. Paste ciphertext back, same key → click **Decrypt**

### RSA
1. Click **Generate Keys** → real RSA-512 key pair is created
2. Type message → click **Encrypt**
3. Click **Decrypt** → private key auto-used from session

### SHA-256
1. Enter any message
2. Click **Generate Hash** → get 256-bit hash + visualization

### Live Comparison
1. Go to **Comparative Analysis**
2. Enter any text message
3. Click **Run Benchmark** → see Speed, Memory, Time table + 3 bar charts

---

## 👩‍🎓 Academic Information

- **Course:** Project Exhibition 2
- **Batch:** 24BCY — Group 58
- **Institution:** VIT Bhopal University
- **Purpose:** Academic project demonstrating cryptographic algorithm implementation and performance analysis

---

## 📚 References

- NIST FIPS 197 — AES Standard
- RSA Laboratories — RSA Algorithm
- NIST FIPS 180-4 — SHA-256 Standard
- Tijjani, A. & Isa, A. (2024). *Performance Analysis of Symmetric and Asymmetric Encryption Algorithms Based on File, Image and Video.* IJEMD-CSAI.

---

## 📄 License

This project is built for academic and educational purposes.
