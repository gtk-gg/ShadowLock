# 🛡️ ShadowLock v1.0 — Python Obfuscator

ShadowLock v1.0 is a **hybrid encryption-based Python obfuscator** that converts Python scripts into **compressed, encrypted, anti-debug–protected** executables using **ChaCha20-Poly1305**, **PBKDF2-HMAC hardened keys**, and a **polymorphic runtime stub**. Requires **Python 3.8+** to run

---

## 🚀 Features

- **ChaCha20-Poly1305 AEAD encryption**
- **PBKDF2-HMAC hardened key derivation (150k rounds)**
- **Compressed bytecode payload (zlib level 9)**
- **Polymorphic stub (random variable names every build)**
- **Anti-Debug & Anti-VM checks**
- **Base85 compact packaging**
- **No external server — everything offline**
- **Fully working, stable & battle-tested**

---

## 📦 Installation

## Install Git (if you haven't)

### Windows PowerShell:
Windows Powershell already comes with Git pre-installed on most systems, but if not, download it from:
https://git-scm.com/downloads

### Linux:
Run:
```bash
sudo apt install git -y
```

### Termux:
Run:
```bash
pkg install git -y
```

## Clone The Git
In order to run this script you have to clone our repository, 
you can do it by simply running:
```bash
git clone https://github.com/gtk-gg/ShadowLock
```
And select the directory by running
```bash
cd ShadowLock
```

## Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 🛠 Usage

Run ShadowLock:

```bash
python shadowlock.py
```
or
```bash
python3 shadowlock.py
```

## Drop the file path when asked:
To get the path of you ```<yourprojectname>.py```, simply select it and press **CTRL + C** and paste it when path is asked
Example:
```
Drop your .py file path:
> C:\Users\yourname\script.py
```

Our ShadowLock will generate:

```<yourprojectname>_shadowcrypted.py```


This new file contains:

- Encrypted & compressed bytecode
- Anti-debug/anti-vm shell
- Auto-decrypting polymorphic loader

---

## 📁 Output Stub Structure

- Encoded payload (`Base85`)
- SALT + MASTER key embedded
- PBKDF2-derived runtime key
- AEAD authentication tag verification
- Runtime decompression + marshal execution

---

## 🔐 Security Design

ShadowLock uses:

- **ChaCha20-Poly1305** for encryption + tamper detection  
- **PBKDF2-HMAC-SHA256** (150k iterations) for key hardening  
- **zlib** compression layer to shrink and hide patterns  
- **marshal** for precompiled bytecode execution  
- **Randomized variable names** for polymorphism  
- **Sandbox escape & debugger detection** (basic protection)
- **⚠️ Note: Obfuscation does *not* guarantee 100% security — skilled attackers can still reverse-engineer or analyze protected Python code with enough time and resources**


---

## 🧑‍💻 Author

**gtk-gg**  
GitHub: https://github.com/gtk-gg

---

## ⚠️ Disclaimer

ShadowLock is made for **education, security research, IP protection, and safe code distribution only.**  
The author is **not responsible** for misuse.

---

## ⭐ Support
If you like the project, drop a star ⭐ on GitHub!
