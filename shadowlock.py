# ================================================
# ShadowLock v1.0 — Hybrid
# Author: gtk-gg • github.com/gtk-gg
# Repaired + optimized
# ================================================

import os
import sys
import zlib
import marshal
import base64
import secrets
import random
import string
import hashlib
import time
import platform

try:
    from Crypto.Cipher import AES, ChaCha20_Poly1305
except ImportError:
    os.system(f"{sys.executable} -m pip install pycryptodome -q")
    from Crypto.Cipher import AES, ChaCha20_Poly1305

# ===================== BANNER =====================
SHADOWLOCK_BANNER = r"""
  sSSs   .S    S.    .S_SSSs     .S_sSSs      sSSs_sSSs     .S     S.   S.        sSSs_sSSs      sSSs   .S    S.   
 d%%SP  .SS    SS.  .SS~SSSSS   .SS~YS%%b    d%%SP~YS%%b   .SS     SS.  SS.      d%%SP~YS%%b    d%%SP  .SS    SS.  
d%S'    S%S    S%S  S%S   SSSS  S%S   `S%b  d%S'     `S%b  S%S     S%S  S%S     d%S'     `S%b  d%S'    S%S    S&S  
S%|     S%S    S%S  S%S    S%S  S%S    S%S  S%S       S%S  S%S     S%S  S%S     S%S       S%S  S%S     S%S    d*S  
S&S     S%S SSSS%S  S%S SSSS%S  S%S    S&S  S&S       S&S  S%S     S%S  S&S     S&S       S&S  S&S     S&S   .S*S  
Y&Ss    S&S  SSS&S  S&S  SSS%S  S&S    S&S  S&S       S&S  S&S     S&S  S&S     S&S       S&S  S&S     S&S_sdSSS   
`S&&S   S&S    S&S  S&S    S&S  S&S    S&S  S&S       S&S  S&S     S&S  S&S     S&S       S&S  S&S     S&S~YSSY%b  
  `S*S  S&S    S&S  S&S    S&S  S&S    S&S  S&S       S&S  S&S     S&S  S&S     S&S       S&S  S&S     S&S    `S%  
   l*S  S*S    S*S  S*S    S&S  S*S    d*S  S*b       d*S  S*S     S*S  S*b     S*b       d*S  S*b     S*S     S%  
  .S*P  S*S    S*S  S*S    S*S  S*S   .S*S  S*S.     .S*S  S*S  .  S*S  S*S.    S*S.     .S*S  S*S.    S*S     S&  
sSS*S   S*S    S*S  S*S    S*S  S*S_sdSSS    SSSbs_sdSSS   S*S_sSs_S*S   SSSbs   SSSbs_sdSSS    SSSbs  S*S     S&  
YSS'    SSS    S*S  SSS    S*S  SSS~YSSY      YSSP~YSSY    SSS~SSS~S*S    YSSP    YSSP~YSSY      YSSP  S*S     SS  
               SP          SP                                                                          SP          
               Y           Y                                                                           Y 
                                       ShadowLock - v1.0
                                              by
                                       github.com/gtk-gg          
"""

COLORS = [
    (57,16,83),
    (90,38,117),
    (157,114,179),
    (201,168,241),
    (255,255,255)
]

def print_gradient(text):
    lines = text.split("\n")
    for i, line in enumerate(lines):
        r,g,b = COLORS[i % len(COLORS)]
        print(f"\033[38;2;{r};{g};{b}m{line}\033[0m")

# ===================== KEY MATERIAL =====================
MASTER = secrets.token_bytes(32)
SALT = secrets.token_bytes(16)
KEY = hashlib.pbkdf2_hmac("sha256", MASTER, SALT, 150000, 32)
NONCE = secrets.token_bytes(12)

# ===================== ANTI-DEBUG + ANTI-VM =====================
ANTI_CHECKS = '''
import os,sys,time,platform,ctypes
try:
    if sys.gettrace(): os._exit(0)
    try:
        if ctypes.windll.kernel32.IsDebuggerPresent():
            os._exit(0)
    except: pass
    bad=["vbox","vmware","qemu","analysis"]
    if any(x in platform.uname().node.lower() for x in bad): os._exit(0)
except: pass
'''

# ===================== ENCRYPTION =====================
def encrypt(data: bytes):
    comp = zlib.compress(data, 9)
    cipher = ChaCha20_Poly1305.new(key=KEY, nonce=NONCE)
    ct, tag = cipher.encrypt_and_digest(comp)
    blob = NONCE + tag + ct + SALT + MASTER
    return base64.b85encode(blob).decode(), SALT, MASTER

# ===================== STUB =====================
def build_stub(payload: str, salt: bytes, master: bytes):

    rv = lambda: ''.join(random.choices(string.ascii_letters, k=random.randint(6,12)))
    a,b,c,d,e,f,g = rv(),rv(),rv(),rv(),rv(),rv(),rv()

    return f'''
# ShadowLock v1.0 - github.com/gtk-gg
import os,sys,zlib,base64,hashlib,marshal
from Crypto.Cipher import ChaCha20_Poly1305
{ANTI_CHECKS}

{a} = "{payload}"
{b} = {salt!r}
{c} = {master!r}

{d} = hashlib.pbkdf2_hmac("sha256", {c}, {b}, 150000, 32)
blob = base64.b85decode({a})

nonce = blob[:12]
tag   = blob[12:28]
ct    = blob[28:-48]

cipher = ChaCha20_Poly1305.new(key={d}, nonce=nonce)
out = cipher.decrypt_and_verify(ct, tag)
code = zlib.decompress(out)

exec(marshal.loads(code))
'''

# ===================== OBFUSCATOR =====================
def obfuscate(path: str):
    if not os.path.isfile(path):
        print("[-] File not found!")
        return

    print("[+] Compiling script...")
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    bytecode = marshal.dumps(compile(src, "<shadowlock>", "exec"))

    print("[+] Encrypting...")
    payload, salt, master = encrypt(bytecode)

    print("[+] Building stub...")
    stub = build_stub(payload, salt, master)

    out = os.path.splitext(os.path.basename(path))[0] + "_shadowcrypted.py"
    with open(out, "w", encoding="utf-8") as f:
        f.write(stub)

    print(f"[+] DONE → {out}")
    print("    ChaCha20-Poly1305")
    print("    PBKDF2 hardened keys")
    print("    Polymorphic stub")
    print("    Fully working & stable")

# ===================== MAIN =====================
def main():
    os.system("cls" if os.name=="nt" else "clear")
    print_gradient(SHADOWLOCK_BANNER)

    while True:
        p = input("Drop your .py file path:\n> ").strip().strip("\"'")
        if os.path.isfile(p): break
        print("[-] Invalid path.\n")

    obfuscate(p)
    print("\n" + "═"*56)
    print("   SHADOWLOCK v1.0 — Protected Successfully")
    print("═"*56)
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
