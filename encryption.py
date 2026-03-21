import os
import time
import tracemalloc
import hashlib
import base64
import json

# ─────────────────────────────────────────────
#  AES  (pure-Python, no external libs needed)
#  Uses AES-128-CBC via pycryptodome if available,
#  falls back to a pure-Python AES implementation.
# ─────────────────────────────────────────────

# ---------- Pure-Python AES-128 ----------
_sbox = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_inv_sbox = [0]*256
for i,v in enumerate(_sbox): _inv_sbox[v]=i

_rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a): return ((a<<1)^0x1b) & 0xff if a&0x80 else (a<<1)&0xff

def _gmul(a,b):
    p=0
    for _ in range(8):
        if b&1: p^=a
        hi=a&0x80; a=((a<<1)&0xff); 
        if hi: a^=0x1b
        b>>=1
    return p

def _sub_word(w): return [_sbox[b] for b in w]
def _rot_word(w): return w[1:]+w[:1]

def _key_expansion(key_bytes):
    w=[list(key_bytes[i:i+4]) for i in range(0,16,4)]
    for i in range(4,44):
        tmp=w[i-1][:]
        if i%4==0:
            tmp=_sub_word(_rot_word(tmp))
            tmp[0]^=_rcon[i//4-1]
        w.append([a^b for a,b in zip(w[i-4],tmp)])
    return w

def _add_round_key(state,rk):
    for c in range(4):
        for r in range(4):
            state[r][c]^=rk[c][r]

def _sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c]=_sbox[state[r][c]]

def _inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c]=_inv_sbox[state[r][c]]

def _shift_rows(state):
    for r in range(1,4):
        state[r]=state[r][r:]+state[r][:r]

def _inv_shift_rows(state):
    for r in range(1,4):
        state[r]=state[r][4-r:]+state[r][:4-r]

def _mix_columns(state):
    for c in range(4):
        s=state
        s0=_gmul(s[0][c],2)^_gmul(s[1][c],3)^s[2][c]^s[3][c]
        s1=s[0][c]^_gmul(s[1][c],2)^_gmul(s[2][c],3)^s[3][c]
        s2=s[0][c]^s[1][c]^_gmul(s[2][c],2)^_gmul(s[3][c],3)
        s3=_gmul(s[0][c],3)^s[1][c]^s[2][c]^_gmul(s[3][c],2)
        state[0][c],state[1][c],state[2][c],state[3][c]=s0,s1,s2,s3

def _inv_mix_columns(state):
    for c in range(4):
        s=state
        s0=_gmul(s[0][c],0x0e)^_gmul(s[1][c],0x0b)^_gmul(s[2][c],0x0d)^_gmul(s[3][c],0x09)
        s1=_gmul(s[0][c],0x09)^_gmul(s[1][c],0x0e)^_gmul(s[2][c],0x0b)^_gmul(s[3][c],0x0d)
        s2=_gmul(s[0][c],0x0d)^_gmul(s[1][c],0x09)^_gmul(s[2][c],0x0e)^_gmul(s[3][c],0x0b)
        s3=_gmul(s[0][c],0x0b)^_gmul(s[1][c],0x0d)^_gmul(s[2][c],0x09)^_gmul(s[3][c],0x0e)
        state[0][c],state[1][c],state[2][c],state[3][c]=s0,s1,s2,s3

def _bytes_to_state(b):
    return [[b[r+4*c] for c in range(4)] for r in range(4)]

def _state_to_bytes(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))

def _pad(data):
    n=16-(len(data)%16)
    return data+bytes([n]*n)

def _unpad(data):
    n=data[-1]
    return data[:-n]

def aes_encrypt_block(block16, round_keys):
    state=_bytes_to_state(block16)
    _add_round_key(state, round_keys[0:4])
    for rnd in range(1,10):
        _sub_bytes(state); _shift_rows(state); _mix_columns(state)
        _add_round_key(state, round_keys[rnd*4:(rnd+1)*4])
    _sub_bytes(state); _shift_rows(state)
    _add_round_key(state, round_keys[40:44])
    return _state_to_bytes(state)

def aes_decrypt_block(block16, round_keys):
    state=_bytes_to_state(block16)
    _add_round_key(state, round_keys[40:44])
    _inv_shift_rows(state); _inv_sub_bytes(state)
    for rnd in range(9,0,-1):
        _add_round_key(state, round_keys[rnd*4:(rnd+1)*4])
        _inv_mix_columns(state); _inv_shift_rows(state); _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0:4])
    return _state_to_bytes(state)

def _derive_key(key_str):
    """Derive a 16-byte key from any string."""
    return hashlib.md5(key_str.encode()).digest()

def aes_encrypt(plaintext: str, key_str: str):
    key = _derive_key(key_str)
    iv = os.urandom(16)
    rk = _key_expansion(key)
    data = _pad(plaintext.encode())
    prev = iv
    ct = b""
    for i in range(0, len(data), 16):
        blk = bytes(a^b for a,b in zip(data[i:i+16], prev))
        enc = aes_encrypt_block(blk, rk)
        ct += enc; prev = enc
    return base64.b64encode(iv+ct).decode()

def aes_decrypt(ciphertext_b64: str, key_str: str):
    raw = base64.b64decode(ciphertext_b64)
    iv, ct = raw[:16], raw[16:]
    key = _derive_key(key_str)
    rk = _key_expansion(key)
    prev = iv; pt = b""
    for i in range(0, len(ct), 16):
        blk = ct[i:i+16]
        dec = aes_decrypt_block(blk, rk)
        pt += bytes(a^b for a,b in zip(dec, prev))
        prev = blk
    return _unpad(pt).decode()

def aes_steps(plaintext: str, key_str: str):
    key = _derive_key(key_str)
    rk = _key_expansion(key)
    data = _pad(plaintext.encode())
    block = data[:16]
    state = _bytes_to_state(block)
    steps = []
    steps.append(f"🔑 Key (hex): {key.hex()}")
    steps.append(f"📝 Plaintext block (hex): {block.hex()}")
    steps.append(f"🔢 Key Expansion: Generated 11 round keys (RK₀–RK₁₀)")
    steps.append(f"⚙️  Initial AddRoundKey: State XOR'd with RK₀ → {_state_to_bytes(state).hex()}")
    _add_round_key(state, rk[0:4])
    for rnd in range(1, 10):
        _sub_bytes(state)
        steps.append(f"🔄 Round {rnd} — SubBytes   : {_state_to_bytes(state).hex()}")
        _shift_rows(state)
        steps.append(f"🔄 Round {rnd} — ShiftRows  : {_state_to_bytes(state).hex()}")
        _mix_columns(state)
        steps.append(f"🔄 Round {rnd} — MixColumns : {_state_to_bytes(state).hex()}")
        _add_round_key(state, rk[rnd*4:(rnd+1)*4])
        steps.append(f"🔄 Round {rnd} — AddRoundKey: {_state_to_bytes(state).hex()}")
    _sub_bytes(state)
    steps.append(f"🏁 Final Round — SubBytes  : {_state_to_bytes(state).hex()}")
    _shift_rows(state)
    steps.append(f"🏁 Final Round — ShiftRows : {_state_to_bytes(state).hex()}")
    _add_round_key(state, rk[40:44])
    final = _state_to_bytes(state)
    steps.append(f"🏁 Final Round — AddRoundKey (Ciphertext block): {final.hex()}")
    return steps


# ─────────────────────────────────────────────
#  RSA  (pure-Python, no external libs)
# ─────────────────────────────────────────────

def _is_prime(n, k=5):
    if n<2: return False
    if n==2: return True
    if n%2==0: return False
    r,d=0,n-1
    while d%2==0: r+=1; d//=2
    import random
    for _ in range(k):
        a=random.randrange(2,n-1)
        x=pow(a,d,n)
        if x in(1,n-1): continue
        for _ in range(r-1):
            x=pow(x,2,n)
            if x==n-1: break
        else: return False
    return True

def _gen_prime(bits=512):
    import random
    while True:
        n=random.getrandbits(bits)|1|(1<<(bits-1))
        if _is_prime(n): return n

def _modinv(a,m):
    g,x,_=_extended_gcd(a,m)
    if g!=1: raise ValueError("No inverse")
    return x%m

def _extended_gcd(a,b):
    if a==0: return b,0,1
    g,x,y=_extended_gcd(b%a,a)
    return g,y-(b//a)*x,x

def rsa_generate_keys(bits=512):
    p=_gen_prime(bits//2)
    q=_gen_prime(bits//2)
    while q==p: q=_gen_prime(bits//2)
    n=p*q
    phi=(p-1)*(q-1)
    e=65537
    d=_modinv(e,phi)
    return {"p":p,"q":q,"n":n,"e":e,"d":d,
            "public_key":f"({e},{n})","private_key":f"({d},{n})"}

def rsa_encrypt(plaintext: str, e: int, n: int) -> str:
    m_bytes = plaintext.encode()
    chunks = []
    chunk_size = (n.bit_length()//8) - 1
    for i in range(0, len(m_bytes), chunk_size):
        chunk = m_bytes[i:i+chunk_size]
        m_int = int.from_bytes(chunk, 'big')
        c_int = pow(m_int, e, n)
        chunks.append(c_int)
    return base64.b64encode(json.dumps(chunks).encode()).decode()

def rsa_decrypt(ciphertext_b64: str, d: int, n: int) -> str:
    chunks = json.loads(base64.b64decode(ciphertext_b64).decode())
    result = b""
    chunk_size = (n.bit_length()//8) - 1
    for c_int in chunks:
        m_int = pow(c_int, d, n)
        m_bytes = m_int.to_bytes(chunk_size, 'big').lstrip(b'\x00')
        result += m_bytes
    return result.decode()

def rsa_steps(p,q,n,e,d):
    return [
        f"📌 Step 1 — Choose two primes: p = {p}, q = {q}",
        f"📌 Step 2 — Compute n = p × q = {n}",
        f"📌 Step 3 — Compute φ(n) = (p−1)(q−1) = {(p-1)*(q-1)}",
        f"📌 Step 4 — Choose e = {e}  [gcd(e, φ(n)) = 1]",
        f"📌 Step 5 — Compute d = e⁻¹ mod φ(n) = {d}",
        f"🔓 Public  Key  → (e={e}, n={n})",
        f"🔐 Private Key  → (d={d}, n={n})",
        f"⚙️  Encrypt: C = M^e mod n",
        f"⚙️  Decrypt: M = C^d mod n",
    ]


# ─────────────────────────────────────────────
#  SHA-256 (real, stdlib)
# ─────────────────────────────────────────────

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def sha256_steps(text: str):
    data = text.encode()
    return [
        f"📝 Input message: \"{text}\"",
        f"📏 Message length: {len(data)} bytes = {len(data)*8} bits",
        f"🔧 Step 1 — Padding: Append '1' bit, then zeros, then 64-bit length → total multiple of 512 bits",
        f"🔢 Step 2 — Initialize 8 hash values H₀–H₇ (first 32 bits of fractional parts of √primes)",
        f"⚙️  Step 3 — Process {max(1, (len(data)+8)//64 + 1)} block(s) of 512 bits",
        f"🔄 Step 4 — Each block: expand to 64 message schedule words (W₀–W₆₃)",
        f"🔄 Step 5 — 64 rounds of compression using Ch, Maj, Σ, σ functions",
        f"➕ Step 6 — Add compressed values back to H₀–H₇",
        f"🏁 Step 7 — Concatenate H₀–H₇ → 256-bit hash",
        f"✅ SHA-256 Hash: {hashlib.sha256(data).hexdigest()}",
    ]


# ─────────────────────────────────────────────
#  Performance Comparison
# ─────────────────────────────────────────────

def measure_performance(text: str, rsa_keys: dict):
    results = {}
    size_bytes = len(text.encode())
    size_mb = size_bytes / (1024 * 1024)

    # AES
    tracemalloc.start()
    t0 = time.perf_counter()
    ct = aes_encrypt(text, "benchmarkkey123")
    aes_decrypt(ct, "benchmarkkey123")
    t1 = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    elapsed = max(t1 - t0, 1e-9)
    results["AES"] = {
        "speed_mbs":  round(size_mb / elapsed, 6),
        "memory_mb":  round(peak / (1024 * 1024), 4),
        "time_sec":   round(elapsed, 6),
    }

    # RSA
    e, d, n = rsa_keys["e"], rsa_keys["d"], rsa_keys["n"]
    chunk = text[:50] if len(text) > 50 else text
    chunk_mb = len(chunk.encode()) / (1024 * 1024)
    tracemalloc.start()
    t0 = time.perf_counter()
    ct2 = rsa_encrypt(chunk, e, n)
    rsa_decrypt(ct2, d, n)
    t1 = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    elapsed = max(t1 - t0, 1e-9)
    results["RSA"] = {
        "speed_mbs":  round(chunk_mb / elapsed, 6),
        "memory_mb":  round(peak / (1024 * 1024), 4),
        "time_sec":   round(elapsed, 6),
    }

    # SHA-256
    tracemalloc.start()
    t0 = time.perf_counter()
    for _ in range(100):
        hashlib.sha256(text.encode()).hexdigest()
    t1 = time.perf_counter()
    _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    elapsed_single = max((t1 - t0) / 100, 1e-9)
    results["SHA256"] = {
        "speed_mbs":  round(size_mb / elapsed_single, 6),
        "memory_mb":  round(peak / (1024 * 1024), 4),
        "time_sec":   round(elapsed_single, 6),
    }

    return results