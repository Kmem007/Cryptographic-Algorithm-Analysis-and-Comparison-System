from flask import Flask, render_template, request, session, jsonify
import json
from encryption import (
    aes_encrypt, aes_decrypt, aes_steps,
    rsa_generate_keys, rsa_encrypt, rsa_decrypt, rsa_steps,
    sha256_hash, sha256_steps,
    measure_performance
)

app = Flask(__name__)
app.secret_key = "crypto_demo_secret_2024"

# ──────────────── HOME ────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ──────────────── DEMO MENU ────────────────
@app.route("/demo")
def demo():
    return render_template("demo.html")

# ──────────────── AES ────────────────
@app.route("/aes", methods=["GET", "POST"])
def aes():
    result = ""
    steps = []
    error = ""
    action = ""
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        key  = request.form.get("key",  "").strip()
        action = request.form.get("action", "encrypt")
        if not text or not key:
            error = "⚠️ Please enter both text and a secret key."
        else:
            try:
                if action == "encrypt":
                    result = aes_encrypt(text, key)
                    steps  = aes_steps(text, key)
                else:
                    result = aes_decrypt(text, key)
                    steps  = ["🔓 Decryption successful — reverse of the 10-round AES process applied.",
                               f"✅ Recovered plaintext: {result}"]
            except Exception as ex:
                error = f"❌ Error: {str(ex)}"
    return render_template("aes.html", result=result, steps=steps,
                           error=error, action=action)

# ──────────────── RSA ────────────────
@app.route("/rsa", methods=["GET", "POST"])
def rsa():
    result = ""
    steps  = []
    keys   = {}
    error  = ""
    action = ""

    if request.method == "POST":
        text   = request.form.get("text", "").strip()
        action = request.form.get("action", "")

        if action == "generate":
            keys = rsa_generate_keys(512)
            # store in session for encrypt/decrypt
            session["rsa_keys"] = {k: str(v) for k, v in keys.items()}
            steps = rsa_steps(keys["p"], keys["q"], keys["n"],
                              keys["e"], keys["d"])
            result = f"Public Key : (e={keys['e']}, n={keys['n']})\nPrivate Key: (d={keys['d']}, n={keys['n']})"

        elif action == "encrypt":
            raw = session.get("rsa_keys")
            if not raw:
                error = "⚠️ Please generate RSA keys first."
            elif not text:
                error = "⚠️ Please enter a message to encrypt."
            else:
                e, n = int(raw["e"]), int(raw["n"])
                result = rsa_encrypt(text, e, n)
                session["rsa_ciphertext"] = result
                steps  = [f"🔒 Encrypted using public key e={e}",
                           f"⚙️  Formula: C = M^e mod n",
                           f"✅ Ciphertext (base64): {result[:60]}..."]

        elif action == "decrypt":
            raw = session.get("rsa_keys")
            ct = text.strip() if text.strip() else session.get("rsa_ciphertext", "")
            if not raw:
                error = "⚠️ Please generate RSA keys first."
            else:
                d, n = int(raw["d"]), int(raw["n"])
                try:
                    result = rsa_decrypt(ct, d, n)
                    steps  = [f"🔓 Decrypted using private key d={d}",
                               f"⚙️  Formula: M = C^d mod n",
                               f"✅ Recovered message: {result}"]
                except Exception as ex:
                    error = f"❌ Decryption failed — paste the correct ciphertext from the Encrypt step. ({str(ex)})"

    return render_template("rsa.html", result=result, steps=steps,
                           keys=keys, error=error, action=action)

# ──────────────── SHA-256 ────────────────
@app.route("/sha", methods=["GET", "POST"])
def sha():
    result = ""
    steps  = []
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        if text:
            result = sha256_hash(text)
            steps  = sha256_steps(text)
    return render_template("sha.html", result=result, steps=steps)

# ──────────────── LIVE COMPARISON ────────────────
@app.route("/compare", methods=["GET", "POST"])
def compare():
    perf = None
    text = ""
    error = ""
    if request.method == "POST":
        text = request.form.get("text", "Hello World").strip() or "Hello World"
        try:
            # Always generate fresh keys for comparison — no session dependency
            keys = rsa_generate_keys(512)
            perf = measure_performance(text, keys)
        except Exception as ex:
            error = f"❌ Benchmark failed: {str(ex)}"
    return render_template("compare.html", perf=perf, text=text, error=error)

# ──────────────── ABOUT ────────────────
@app.route("/about")
def about():
    return render_template("about.html")

# ──────────────── RUN ────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")