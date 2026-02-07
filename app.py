from flask import Flask, render_template, request
import hashlib
import base64

app = Flask(__name__)
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")


# ---------------- HOME ----------------
@app.route("/")
def index():
    return render_template("index.html")

# ---------------- DEMO MENU ----------------
@app.route("/demo")
def demo():
    return render_template("demo.html")

# ---------------- AES (Educational) ----------------
@app.route("/aes", methods=["GET", "POST"])
def aes():
    result = ""
    if request.method == "POST":
        text = request.form["text"]
        key = request.form["key"]

        if request.form["action"] == "encrypt":
            result = base64.b64encode(text.encode()).decode()
        else:
            try:
                result = base64.b64decode(text.encode()).decode()
            except:
                result = "Invalid Cipher Text"

    return render_template("aes.html", result=result)

# ---------------- RSA (Educational) ----------------
@app.route("/rsa", methods=["GET", "POST"])
def rsa():
    result = ""
    if request.method == "POST":
        text = request.form["text"]
        result = text[::-1]   # demo logic

    return render_template("rsa.html", result=result)

# ---------------- SHA ----------------
@app.route("/sha", methods=["GET", "POST"])
def sha():
    result = ""
    if request.method == "POST":
        text = request.form["text"]
        result = hashlib.sha256(text.encode()).hexdigest()

    return render_template("sha.html", result=result)

# ---------------- COMPARISON ----------------
@app.route('/compare')   # route matches the URL
def compare():
    return render_template('compare.html')


# ---------------- ABOUT ----------------
@app.route("/about")
def about():
    return render_template("about.html")

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
