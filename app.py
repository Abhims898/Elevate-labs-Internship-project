import os
import io
import json
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session
from werkzeug.utils import secure_filename
from crypto import encrypt_file_aes, decrypt_file_aes

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))

# Config
STORAGE_DIR = os.environ.get("SFS_STORAGE_DIR", "storage")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

# -------- Authentication --------
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if ADMIN_PASSWORD and not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == ADMIN_PASSWORD:
            session["logged_in"] = True
            flash("Login successful", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid password", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))

# -------- Routes --------
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        file = request.files["file"]
        user_key = request.form.get("user_key")
        if file and user_key:
            try:
                filename = secure_filename(file.filename)
                enc_path = os.path.join(STORAGE_DIR, filename + ".enc")
                meta_path = enc_path + ".json"

                ciphertext, iv, tag, key_hash = encrypt_file_aes(file.read(), user_key, filename)

                with open(enc_path, "wb") as f:
                    f.write(ciphertext)

                metadata = {
                    "original_name": filename,
                    "encrypted_name": filename + ".enc",
                    "iv": iv.hex(),
                    "tag": tag.hex(),
                    "key_hash": key_hash,
                    "time": datetime.utcnow().isoformat(),
                    "sha256": hashlib.sha256(ciphertext).hexdigest(),
                }
                with open(meta_path, "w") as mf:
                    json.dump(metadata, mf)

                flash(f"File '{filename}' encrypted successfully!", "success")
                return redirect(url_for("list_files"))
            except Exception as e:
                flash("Encryption failed: " + str(e), "danger")
    return render_template("index.html")

@app.route("/files")
@login_required
def list_files():
    files = []
    for fname in os.listdir(STORAGE_DIR):
        if fname.endswith(".enc"):
            meta_path = os.path.join(STORAGE_DIR, fname + ".json")
            if os.path.exists(meta_path):
                with open(meta_path) as f:
                    meta = json.load(f)
                files.append(meta)
    return render_template("files.html", files=files)

@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt_file():
    if request.method == "POST":
        file = request.files["file"]
        user_key = request.form.get("user_key")
        if file and user_key:
            enc_path = os.path.join(STORAGE_DIR, "temp_upload.enc")
            file.save(enc_path)

            try:
                original_name, plaintext = decrypt_file_aes(enc_path, user_key)
                os.remove(enc_path)
                return send_file(
                    io.BytesIO(plaintext),
                    as_attachment=True,
                    download_name=original_name,
                )
            except Exception as e:
                flash("Decryption failed: " + str(e), "danger")
                return redirect(url_for("decrypt_file"))
    return render_template("decrypt.html")

@app.route("/delete/<filename>", methods=["POST"])
@login_required
def delete_file(filename):
    enc_path = os.path.join(STORAGE_DIR, filename)
    meta_path = enc_path + ".json"
    try:
        if os.path.exists(enc_path):
            os.remove(enc_path)
        if os.path.exists(meta_path):
            os.remove(meta_path)
        flash(f"Deleted {filename}", "success")
    except Exception as e:
        flash("Error deleting file: " + str(e), "danger")
    return redirect(url_for("list_files"))

if __name__ == "__main__":
    app.run(debug=True)
