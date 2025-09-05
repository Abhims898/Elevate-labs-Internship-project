# app.py
import os
import io
import uuid
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for,
    send_file, flash, session
)
from werkzeug.utils import secure_filename
from crypto import (
    load_master_key_from_env,
    encrypt_file_bytes,
    decrypt_file_bytes,
    generate_master_key_b64
)

# Paths
BASE = Path(__file__).parent
STORAGE_DIR = Path(os.environ.get("SFS_STORAGE_DIR", str(BASE / "storage")))
TEMP_DIR = Path(os.environ.get("SFS_TEMP_DIR", str(BASE / "temp")))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
TEMP_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24).hex())

# Auth
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # if set, login is required

# Load master key
try:
    MASTER_KEY = load_master_key_from_env()
except Exception as e:
    MASTER_KEY = None
    print("Warning: MASTER_KEY not loaded:", e)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if ADMIN_PASSWORD and not session.get("logged_in"):
            flash("Please login first", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_settings():
    return dict(auth_enabled=bool(ADMIN_PASSWORD))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pw = request.form.get("password", "")
        if ADMIN_PASSWORD and pw == ADMIN_PASSWORD:
            session['logged_in'] = True
            flash("Logged in", "success")
            nxt = request.args.get("next") or url_for("index")
            return redirect(nxt)
        flash("Invalid password", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("index"))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate-key", methods=["POST"])
def generate_key():
    return {"master_key": generate_master_key_b64()}

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if MASTER_KEY is None:
        flash("Server error: master key not configured.", "danger")
        return redirect(url_for('index'))

    if 'file' not in request.files:
        flash("No file part", "warning")
        return redirect(url_for('index'))

    f = request.files['file']
    if f.filename == '':
        flash("No selected file", "warning")
        return redirect(url_for('index'))

    filename = secure_filename(f.filename)
    data = f.read()

    package = encrypt_file_bytes(MASTER_KEY, filename, data)

    out_name = filename + ".enc"
    out_path = STORAGE_DIR / out_name
    with open(out_path, "wb") as fh:
        fh.write(package)

    # Read metadata to show (decrypt locally)
    try:
        res = decrypt_file_bytes(MASTER_KEY, package)
        meta = res["metadata"]
    except Exception:
        meta = {"orig_filename": filename}

    return render_template("result.html",
                           action="encrypted",
                           stored_name=out_name,
                           orig_filename=meta.get("orig_filename"),
                           timestamp=meta.get("timestamp"),
                           size=meta.get("size"),
                           sha256=meta.get("sha256"),
                           download_url=url_for("download_enc", stored_name=out_name)
                           )

@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt_upload():
    if request.method == "POST":
        if MASTER_KEY is None:
            flash("Server error: master key not configured.", "danger")
            return redirect(url_for('decrypt_upload'))

        if 'file' not in request.files:
            flash("No file part", "warning")
            return redirect(url_for('decrypt_upload'))

        f = request.files['file']
        if f.filename == '':
            flash("No selected file", "warning")
            return redirect(url_for('decrypt_upload'))

        package_bytes = f.read()
        try:
            res = decrypt_file_bytes(MASTER_KEY, package_bytes)
            meta = res["metadata"]
            plaintext = res["plaintext"]
            orig_name = secure_filename(meta.get("orig_filename", "decrypted.bin"))

            token = uuid.uuid4().hex
            temp_fname = f"{token}_{orig_name}"
            temp_path = TEMP_DIR / temp_fname
            with open(temp_path, "wb") as tf:
                tf.write(plaintext)

            download_url = url_for("download_temp", token=token)
            return render_template("result.html",
                                   action="decrypted",
                                   stored_name=temp_fname,
                                   orig_filename=orig_name,
                                   timestamp=meta.get("timestamp"),
                                   size=meta.get("size"),
                                   sha256=meta.get("sha256"),
                                   download_url=download_url)
        except Exception as e:
            flash("Decryption failed: " + str(e), "danger")
            return redirect(url_for('decrypt_upload'))

    return render_template("decrypt.html")

@app.route("/download-enc/<stored_name>")
@login_required
def download_enc(stored_name):
    stored_name = secure_filename(stored_name)
    file_path = STORAGE_DIR / stored_name
    if not file_path.exists():
        flash("File not found", "warning")
        return redirect(url_for('list_files'))
    return send_file(str(file_path), as_attachment=True, download_name=stored_name)

@app.route("/download-temp/<token>")
@login_required
def download_temp(token):
    matches = list(TEMP_DIR.glob(f"{token}_*"))
    if not matches:
        flash("Temporary file not found or expired", "warning")
        return redirect(url_for('index'))
    p = matches[0]
    try:
        return send_file(str(p), as_attachment=True, download_name=p.name.split("_", 1)[1])
    finally:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass

@app.route("/files")
@login_required
def list_files():
    files = []
    for p in sorted(STORAGE_DIR.glob("*.enc")):
        entry = {"stored_name": p.name}
        try:
            pkg = p.read_bytes()
            meta = decrypt_file_bytes(MASTER_KEY, pkg)["metadata"] if MASTER_KEY else {}
            entry.update({
                "orig_filename": meta.get("orig_filename"),
                "timestamp": meta.get("timestamp"),
                "size": meta.get("size"),
                "sha256": meta.get("sha256")
            })
        except Exception as e:
            entry["error"] = str(e)
        files.append(entry)
    return render_template("files.html", files=files)

@app.route("/download-decrypted/<stored_name>")
@login_required
def download_decrypted(stored_name):
    stored_name = secure_filename(stored_name)
    file_path = STORAGE_DIR / stored_name
    if not file_path.exists():
        flash("File not found", "warning")
        return redirect(url_for('list_files'))
    try:
        pkg = file_path.read_bytes()
        res = decrypt_file_bytes(MASTER_KEY, pkg)
        meta = res["metadata"]
        plaintext = res["plaintext"]
        return send_file(io.BytesIO(plaintext),
                         as_attachment=True,
                         download_name=meta.get("orig_filename"),
                         mimetype="application/octet-stream")
    except Exception as e:
        flash("Decrypt/verify failed: " + str(e), "danger")
        return redirect(url_for('list_files'))

@app.route("/delete/<stored_name>", methods=["POST"])
@login_required
def delete_file(stored_name):
    stored_name = secure_filename(stored_name)
    file_path = STORAGE_DIR / stored_name
    try:
        if file_path.exists():
            file_path.unlink()
            flash(f"Deleted {stored_name}", "success")
        else:
            flash("File not found", "warning")
    except Exception as e:
        flash("Error deleting file: " + str(e), "danger")
    return redirect(url_for('list_files'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
