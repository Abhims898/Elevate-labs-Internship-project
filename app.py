import os
from flask import Flask, request, render_template, redirect, url_for, send_file, flash, jsonify
from werkzeug.utils import secure_filename
from pathlib import Path
import io
from crypto import load_master_key_from_env, encrypt_file_bytes, decrypt_file_bytes, generate_master_key_b64

# Configuration
STORAGE_DIR = Path(os.environ.get("SFS_STORAGE_DIR", "storage"))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB default limit

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = os.environ.get("FLASK_SECRET", "change-me-in-prod")

# Load master key at startup
try:
    MASTER_KEY = load_master_key_from_env()
except Exception as e:
    MASTER_KEY = None
    print("Warning: MASTER_KEY not loaded:", e)

@app.context_processor
def inject_settings():
    return dict(storage_dir=str(STORAGE_DIR))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate-key", methods=["POST"])
def generate_key():
    # returns a base64 key for user to copy to env
    return jsonify({"master_key": generate_master_key_b64()})

@app.route("/upload", methods=["POST"])
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
    flash(f"File encrypted and stored as {out_name}", "success")
    return redirect(url_for('index'))

@app.route("/files")
def list_files():
    files = []
    for p in sorted(STORAGE_DIR.glob("*.enc")):
        try:
            with open(p, "rb") as fh:
                pkg = fh.read()
            # Try to read metadata without exposing plaintext by decrypting
            res = decrypt_file_bytes(MASTER_KEY, pkg) if MASTER_KEY else None
            meta = res["metadata"] if res else {}
            files.append({
                "stored_name": p.name,
                "orig_filename": meta.get("orig_filename"),
                "timestamp": meta.get("timestamp"),
                "size": meta.get("size"),
                "sha256": meta.get("sha256")
            })
        except Exception as e:
            files.append({"stored_name": p.name, "error": str(e)})
    return render_template("files.html", files=files)

@app.route("/download/<stored_name>")
def download_decrypted(stored_name):
    if MASTER_KEY is None:
        flash("Server error: master key not configured.", "danger")
        return redirect(url_for('index'))
    # sanitize
    stored_name = secure_filename(stored_name)
    file_path = STORAGE_DIR / stored_name
    if not file_path.exists():
        flash("File not found", "warning")
        return redirect(url_for('list_files'))
    with open(file_path, "rb") as fh:
        pkg = fh.read()
    try:
        res = decrypt_file_bytes(MASTER_KEY, pkg)
    except Exception as e:
        flash("Decrypt/verify failed: " + str(e), "danger")
        return redirect(url_for('list_files'))
    meta = res["metadata"]
    plaintext = res["plaintext"]
    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=meta.get("orig_filename"),
        mimetype="application/octet-stream"
    )

@app.route("/download-enc/<stored_name>")
def download_enc(stored_name):
    stored_name = secure_filename(stored_name)
    file_path = STORAGE_DIR / stored_name
    if not file_path.exists():
        flash("File not found", "warning")
        return redirect(url_for('list_files'))
    return send_file(str(file_path), as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
