Secure File Storage - PyQt5 GUI
==============================

What this app does:
- AES-256-GCM authenticated encryption for files.
- Stores encrypted package files with ".enc" extension in a local storage folder.
- Metadata (original filename, timestamp, SHA-256, size) is stored inside the encrypted package.
- Allows encrypting, listing, decrypting, and verifying integrity via GUI.

How to run (local desktop):
1. Create and activate a virtualenv:
   python -m venv venv
   source venv/bin/activate   (on Windows: venv\Scripts\activate)

2. Install requirements:
   pip install -r requirements.txt

3. Run the app:
   python main.py

First run generates a master key at ~/.sfs_gui/master.key — back this up. If you lose it, you cannot decrypt files.

Notes:
- For large files the app loads into memory. For production or very large files, implement streaming encryption.
- This is a desktop app for local use. If you need a web version for Render (server-side), ask and I will provide a Flask + S3 design.

Files included:
- main.py       (PyQt5 GUI)
- crypto.py     (crypto helpers using AES-GCM)
- requirements.txt
- README.md
