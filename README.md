Secure File Storage - Flask web app (AES-256-GCM)
=================================================

This project is a simple Flask web application that:
- Encrypts uploaded files using AES-256-GCM.
- Stores encrypted packages with a `.enc` extension in a storage folder.
- Stores file metadata (original filename, timestamp, SHA-256, size) inside the encrypted package.
- Allows downloading the `.enc` blob or downloading the decrypted file (server-side decrypt).

Important: Set environment variable `SFS_MASTER_KEY` to a urlsafe-base64 encoded 32-byte key before starting the server.
You can generate one locally with a small Python snippet or use the "Generate Test Master Key" button in the UI and copy it.

Deployment (Render):
1. Create a Web Service on Render and connect your repo.
2. Set the build command (Render runs pip install automatically).
3. Add environment variables:
   - SFS_MASTER_KEY (required)
   - FLASK_SECRET (recommended)
   - SFS_STORAGE_DIR (optional)
4. Use the provided Procfile or set the start command:
   `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1`

Storage persistence:
Render services have ephemeral filesystems by default. To persist files across deploys, use Render Volumes or an external object store (S3). If you want S3 support, I can add it.

Security notes:
- Protect the master key with Render secrets or a proper secrets manager.
- Add authentication before exposing this to the internet.
- Consider rate limits and file size limits.
