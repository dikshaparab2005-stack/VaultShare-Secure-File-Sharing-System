"""Encrypted file sharing application.

Run with: python app.py
For deployment, set FLASK_SECRET_KEY to a long random value and serve behind
HTTPS with a production WSGI server. The generated local keys must be backed up.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from logging.handlers import RotatingFileHandler

IST = timezone(timedelta(hours=5, minutes=30))

from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secure_file_sharing.db"
KEY_PATH = BASE_DIR / "secret.key"
SESSION_KEY_PATH = BASE_DIR / "session.key"
STORAGE_DIR = BASE_DIR / "encrypted_files"
DOWNLOAD_DIR = BASE_DIR / "downloads"
LOG_PATH = BASE_DIR / "activity.log"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
CLAMAV_HOST = os.environ.get("CLAMAV_HOST", "127.0.0.1")
CLAMAV_PORT = int(os.environ.get("CLAMAV_PORT", "3310"))
PBKDF2_ITERATIONS = 600_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or None,
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)


def ensure_secret(path: Path, generator) -> bytes:
    """Load/create a secret atomically and reject malformed existing secrets."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        value = path.read_bytes()
    except FileNotFoundError:
        value = generator()
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(value)
                out.flush()
                os.fsync(out.fileno())
        except FileExistsError:
            value = path.read_bytes()
    return value


FERNET_KEY = ensure_secret(KEY_PATH, Fernet.generate_key)
try:
    CIPHER = Fernet(FERNET_KEY)
except (ValueError, TypeError) as exc:
    raise RuntimeError(f"Encryption key at {KEY_PATH} is invalid") from exc
if not app.config["SECRET_KEY"]:
    app.config["SECRET_KEY"] = ensure_secret(SESSION_KEY_PATH, lambda: secrets.token_bytes(48))

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
handler = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=4, encoding="utf-8")
log_formatter = logging.Formatter("%(asctime)sZ\t%(message)s")
log_formatter.converter = time.gmtime
handler.setFormatter(log_formatter)
handler.setLevel(logging.INFO)
logger = logging.getLogger("secure_file_sharing")
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def log_action(username: str, action: str, status: str) -> None:
    clean_user = re.sub(r"[^A-Za-z0-9_.@-]", "_", username or "anonymous")[:80]
    clean_action = re.sub(r"[\r\n\t]", " ", action)[:160]
    clean_status = re.sub(r"[\r\n\t]", " ", status)[:80]
    logger.info("username=%s\taction=%s\tstatus=%s", clean_user, clean_action, clean_status)


def scan_file_with_clamav(content: bytes) -> dict[str, str | None]:
    """Check daemon availability, then scan in-memory bytes; fail closed on errors."""
    try:
        import clamd

        scanner = clamd.ClamdNetworkSocket(
            host=CLAMAV_HOST, port=CLAMAV_PORT, timeout=10
        )
        # A successful TCP connection alone is insufficient: verify this is
        # responding ClamAV before sending the upload for scanning.
        if scanner.ping() != "PONG":
            app.logger.error("ClamAV availability check returned an unexpected response")
            return {"status": "ERROR", "threat": None}
        response = scanner.instream(io.BytesIO(content))
        if not isinstance(response, dict) or len(response) != 1:
            return {"status": "ERROR", "threat": None}
        result = next(iter(response.values()))
        if not isinstance(result, (tuple, list)) or len(result) != 2:
            return {"status": "ERROR", "threat": None}
        scan_status, signature = result
        if scan_status == "OK" and signature is None:
            return {"status": "CLEAN", "threat": None}
        if scan_status == "FOUND" and isinstance(signature, str) and signature:
            safe_signature = re.sub(r"[^A-Za-z0-9_.-]", "_", signature)[:100]
            return {"status": "THREAT", "threat": safe_signature}
        return {"status": "ERROR", "threat": None}
    except Exception:
        # Keep connection details and exceptions in server logs only.
        app.logger.exception("ClamAV scan failed")
        return {"status": "ERROR", "threat": None}


@contextmanager
def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with connect_db() as db:
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL UNIQUE,
            file_hash TEXT NOT NULL,
            upload_time TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS shared_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            share_time TEXT NOT NULL,
            expiry_time TEXT,
            download_limit INTEGER,
            download_count INTEGER NOT NULL DEFAULT 0 CHECK(download_count >= 0),
            revoked_at TEXT,
            UNIQUE(file_id, receiver_id)
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            notification_type TEXT NOT NULL CHECK(notification_type IN ('file_shared','access_revoked','share_expired')),
            message TEXT NOT NULL,
            file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
            share_id INTEGER REFERENCES shared_files(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0 CHECK(is_read IN (0,1)),
            dedupe_key TEXT UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id);
        CREATE INDEX IF NOT EXISTS idx_shares_receiver ON shared_files(receiver_id);
        CREATE INDEX IF NOT EXISTS idx_notifications_recipient_created ON notifications(recipient_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(recipient_id, is_read);
        """)
        columns = {row[1] for row in db.execute("PRAGMA table_info(shared_files)")}
        if "revoked_at" not in columns:
            db.execute("ALTER TABLE shared_files ADD COLUMN revoked_at TEXT")


init_db()


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        with connect_db() as db:
            g.user = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
        if g.user is None:
            session.clear()
        else:
            create_expiry_notifications(g.user["id"])


def create_expiry_notifications(recipient_id: int) -> None:
    """Create one informational notice per share, only after its stored expiry."""
    now = utcnow()
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        rows = db.execute("""SELECT s.id,s.file_id,s.expiry_time,f.original_filename,u.username
            FROM shared_files s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.sender_id
            WHERE s.receiver_id=? AND s.expiry_time IS NOT NULL AND s.expiry_time<>''
              """, (recipient_id,)).fetchall()
        for row in rows:
            expiry = parse_iso(row["expiry_time"])
            if expiry and expiry <= now:
                db.execute("""INSERT OR IGNORE INTO notifications
                    (recipient_id,notification_type,message,file_id,share_id,created_at,dedupe_key)
                    VALUES(?,?,?,?,?,?,?)""",
                    (recipient_id, "share_expired", f"Access to {row['original_filename']} shared by {row['username']} has expired.",
                     row["file_id"], row["id"], now.isoformat(), f"share-expired:{row['id']}"))
        db.commit()


@app.before_request
def csrf_protect():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            log_action(g.user["username"] if g.user else "anonymous", "CSRF validation", "DENIED")
            abort(400, description="Your form expired. Please try again.")


@app.context_processor
def inject_template_values():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    unread_count = 0
    if g.user:
        with connect_db() as db:
            unread_count = db.execute("SELECT COUNT(*) FROM notifications WHERE recipient_id=? AND is_read=0",
                                      (g.user["id"],)).fetchone()[0]
    return {"csrf_token": session["csrf_token"], "current_year": utcnow().year,
            "unread_notification_count": unread_count}


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)


def parse_iso(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def verify_and_read(file_row):
    """Decrypt file and verify digest. Return bytes or raise a safe exception."""
    path = STORAGE_DIR / file_row["stored_filename"]
    if path.parent.resolve() != STORAGE_DIR.resolve() or not path.is_file():
        raise FileNotFoundError
    encrypted = path.read_bytes()
    plain = CIPHER.decrypt(encrypted)
    digest = hashlib.sha256(plain).hexdigest()
    if not hmac.compare_digest(digest, file_row["file_hash"]):
        raise ValueError("integrity")
    return plain


@app.route("/")
def index():
    return redirect(url_for("dashboard") if g.user else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not USERNAME_RE.fullmatch(username):
            flash("Use 3–32 letters, numbers, dots, underscores, or hyphens for your username.", "error")
        elif len(password) < 12 or len(password) > 1024:
            flash("Password must be at least 12 characters long.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            salt = os.urandom(16)
            digest = password_digest(password, salt)
            try:
                with connect_db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("INSERT INTO users(username,password_hash,salt,created_at) VALUES(?,?,?,?)",
                               (username, digest, salt, utcnow().isoformat()))
                    db.commit()
                log_action(username, "Registration", "SUCCESS")
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already registered.", "error")
            except sqlite3.Error:
                log_action(username, "Registration", "ERROR")
                app.logger.exception("Registration database failure")
                flash("Account could not be created. Please try again.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        valid = False
        if user:
            try:
                valid = hmac.compare_digest(password_digest(password, user["salt"]), user["password_hash"])
            except (ValueError, TypeError):
                valid = False
        if valid:
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            log_action(user["username"], "Login", "SUCCESS")
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
        log_action(username or "anonymous", "Failed Login", "DENIED")
        flash("Invalid credentials.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_action(g.user["username"], "Logout", "SUCCESS")
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    with connect_db() as db:
        stats = {
            "files": db.execute("SELECT COUNT(*) FROM files WHERE owner_id=?", (g.user["id"],)).fetchone()[0],
            "received": db.execute("SELECT COUNT(*) FROM shared_files WHERE receiver_id=?", (g.user["id"],)).fetchone()[0],
            "shared": db.execute("SELECT COUNT(*) FROM shared_files WHERE sender_id=?", (g.user["id"],)).fetchone()[0],
        }
    return render_template("dashboard.html", stats=stats)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploads = [item for item in request.files.getlist("file") if item and item.filename]
        if not uploads:
            flash("Choose a file to upload.", "error")
            return redirect(url_for("upload"))
        for uploaded in uploads:
            original = secure_filename(uploaded.filename)
            if not original:
                flash(f"{uploaded.filename}: filename is not valid.", "error")
                continue
            target = STORAGE_DIR / f"{uuid.uuid4().hex}.enc"
            stored_on_disk = False
            try:
                content = uploaded.read(MAX_UPLOAD_BYTES + 1)
                if len(content) > MAX_UPLOAD_BYTES:
                    flash(f"{original}: exceeds the 50 MB upload limit.", "error")
                    continue
                scan = scan_file_with_clamav(content)
                if scan["status"] == "THREAT":
                    detail = f" threat={scan['threat']}" if scan["threat"] else ""
                    log_action(g.user["username"], f"MALWARE_DETECTED file={original}{detail}", "REJECTED")
                    flash(f"{original}: rejected because malware was detected.", "error")
                    continue
                if scan["status"] != "CLEAN":
                    log_action(g.user["username"], f"MALWARE_SCAN file={original}", "ERROR")
                    flash(f"{original}: malware scanner is unavailable; file rejected.", "error")
                    continue
                log_action(g.user["username"], f"MALWARE_SCAN file={original}", "CLEAN")
                digest = hashlib.sha256(content).hexdigest()
                ciphertext = CIPHER.encrypt(content)
                with target.open("xb") as out:
                    out.write(ciphertext)
                stored_on_disk = True
                with connect_db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("INSERT INTO files(owner_id,original_filename,stored_filename,file_hash,upload_time) VALUES(?,?,?,?,?)",
                               (g.user["id"], original, target.name, digest, utcnow().isoformat()))
                    db.commit()
                log_action(g.user["username"], f"Upload file={original}", "SUCCESS")
                flash(f"{original}: scanned, encrypted, and uploaded successfully.", "success")
            except (OSError, sqlite3.Error, ValueError):
                if stored_on_disk:
                    target.unlink(missing_ok=True)
                log_action(g.user["username"], f"Upload file={original}", "ERROR")
                app.logger.exception("Upload failed")
                flash(f"{original}: upload failed. Please try again.", "error")
            except Exception:
                if stored_on_disk:
                    target.unlink(missing_ok=True)
                log_action(g.user["username"], f"Upload file={original}", "ERROR")
                app.logger.exception("Unexpected upload failure")
                flash(f"{original}: upload failed. Please try again.", "error")
        return redirect(url_for("my_files"))
    return render_template("upload.html", max_mb=MAX_UPLOAD_BYTES // (1024 * 1024))


@app.route("/files")
@login_required
def my_files():
    with connect_db() as db:
        files = db.execute("SELECT * FROM files WHERE owner_id=? ORDER BY upload_time DESC", (g.user["id"],)).fetchall()
        shares = db.execute("""SELECT s.id,s.revoked_at,s.receiver_id,f.original_filename,u.username AS receiver_name
            FROM shared_files s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.receiver_id
            WHERE s.sender_id=? ORDER BY s.share_time DESC""", (g.user["id"],)).fetchall()
    return render_template("my_files.html", files=files, shares=shares)


@app.route("/files/<file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    username = g.user["username"]
    if not re.fullmatch(r"[1-9][0-9]*", file_id):
        flash("Unable to delete the file. Please try again.", "error")
        return redirect(url_for("my_files"))

    try:
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id,stored_filename FROM files WHERE id=? AND owner_id=?",
                (int(file_id), g.user["id"]),
            ).fetchone()
            if row is None:
                db.rollback()
                log_action(username, "Delete file", "DENIED")
                flash("Unable to delete the file. Please try again.", "error")
                return redirect(url_for("my_files"))

            stored_filename = row["stored_filename"]
            stored_path = STORAGE_DIR / stored_filename
            if (Path(stored_filename).name != stored_filename
                    or stored_path.parent.resolve() != STORAGE_DIR.resolve()):
                raise OSError("Invalid stored filename")

            # Missing encrypted data is safe to clean up: remove only this
            # owner's stale metadata and its cascading share records.
            if stored_path.exists():
                stored_path.unlink()
            db.execute("DELETE FROM files WHERE id=? AND owner_id=?", (row["id"], g.user["id"]))
            db.commit()
        log_action(username, f"Delete file_id={file_id}", "SUCCESS")
        flash("File deleted successfully.", "success")
    except (OSError, sqlite3.Error, ValueError):
        log_action(username, f"Delete file_id={file_id}", "ERROR")
        app.logger.exception("File deletion failed")
        flash("Unable to delete the file. Please try again.", "error")
    return redirect(url_for("my_files"))


@app.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id):
    with connect_db() as db:
        file_row = db.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, g.user["id"])).fetchone()
        if not file_row:
            log_action(g.user["username"], "Unauthorized Access to share", "DENIED")
            abort(404)
        if request.method == "POST":
            receiver_names = list(dict.fromkeys(name.strip() for name in request.form.getlist("username") if name.strip()))
            expiry_hours = request.form.get("expiry_hours", "")
            limit_text = request.form.get("download_limit", "")
            if not receiver_names:
                flash("Select at least one registered user.", "error")
                receivers = []
            elif any(not USERNAME_RE.fullmatch(name) for name in receiver_names):
                flash("One or more selected usernames are invalid.", "error")
                receivers = []
            else:
                placeholders = ",".join("?" for _ in receiver_names)
                receivers = db.execute(f"SELECT id,username FROM users WHERE username COLLATE NOCASE IN ({placeholders})", receiver_names).fetchall()
                if len(receivers) != len(receiver_names):
                    flash("One or more selected users are not registered.", "error")
                    receivers = []
            if receivers and any(receiver["id"] == g.user["id"] for receiver in receivers):
                flash("You cannot share a file with yourself.", "error")
                receivers = []
            if receivers:
                try:
                    expiry = None
                    if expiry_hours:
                        hours = int(expiry_hours)
                        if not 1 <= hours <= 8760:
                            raise ValueError
                        expiry = (utcnow() + timedelta(hours=hours)).isoformat()
                    limit = int(limit_text) if limit_text else None
                    if limit is not None and not 1 <= limit <= 100000:
                        raise ValueError
                except (ValueError, OverflowError):
                    flash("Expiry must be 1–8760 hours and download limit 1–100000 (or blank for no limit).", "error")
                else:
                    try:
                        db.execute("BEGIN IMMEDIATE")
                        share_time = utcnow().isoformat()
                        for receiver in receivers:
                            previous = db.execute("SELECT id,revoked_at FROM shared_files WHERE file_id=? AND receiver_id=?",
                                                  (file_id, receiver["id"])).fetchone()
                            db.execute("""INSERT INTO shared_files(file_id,sender_id,receiver_id,share_time,expiry_time,download_limit,download_count)
                                          VALUES(?,?,?,?,?,?,0)
                                          ON CONFLICT(file_id,receiver_id) DO UPDATE SET sender_id=excluded.sender_id,
                                          share_time=excluded.share_time, expiry_time=excluded.expiry_time,
                                          download_limit=excluded.download_limit, download_count=0, revoked_at=NULL""",
                                       (file_id, g.user["id"], receiver["id"], share_time, expiry, limit))
                            share_row = db.execute("SELECT id FROM shared_files WHERE file_id=? AND receiver_id=?",
                                                   (file_id, receiver["id"])).fetchone()
                            if not previous or previous["revoked_at"]:
                                db.execute("""INSERT OR IGNORE INTO notifications
                                    (recipient_id,notification_type,message,file_id,share_id,created_at,dedupe_key)
                                    VALUES(?,?,?,?,?,?,?)""",
                                    (receiver["id"], "file_shared",
                                     f"{g.user['username']} shared {file_row['original_filename']} with you.",
                                     file_id, share_row["id"], share_time,
                                     f"file-shared:{share_row['id']}:{share_time}"))
                        db.commit()
                        recipient_names = ", ".join(receiver["username"] for receiver in receivers)
                        log_action(g.user["username"], f"Share file_id={file_id} with={recipient_names}", "SUCCESS")
                        flash(f"File shared with {recipient_names}.", "success")
                        return redirect(url_for("my_files"))
                    except sqlite3.Error:
                        db.rollback()
                        log_action(g.user["username"], f"Share file_id={file_id}", "ERROR")
                        flash("Could not share this file. Please try again.", "error")
        recipients = db.execute("SELECT username FROM users WHERE id<>? ORDER BY username COLLATE NOCASE", (g.user["id"],)).fetchall()
    return render_template("share.html", file=file_row, recipients=recipients)


@app.route("/share-files", methods=["GET", "POST"])
@login_required
def share_files():
    with connect_db() as db:
        files = db.execute("SELECT id,original_filename FROM files WHERE owner_id=? ORDER BY upload_time DESC",
                           (g.user["id"],)).fetchall()
        recipients = db.execute("SELECT username FROM users WHERE id<>? ORDER BY username COLLATE NOCASE",
                                (g.user["id"],)).fetchall()
        if request.method == "POST":
            file_ids = list(dict.fromkeys(request.form.getlist("file_id")))
            receiver_names = list(dict.fromkeys(name.strip() for name in request.form.getlist("username") if name.strip()))
            selected = []
            if not file_ids or any(not re.fullmatch(r"[1-9][0-9]*", value) for value in file_ids):
                flash("Select at least one file you own.", "error")
            else:
                placeholders = ",".join("?" for _ in file_ids)
                selected = db.execute(f"SELECT id,original_filename FROM files WHERE owner_id=? AND id IN ({placeholders})",
                                      [g.user["id"], *[int(value) for value in file_ids]]).fetchall()
                if len(selected) != len(file_ids):
                    flash("One or more selected files are unavailable.", "error")
                    selected = []
            receivers = []
            if not receiver_names:
                flash("Select at least one registered user.", "error")
            elif any(not USERNAME_RE.fullmatch(name) for name in receiver_names):
                flash("One or more selected usernames are invalid.", "error")
            else:
                placeholders = ",".join("?" for _ in receiver_names)
                receivers = db.execute(f"SELECT id,username FROM users WHERE username COLLATE NOCASE IN ({placeholders})",
                                       receiver_names).fetchall()
                if len(receivers) != len(receiver_names):
                    flash("One or more selected users are not registered.", "error")
                    receivers = []
            if receivers and any(receiver["id"] == g.user["id"] for receiver in receivers):
                flash("You cannot share files with yourself.", "error")
                receivers = []
            if selected and receivers:
                try:
                    expiry_hours = request.form.get("expiry_hours", "")
                    expiry = None
                    if expiry_hours:
                        hours = int(expiry_hours)
                        if not 1 <= hours <= 8760:
                            raise ValueError
                        expiry = (utcnow() + timedelta(hours=hours)).isoformat()
                    limit_text = request.form.get("download_limit", "")
                    limit = int(limit_text) if limit_text else None
                    if limit is not None and not 1 <= limit <= 100000:
                        raise ValueError
                except (ValueError, OverflowError):
                    flash("Expiry must be 1–8760 hours and download limit 1–100000 (or blank for no limit).", "error")
                else:
                    try:
                        db.execute("BEGIN IMMEDIATE")
                        share_time = utcnow().isoformat()
                        for file_row in selected:
                            for receiver in receivers:
                                previous = db.execute("SELECT id,revoked_at FROM shared_files WHERE file_id=? AND receiver_id=?",
                                                      (file_row["id"], receiver["id"])).fetchone()
                                db.execute("""INSERT INTO shared_files(file_id,sender_id,receiver_id,share_time,expiry_time,download_limit,download_count)
                                              VALUES(?,?,?,?,?,?,0)
                                              ON CONFLICT(file_id,receiver_id) DO UPDATE SET sender_id=excluded.sender_id,
                                              share_time=excluded.share_time, expiry_time=excluded.expiry_time,
                                              download_limit=excluded.download_limit, download_count=0, revoked_at=NULL""",
                                           (file_row["id"], g.user["id"], receiver["id"], share_time, expiry, limit))
                                share_row = db.execute("SELECT id FROM shared_files WHERE file_id=? AND receiver_id=?",
                                                       (file_row["id"], receiver["id"])).fetchone()
                                if not previous or previous["revoked_at"]:
                                    db.execute("""INSERT OR IGNORE INTO notifications
                                        (recipient_id,notification_type,message,file_id,share_id,created_at,dedupe_key)
                                        VALUES(?,?,?,?,?,?,?)""",
                                        (receiver["id"], "file_shared",
                                         f"{g.user['username']} shared {file_row['original_filename']} with you.",
                                         file_row["id"], share_row["id"], share_time,
                                         f"file-shared:{share_row['id']}:{share_time}"))
                        db.commit()
                        log_action(g.user["username"], f"Share files={len(selected)} recipients={len(receivers)}", "SUCCESS")
                        flash(f"{len(selected)} file(s) shared with {len(receivers)} recipient(s).", "success")
                        return redirect(url_for("my_files"))
                    except sqlite3.Error:
                        db.rollback()
                        log_action(g.user["username"], "Share multiple files", "ERROR")
                        flash("Could not share the selected files. Please try again.", "error")
    return render_template("share.html", files=files, recipients=recipients)


@app.route("/shared")
@login_required
def shared_with_me():
    with connect_db() as db:
        shares = db.execute("""SELECT s.*, f.original_filename, f.upload_time, u.username AS sender_name
            FROM shared_files s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.sender_id
            WHERE s.receiver_id=? ORDER BY s.share_time DESC""", (g.user["id"],)).fetchall()
    now = utcnow()
    items = []
    for row in shares:
        expiry = parse_iso(row["expiry_time"])
        expired = bool(row["expiry_time"] and (expiry is None or expiry <= now))
        exhausted = row["download_limit"] is not None and row["download_count"] >= row["download_limit"]
        item = dict(row)
        item.update(expired=expired, exhausted=exhausted, revoked=bool(row["revoked_at"]),
                    expiry_display=expiry.astimezone(IST).strftime("%Y-%m-%d %H:%M") if expiry else None,
                    remaining=None if row["download_limit"] is None else max(0, row["download_limit"] - row["download_count"]))
        items.append(item)
    return render_template("shared_with_me.html", shares=items)


@app.route("/download/<int:share_id>")
@login_required
def download_shared(share_id):
    username = g.user["username"]
    try:
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""SELECT s.*, f.original_filename, f.stored_filename, f.file_hash
                FROM shared_files s JOIN files f ON f.id=s.file_id WHERE s.id=? AND s.receiver_id=?""",
                            (share_id, g.user["id"])).fetchone()
            if not row:
                db.rollback()
                log_action(username, "Unauthorized Access to download", "DENIED")
                abort(404)
            if row["revoked_at"]:
                db.rollback()
                log_action(username, f"Revoked share denial share_id={share_id}", "DENIED")
                flash("Access denied: the sender revoked this share.", "error")
                return redirect(url_for("shared_with_me"))
            expiry = parse_iso(row["expiry_time"])
            if row["expiry_time"] and (expiry is None or utcnow() >= expiry):
                db.rollback()
                log_action(username, f"Expiry Denial share_id={share_id}", "DENIED")
                flash("Access denied: sharing link expired.", "error")
                return redirect(url_for("shared_with_me"))


            if row["download_limit"] is not None and row["download_count"] >= row["download_limit"]:
                db.rollback()
                log_action(username, f"Download limit denial share_id={share_id}", "DENIED")
                flash("Access denied: download limit reached.", "error")
                return redirect(url_for("shared_with_me"))
            try:
                content = verify_and_read(row)
            except ValueError as exc:
                db.rollback()
                if str(exc) == "integrity":
                    log_action(username, f"Integrity Failure share_id={share_id}", "FAILED")
                    flash("Integrity verification failed. The file was not downloaded.", "error")
                else:
                    log_action(username, f"Decrypt Failure share_id={share_id}", "FAILED")
                    flash("The encrypted file could not be verified.", "error")
                return redirect(url_for("shared_with_me"))
            except (OSError, InvalidToken, FileNotFoundError):
                db.rollback()
                log_action(username, f"Decrypt Failure share_id={share_id}", "FAILED")
                flash("The encrypted file is unavailable or damaged.", "error")
                return redirect(url_for("shared_with_me"))
            db.execute("UPDATE shared_files SET download_count=download_count+1 WHERE id=?", (share_id,))
            db.commit()
        log_action(username, f"Download share_id={share_id}", "SUCCESS")
        return send_file(io.BytesIO(content), as_attachment=True, download_name=row["original_filename"], mimetype="application/octet-stream")
    except sqlite3.Error:
        log_action(username, f"Download share_id={share_id}", "ERROR")
        app.logger.exception("Download database error")
        flash("Download could not be completed.", "error")
        return redirect(url_for("shared_with_me"))


@app.route("/shares/<int:share_id>/revoke", methods=["POST"])
@login_required
def revoke_share(share_id):
    with connect_db() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("""SELECT s.id,s.file_id,s.receiver_id,f.original_filename,u.username
            FROM shared_files s JOIN files f ON f.id=s.file_id JOIN users u ON u.id=s.receiver_id
            WHERE s.id=? AND s.sender_id=?""", (share_id, g.user["id"])).fetchone()
        if row is None:
            db.rollback()
            log_action(g.user["username"], f"Revoke share_id={share_id}", "DENIED")
            abort(404)
        revoked_at = utcnow().isoformat()
        db.execute("UPDATE shared_files SET revoked_at=? WHERE id=? AND sender_id=? AND revoked_at IS NULL",
                   (revoked_at, share_id, g.user["id"]))
        if db.execute("SELECT changes()").fetchone()[0]:
            db.execute("""INSERT INTO notifications
                (recipient_id,notification_type,message,file_id,share_id,created_at,dedupe_key)
                VALUES(?,?,?,?,?,?,?)""",
                (row["receiver_id"], "access_revoked",
                 f"{g.user['username']} revoked your access to {row['original_filename']}.",
                 row["file_id"], row["id"], revoked_at, f"access-revoked:{row['id']}:{revoked_at}"))
            log_action(g.user["username"], f"Revoke share_id={share_id} recipient={row['username']}", "SUCCESS")
        db.commit()
    flash("File access revoked.", "success")
    return redirect(url_for("my_files"))


@app.route("/notifications")
@login_required
def notifications():
    with connect_db() as db:
        rows = db.execute("SELECT * FROM notifications WHERE recipient_id=? ORDER BY created_at DESC,id DESC",
                          (g.user["id"],)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        parsed = parse_iso(row["created_at"])
        item["created_display"] = parsed.astimezone(IST).strftime("%Y-%m-%d %H:%M") if parsed else row["created_at"]
        items.append(item)
    return render_template("notifications.html", notifications=items)


@app.route("/notifications/<notification_id>/read", methods=["POST"])
@login_required
def mark_notification_read(notification_id):
    if not re.fullmatch(r"[1-9][0-9]*", notification_id):
        abort(404)
    with connect_db() as db:
        changed = db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND recipient_id=?",
                             (int(notification_id), g.user["id"])).rowcount
    if not changed:
        abort(404)
    return redirect(url_for("notifications"))
@app.route("/download/owned/<int:file_id>")
@login_required
def download_owned(file_id):
    username = g.user["username"]
    with connect_db() as db:
        row = db.execute("SELECT * FROM files WHERE id=? AND owner_id=?", (file_id, g.user["id"])).fetchone()
    if not row:
        log_action(username, "Unauthorized Access to owned download", "DENIED")
        abort(404)
    try:
        content = verify_and_read(row)
    except (ValueError, InvalidToken, OSError, FileNotFoundError):
        log_action(username, f"Integrity Failure file_id={file_id}", "FAILED")
        flash("Integrity verification failed. The file was not downloaded.", "error")
        return redirect(url_for("my_files"))
    log_action(username, f"Download owned file_id={file_id}", "SUCCESS")
    return send_file(io.BytesIO(content), as_attachment=True, download_name=row["original_filename"], mimetype="application/octet-stream")


@app.route("/logs")
@login_required
def logs():
    entries = []
    try:
        if LOG_PATH.exists():
            for line in LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()[-1000:]:
                # Activity log content is restricted to the signed-in user's account.
                if f"username={g.user['username']}\t" in line:
                    parts = line.split("\t")
                    entries.append({"timestamp": parts[0].removesuffix("Z"), "action": "", "status": ""})
                    for part in parts[1:]:
                        if part.startswith("action="): entries[-1]["action"] = part[7:]
                        if part.startswith("status="): entries[-1]["status"] = part[7:]
    except OSError:
        flash("Activity log is temporarily unavailable.", "warning")
    entries.reverse()
    return render_template("logs.html", entries=entries[:200])


@app.errorhandler(RequestEntityTooLarge)
def too_large(_error):
    flash("File exceeds the 50 MB upload limit.", "error")
    return redirect(url_for("upload"))


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "Bad request")), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested resource was not found."), 404


@app.errorhandler(500)
def internal_error(_error):
    app.logger.exception("Unhandled application error")
    return render_template("error.html", code=500, message="An unexpected error occurred."), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
