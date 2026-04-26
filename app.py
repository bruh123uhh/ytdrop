"""
YTDROP v5 — Flask backend
Seguridad, autenticación, suscripciones, biblioteca, admin spy panel
"""

import os
import re
import json
import uuid
import time
import hashlib
import secrets
import threading
from pathlib import Path
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict

from flask import (
    Flask, request, jsonify, send_file,
    render_template, abort, session, redirect
)
import yt_dlp

# ─────────────────────────────────────────────
# APP CONFIG
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,   # Set True on HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

DOWNLOAD_DIR = os.environ.get("DOWNLOAD_FOLDER", "downloads")
DATA_FILE    = os.environ.get("DATA_FILE", "data/db.json")
FILE_TTL     = 86400   # delete files after 24h
COOKIES_FILE = os.environ.get("COOKIES_FILE", "data/cookies.txt")

os.makedirs(DOWNLOAD_DIR, exist_ok=True)
os.makedirs("data", exist_ok=True)

tasks: dict = {}          # task_id -> progress dict
_db_lock = threading.Lock()

# ─────────────────────────────────────────────
# PLANS
# ─────────────────────────────────────────────
PLANS = {
    "free": {
        "name": "Free", "price": 0, "icon": "🆓", "color": "#5a6478",
        "downloads_day": 3, "max_quality": "128",
        "formats": ["mp3"],
    },
    "basic": {
        "name": "Basic", "price": 4.99, "icon": "⭐", "color": "#00cfff",
        "downloads_day": 20, "max_quality": "192",
        "formats": ["mp3", "m4a"],
    },
    "medium": {
        "name": "Medium", "price": 9.99, "icon": "💜", "color": "#a855f7",
        "downloads_day": 50, "max_quality": "256",
        "formats": ["mp3", "m4a", "wav"],
    },
    "premium": {
        "name": "Premium", "price": 19.99, "icon": "👑", "color": "#ffe234",
        "downloads_day": 9999, "max_quality": "320",
        "formats": ["mp3", "m4a", "wav", "mp4"],
    },
}

# ─────────────────────────────────────────────
# RATE LIMITING
# ─────────────────────────────────────────────
_rate: dict = defaultdict(list)   # ip -> [timestamps]
_banned_ips: set = set()
RATE_MAX = 10
RATE_WIN = 300   # 5 min


def get_ip() -> str:
    return (
        request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
        .split(",")[0].strip()
    )


def rate_ok(ip: str) -> bool:
    if ip in _banned_ips:
        return False
    now = time.time()
    _rate[ip] = [t for t in _rate[ip] if now - t < RATE_WIN]
    if len(_rate[ip]) >= RATE_MAX:
        _banned_ips.add(ip)
        return False
    _rate[ip].append(now)
    return True


def clear_rate(ip: str) -> None:
    _rate.pop(ip, None)
    _banned_ips.discard(ip)


# ─────────────────────────────────────────────
# DB HELPERS
# ─────────────────────────────────────────────
def _empty_db() -> dict:
    return {
        "users": {},
        "library": {},
        "activity": {},
        "searches": {},
        "plays": {},
        "notes": {},
    }


def load_db() -> dict:
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                db = json.load(f)
                # Ensure all top-level keys exist
                for k in ("library", "activity", "searches", "plays", "notes"):
                    db.setdefault(k, {})
                return db
        except Exception:
            pass
    return _empty_db()


def save_db(db: dict) -> None:
    with _db_lock:
        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2, ensure_ascii=False)
        os.replace(tmp, DATA_FILE)


# ─────────────────────────────────────────────
# PASSWORD HASHING  (PBKDF2-SHA256, 300k rounds)
# ─────────────────────────────────────────────
def hash_pw(pw: str, salt: str = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 300_000)
    return f"{salt}:{h.hex()}"


def verify_pw(pw: str, stored: str) -> bool:
    try:
        if ":" in stored:
            salt, _ = stored.split(":", 1)
            return secrets.compare_digest(hash_pw(pw, salt), stored)
        return secrets.compare_digest(
            hashlib.sha256(pw.encode()).hexdigest(), stored
        )
    except Exception:
        return False


# ─────────────────────────────────────────────
# SEED ADMIN
# usuario: admin  /  contrasena: admin123
# Se resetea en cada arranque para garantizar acceso
# ─────────────────────────────────────────────
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

def _seed():
    db = load_db()
    if ADMIN_USER not in db["users"]:
        db["users"][ADMIN_USER] = {
            "id": ADMIN_USER, "username": ADMIN_USER,
            "email": "admin@ytdrop.com",
            "password": hash_pw(ADMIN_PASS),
            "plan": "premium", "role": "admin", "is_banned": False,
            "created_at": datetime.now().isoformat(),
            "last_seen": "", "login_count": 0, "reg_ip": "localhost",
            "avatar": "\U0001f451", "bio": "Administrador del sistema",
            "downloads_today": 0, "last_download_date": "",
            "total_downloads": 0, "total_searches": 0, "total_plays": 0,
        }
        for k in ("library", "activity", "searches", "plays", "notes"):
            db.setdefault(k, {})[ADMIN_USER] = []
    else:
        # Siempre resetea la contrasena del admin al arrancar
        db["users"][ADMIN_USER]["password"]  = hash_pw(ADMIN_PASS)
        db["users"][ADMIN_USER]["role"]      = "admin"
        db["users"][ADMIN_USER]["plan"]      = "premium"
        db["users"][ADMIN_USER]["is_banned"] = False
    save_db(db)


_seed()


# ─────────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────────
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = load_db()
    u = db["users"].get(uid)
    if u and u.get("is_banned"):
        session.clear()
        return None
    return u


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            if request.is_json:
                return jsonify({"error": "No autenticado", "redirect": "/login"}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or u.get("role") != "admin":
            if request.is_json:
                return jsonify({"error": "Acceso denegado"}), 403
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper


def check_dl_limit(user: dict):
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
    if plan["downloads_day"] >= 9999:
        return True, ""
    today = datetime.now().strftime("%Y-%m-%d")
    if user.get("last_download_date") != today:
        return True, ""
    if user.get("downloads_today", 0) >= plan["downloads_day"]:
        return False, f"Límite diario de {plan['downloads_day']} descargas alcanzado."
    return True, ""


def bump_dl(uid: str) -> None:
    db = load_db()
    u = db["users"].get(uid)
    if not u:
        return
    today = datetime.now().strftime("%Y-%m-%d")
    if u.get("last_download_date") != today:
        u["downloads_today"] = 0
        u["last_download_date"] = today
    u["downloads_today"] = u.get("downloads_today", 0) + 1
    u["total_downloads"] = u.get("total_downloads", 0) + 1
    save_db(db)


# ─────────────────────────────────────────────
# ACTIVITY / LOGGING
# ─────────────────────────────────────────────
ACTION_ICONS = {
    "login": "🔑", "logout": "🚪", "register": "✨",
    "download": "⬇", "download_error": "⚠", "search": "🔍",
    "play": "▶", "library_delete": "🗑", "plan_changed": "⭐",
    "password_change": "🔐", "profile_update": "✏",
    "ban": "🚫", "unban": "✅",
    "admin_plan": "⚙", "admin_role": "🎭",
    "admin_delete": "💀", "admin_create": "➕",
    "admin_note": "📝", "admin_reset_pw": "🔑",
}


def log(uid: str, action: str, detail: str = "", extra: dict = None) -> None:
    db = load_db()
    db.setdefault("activity", {}).setdefault(uid, [])
    entry = {
        "ts": datetime.now().isoformat(),
        "action": action,
        "detail": detail[:300],
        "ip": get_ip(),
        "ua": request.headers.get("User-Agent", "")[:120],
    }
    if extra:
        entry.update(extra)
    db["activity"][uid].insert(0, entry)
    db["activity"][uid] = db["activity"][uid][:500]
    save_db(db)


def log_search(uid: str, query: str) -> None:
    db = load_db()
    db.setdefault("searches", {}).setdefault(uid, [])
    db["searches"][uid].insert(0, {
        "ts": datetime.now().isoformat(),
        "query": query[:200],
        "ip": get_ip(),
    })
    db["searches"][uid] = db["searches"][uid][:300]
    db["users"][uid]["total_searches"] = db["users"][uid].get("total_searches", 0) + 1
    save_db(db)


def log_play(uid: str, title: str, thumbnail: str, task_id: str, duration: int) -> None:
    db = load_db()
    db.setdefault("plays", {}).setdefault(uid, [])
    db["plays"][uid].insert(0, {
        "ts": datetime.now().isoformat(),
        "title": title[:200],
        "thumbnail": thumbnail,
        "task_id": task_id,
        "duration": duration,
        "ip": get_ip(),
    })
    db["plays"][uid] = db["plays"][uid][:300]
    db["users"][uid]["total_plays"] = db["users"][uid].get("total_plays", 0) + 1
    save_db(db)


def add_library(uid: str, entry: dict) -> None:
    db = load_db()
    db.setdefault("library", {}).setdefault(uid, [])
    db["library"][uid].insert(0, entry)
    db["library"][uid] = db["library"][uid][:300]
    save_db(db)


# ─────────────────────────────────────────────
# FILE UTILS
# ─────────────────────────────────────────────
def clean_old_files() -> None:
    now = time.time()
    for fname in os.listdir(DOWNLOAD_DIR):
        fp = os.path.join(DOWNLOAD_DIR, fname)
        if os.path.isfile(fp) and now - os.path.getmtime(fp) > FILE_TTL:
            try:
                os.remove(fp)
            except OSError:
                pass


def fmt_bytes(b) -> str:
    if not b:
        return "—"
    b = int(b)
    return f"{b/1_000_000:.1f} MB" if b >= 1_000_000 else f"{b/1_000:.0f} KB"


# ─────────────────────────────────────────────
# DOWNLOAD WORKER
# ─────────────────────────────────────────────
def make_hook(tid: str):
    def hook(d):
        if d["status"] == "downloading":
            tot = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
            dl  = d.get("downloaded_bytes", 0)
            tasks[tid].update({
                "status": "downloading",
                "percent": int((dl / tot) * 100) if tot else 0,
                "speed": fmt_bytes(d.get("speed") or 0) + "/s",
                "eta": f"{d.get('eta', 0)}s",
                "downloaded": fmt_bytes(dl),
                "total": fmt_bytes(tot),
            })
        elif d["status"] == "finished":
            tasks[tid].update({"status": "processing", "percent": 99})
    return hook


def get_ydl_base_opts() -> dict:
    """Base yt-dlp options — adds cookies and spoofs browser if available."""
    opts = {
        "quiet": True,
        "no_warnings": True,
        "http_headers": {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        "extractor_args": {
            "youtube": {
                "player_client": ["android", "web"],
            }
        },
        # Always try to avoid bot detection
        "sleep_interval": 1,
        "max_sleep_interval": 3,
    }
    # Add cookies if the file exists
    if os.path.exists(COOKIES_FILE):
        opts["cookiefile"] = COOKIES_FILE
    return opts


def dl_worker(url: str, tid: str, fmt: str, quality: str, uid: str,
              start_t=None, end_t=None) -> None:
    clean_old_files()
    try:
        out = os.path.join(DOWNLOAD_DIR, f"{tid}_%(title)s.%(ext)s")
        opts = get_ydl_base_opts()
        opts.update({
            "outtmpl": out,
            "progress_hooks": [make_hook(tid)],
            "noplaylist": True,
        })

        if start_t or end_t:
            sec = {}
            if start_t:
                sec["start_time"] = start_t
            if end_t:
                sec["end_time"] = end_t
            opts["download_ranges"] = yt_dlp.utils.download_range_func(None, [sec])
            opts["force_keyframes_at_cuts"] = True

        if fmt == "mp3":
            opts["format"] = "bestaudio/best"
            opts["postprocessors"] = [
                {"key": "FFmpegExtractAudio", "preferredcodec": "mp3",
                 "preferredquality": quality},
                {"key": "EmbedThumbnail"},
                {"key": "FFmpegMetadata"},
            ]
            opts["writethumbnail"] = True
        elif fmt == "mp4":
            opts["format"] = "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best"
            opts["merge_output_format"] = "mp4"
        elif fmt == "wav":
            opts["format"] = "bestaudio/best"
            opts["postprocessors"] = [
                {"key": "FFmpegExtractAudio", "preferredcodec": "wav"},
            ]
        elif fmt == "m4a":
            opts["format"] = "bestaudio[ext=m4a]/bestaudio/best"
            opts["postprocessors"] = [
                {"key": "FFmpegExtractAudio", "preferredcodec": "m4a"},
            ]

        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(url, download=True)

        title     = info.get("title", "audio")
        artist    = info.get("artist") or info.get("uploader", "Unknown")
        duration  = info.get("duration", 0)
        thumbnail = info.get("thumbnail", "")

        found = next(
            (os.path.join(DOWNLOAD_DIR, f) for f in sorted(os.listdir(DOWNLOAD_DIR))
             if f.startswith(tid) and not f.endswith((".jpg", ".webp", ".png"))),
            None,
        )

        if found and os.path.exists(found):
            sz = fmt_bytes(os.path.getsize(found))
            tasks[tid] = {
                "status": "done", "percent": 100, "filename": found,
                "title": title, "artist": artist, "duration": duration,
                "thumbnail": thumbnail, "filesize": sz,
                "format": fmt.upper(), "task_id": tid,
            }
            bump_dl(uid)
            add_library(uid, {
                "task_id": tid, "title": title, "artist": artist,
                "duration": duration, "thumbnail": thumbnail,
                "filesize": sz, "format": fmt.upper(), "url": url,
                "downloaded_at": datetime.now().isoformat(),
            })
            log(uid, "download", f"{title} [{fmt.upper()}]",
                {"title": title, "thumbnail": thumbnail, "url": url,
                 "fmt": fmt, "filesize": sz})
        else:
            tasks[tid] = {"status": "error", "message": "Archivo no encontrado."}

    except yt_dlp.utils.DownloadError as exc:
        msg = str(exc)
        if "Sign in" in msg or "bot" in msg.lower() or "age" in msg.lower():
            msg = "YouTube está bloqueando esta descarga. Prueba con otra canción o espera unos minutos."
        elif "private" in msg.lower():
            msg = "Video privado."
        elif "not available" in msg.lower() or "region" in msg.lower():
            msg = "No disponible en tu región."
        elif "copyright" in msg.lower():
            msg = "Video bloqueado por derechos de autor."
        else:
            msg = "Error: " + msg[:160]
        tasks[tid] = {"status": "error", "message": msg}
        log(uid, "download_error", msg)
    except Exception as exc:
        tasks[tid] = {"status": "error", "message": str(exc)[:200]}


# ═════════════════════════════════════════════
# PAGE ROUTES
# ═════════════════════════════════════════════
@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect("/login")
    db = load_db()
    db["users"][u["id"]]["last_seen"] = datetime.now().isoformat()
    save_db(db)
    return render_template("app.html", user=u, plans=PLANS)


@app.route("/login")
def login_page():
    if current_user():
        return redirect("/")
    return render_template("login.html")


@app.route("/admin")
@admin_required
def admin_page():
    return render_template("admin.html", user=current_user(), plans=PLANS)


@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid:
        log(uid, "logout", "Sesión cerrada")
    session.clear()
    return redirect("/login")


# ═════════════════════════════════════════════
# AUTH API
# ═════════════════════════════════════════════
@app.route("/api/auth/register", methods=["POST"])
def api_register():
    ip = get_ip()
    if not rate_ok(ip):
        return jsonify({"error": "Demasiados intentos. Espera 5 minutos."}), 429

    d        = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip().lower()
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""

    if not all([username, email, password]):
        return jsonify({"error": "Todos los campos son obligatorios"}), 400
    if not re.match(r'^[a-z0-9_]{3,24}$', username):
        return jsonify({"error": "Usuario: 3-24 chars, solo letras/números/guión"}), 400
    if len(password) < 8:
        return jsonify({"error": "Contraseña: mínimo 8 caracteres"}), 400
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({"error": "Email inválido"}), 400

    db = load_db()
    if username in db["users"]:
        return jsonify({"error": "Nombre de usuario ya existe"}), 400
    if any(u["email"] == email for u in db["users"].values()):
        return jsonify({"error": "Email ya registrado"}), 400

    db["users"][username] = {
        "id": username, "username": username, "email": email,
        "password": hash_pw(password),
        "plan": "free", "role": "user", "is_banned": False,
        "created_at": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
        "login_count": 1, "reg_ip": ip,
        "avatar": "🎵", "bio": "",
        "downloads_today": 0, "last_download_date": "",
        "total_downloads": 0, "total_searches": 0, "total_plays": 0,
    }
    for k in ("library", "activity", "searches", "plays", "notes"):
        db.setdefault(k, {})[username] = []
    save_db(db)

    session["user_id"] = username
    session.permanent = True
    log(username, "register", f"Registro desde {ip}")
    clear_rate(ip)
    return jsonify({"ok": True, "redirect": "/"})


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    ip = get_ip()
    if not rate_ok(ip):
        return jsonify({"error": "Demasiados intentos. IP bloqueada temporalmente."}), 429

    d        = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip().lower()
    password = d.get("password") or ""

    db = load_db()
    u  = db["users"].get(username)

    if not u or not verify_pw(password, u["password"]):
        return jsonify({"error": "Usuario o contraseña incorrectos"}), 401
    if u.get("is_banned"):
        return jsonify({"error": "Cuenta suspendida. Contacta al administrador."}), 403

    # Upgrade legacy hash silently
    if ":" not in u["password"]:
        db["users"][username]["password"] = hash_pw(password)

    db["users"][username]["last_seen"]   = datetime.now().isoformat()
    db["users"][username]["login_count"] = u.get("login_count", 0) + 1
    save_db(db)

    session["user_id"] = username
    session.permanent  = True
    log(username, "login", f"Login desde {ip}")
    clear_rate(ip)

    return jsonify({
        "ok": True,
        "redirect": "/admin" if u.get("role") == "admin" else "/",
    })


@app.route("/api/auth/me")
@login_required
def api_me():
    u    = current_user()
    plan = PLANS.get(u.get("plan", "free"), PLANS["free"])
    today = datetime.now().strftime("%Y-%m-%d")
    used  = u.get("downloads_today", 0) if u.get("last_download_date") == today else 0
    db    = load_db()
    lib   = len(db.get("library", {}).get(u["id"], []))
    return jsonify({
        "username": u["username"], "email": u["email"],
        "plan": u["plan"], "role": u.get("role", "user"),
        "avatar": u.get("avatar", "🎵"), "bio": u.get("bio", ""),
        "plan_info": plan,
        "downloads_used": used, "downloads_limit": plan["downloads_day"],
        "created_at": u.get("created_at", ""),
        "last_seen": u.get("last_seen", ""),
        "login_count": u.get("login_count", 0),
        "total_downloads": u.get("total_downloads", 0),
        "total_searches": u.get("total_searches", 0),
        "total_plays": u.get("total_plays", 0),
        "library_count": lib,
    })


@app.route("/api/auth/update", methods=["POST"])
@login_required
def api_update():
    d   = request.get_json(silent=True) or {}
    uid = session["user_id"]
    db  = load_db()
    u   = db["users"][uid]

    VALID_AVATARS = ["🎵","🎸","🎤","🎹","🥁","🎺","🎻","🎧","👑","⭐","🔥","💜","🎶","🎼","🎙","🌊"]
    if "bio" in d:
        u["bio"] = str(d["bio"])[:200]
    if "avatar" in d and d["avatar"] in VALID_AVATARS:
        u["avatar"] = d["avatar"]
    if d.get("new_password"):
        if not verify_pw(d.get("old_password", ""), u["password"]):
            return jsonify({"error": "Contraseña actual incorrecta"}), 400
        if len(d["new_password"]) < 8:
            return jsonify({"error": "Nueva contraseña: mínimo 8 caracteres"}), 400
        u["password"] = hash_pw(d["new_password"])
        log(uid, "password_change", "Contraseña cambiada")

    save_db(db)
    log(uid, "profile_update", "Perfil actualizado")
    return jsonify({"ok": True})


# ═════════════════════════════════════════════
# LIBRARY
# ═════════════════════════════════════════════
@app.route("/api/library")
@login_required
def api_library():
    uid = session["user_id"]
    db  = load_db()
    lib = db.get("library", {}).get(uid, [])
    return jsonify({"items": lib, "count": len(lib)})


@app.route("/api/library/<tid>", methods=["DELETE"])
@login_required
def api_del_lib(tid):
    uid = session["user_id"]
    db  = load_db()
    before = len(db.get("library", {}).get(uid, []))
    db["library"][uid] = [x for x in db["library"].get(uid, []) if x["task_id"] != tid]
    save_db(db)
    log(uid, "library_delete", f"Eliminado {tid}")
    return jsonify({"ok": True, "removed": before - len(db["library"][uid])})


@app.route("/api/plays/log", methods=["POST"])
@login_required
def api_log_play():
    d   = request.get_json(silent=True) or {}
    uid = session["user_id"]
    log_play(uid, d.get("title",""), d.get("thumbnail",""),
             d.get("task_id",""), int(d.get("duration", 0)))
    return jsonify({"ok": True})


# ═════════════════════════════════════════════
# ADMIN API
# ═════════════════════════════════════════════
@app.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    db     = load_db()
    users  = db["users"]
    today  = datetime.now().strftime("%Y-%m-%d")
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()

    plan_counts = {p: 0 for p in PLANS}
    for u in users.values():
        plan_counts[u.get("plan", "free")] = plan_counts.get(u.get("plan","free"), 0) + 1

    active_today = sum(1 for u in users.values() if (u.get("last_seen","") or "").startswith(today))
    new_today    = sum(1 for u in users.values() if (u.get("created_at","") or "").startswith(today))
    new_week     = sum(1 for u in users.values() if (u.get("created_at","") or "") >= week_ago)
    banned       = sum(1 for u in users.values() if u.get("is_banned"))
    total_dl     = sum(len(v) for v in db.get("library",{}).values())
    total_plays  = sum(len(v) for v in db.get("plays",{}).values())
    total_srch   = sum(len(v) for v in db.get("searches",{}).values())
    total_acts   = sum(len(v) for v in db.get("activity",{}).values())

    return jsonify({
        "total_users": len(users), "plan_counts": plan_counts,
        "active_today": active_today, "new_today": new_today, "new_week": new_week,
        "banned": banned, "total_downloads": total_dl,
        "total_plays": total_plays, "total_searches": total_srch,
        "total_activities": total_acts, "active_tasks": len(tasks),
    })


@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    db   = load_db()
    q    = (request.args.get("q") or "").lower()
    plan = request.args.get("plan") or ""
    role = request.args.get("role") or ""
    out  = []
    today = datetime.now().strftime("%Y-%m-%d")
    for uid, u in db["users"].items():
        if q and q not in u["username"].lower() and q not in u["email"].lower():
            continue
        if plan and u.get("plan") != plan:
            continue
        if role and u.get("role") != role:
            continue
        used = u.get("downloads_today",0) if u.get("last_download_date")==today else 0
        out.append({
            "id": uid, "username": u["username"], "email": u["email"],
            "plan": u["plan"], "role": u.get("role","user"),
            "avatar": u.get("avatar","🎵"), "is_banned": u.get("is_banned",False),
            "created_at": u.get("created_at",""), "last_seen": u.get("last_seen",""),
            "login_count": u.get("login_count",0), "reg_ip": u.get("reg_ip",""),
            "downloads_today": used,
            "total_downloads": u.get("total_downloads",0),
            "total_searches":  u.get("total_searches",0),
            "total_plays":     u.get("total_plays",0),
            "library_count":   len(db.get("library",{}).get(uid,[])),
        })
    out.sort(key=lambda x: x["created_at"], reverse=True)
    return jsonify({"users": out, "total": len(out)})


@app.route("/api/admin/users/<uid>")
@admin_required
def api_admin_user_detail(uid):
    db = load_db()
    u  = db["users"].get(uid)
    if not u:
        return jsonify({"error": "No encontrado"}), 404
    today = datetime.now().strftime("%Y-%m-%d")
    used  = u.get("downloads_today",0) if u.get("last_download_date")==today else 0
    return jsonify({
        "id": uid, "username": u["username"], "email": u["email"],
        "plan": u["plan"], "role": u.get("role","user"),
        "avatar": u.get("avatar","🎵"), "bio": u.get("bio",""),
        "is_banned": u.get("is_banned",False),
        "created_at": u.get("created_at",""), "last_seen": u.get("last_seen",""),
        "login_count": u.get("login_count",0), "reg_ip": u.get("reg_ip",""),
        "downloads_today": used,
        "total_downloads": u.get("total_downloads",0),
        "total_searches":  u.get("total_searches",0),
        "total_plays":     u.get("total_plays",0),
        "library":   db.get("library",{}).get(uid,[])[:60],
        "activity":  db.get("activity",{}).get(uid,[])[:120],
        "searches":  db.get("searches",{}).get(uid,[])[:60],
        "plays":     db.get("plays",{}).get(uid,[])[:60],
        "notes":     db.get("notes",{}).get(uid,[]),
    })


@app.route("/api/admin/users", methods=["POST"])
@admin_required
def api_admin_create_user():
    d        = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip().lower()
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or secrets.token_urlsafe(12)
    plan     = d.get("plan", "free")
    role     = d.get("role", "user")

    if not username or not email:
        return jsonify({"error": "Usuario y email requeridos"}), 400
    if not re.match(r'^[a-z0-9_]{3,24}$', username):
        return jsonify({"error": "Usuario inválido"}), 400
    if plan not in PLANS:
        return jsonify({"error": "Plan inválido"}), 400
    if role not in ("user", "admin"):
        return jsonify({"error": "Rol inválido"}), 400

    db = load_db()
    if username in db["users"]:
        return jsonify({"error": "Usuario ya existe"}), 400

    db["users"][username] = {
        "id": username, "username": username, "email": email,
        "password": hash_pw(password), "plan": plan, "role": role,
        "is_banned": False, "created_at": datetime.now().isoformat(),
        "last_seen": "", "login_count": 0, "reg_ip": "admin_created",
        "avatar": "🎵", "bio": "",
        "downloads_today": 0, "last_download_date": "",
        "total_downloads": 0, "total_searches": 0, "total_plays": 0,
    }
    for k in ("library", "activity", "searches", "plays", "notes"):
        db.setdefault(k, {})[username] = []
    save_db(db)
    log(session["user_id"], "admin_create", f"Creado {username} ({plan}/{role})")
    return jsonify({"ok": True, "password": password})


@app.route("/api/admin/users/<uid>/plan", methods=["POST"])
@admin_required
def api_admin_plan(uid):
    d    = request.get_json(silent=True) or {}
    plan = d.get("plan", "free")
    if plan not in PLANS:
        return jsonify({"error": "Plan inválido"}), 400
    db = load_db()
    if uid not in db["users"]:
        return jsonify({"error": "No encontrado"}), 404
    old = db["users"][uid]["plan"]
    db["users"][uid]["plan"] = plan
    save_db(db)
    log(session["user_id"], "admin_plan", f"{uid}: {old} → {plan}")
    log(uid, "plan_changed", f"Plan cambiado a {plan} por administrador")
    return jsonify({"ok": True})


@app.route("/api/admin/users/<uid>/role", methods=["POST"])
@admin_required
def api_admin_role(uid):
    if uid == "admin":
        return jsonify({"error": "No puedes modificar al admin principal"}), 400
    d    = request.get_json(silent=True) or {}
    role = d.get("role", "user")
    if role not in ("user", "admin"):
        return jsonify({"error": "Rol inválido"}), 400
    db = load_db()
    if uid not in db["users"]:
        return jsonify({"error": "No encontrado"}), 404
    db["users"][uid]["role"] = role
    save_db(db)
    log(session["user_id"], "admin_role", f"{uid} → {role}")
    return jsonify({"ok": True})


@app.route("/api/admin/users/<uid>/ban", methods=["POST"])
@admin_required
def api_admin_ban(uid):
    if uid == "admin":
        return jsonify({"error": "No puedes banear al admin principal"}), 400
    db = load_db()
    if uid not in db["users"]:
        return jsonify({"error": "No encontrado"}), 404
    banned = not db["users"][uid].get("is_banned", False)
    db["users"][uid]["is_banned"] = banned
    save_db(db)
    action = "ban" if banned else "unban"
    log(session["user_id"], action, f"{uid} {'baneado' if banned else 'desbaneado'}")
    log(uid, action, f"Cuenta {'suspendida' if banned else 'restaurada'} por admin")
    return jsonify({"ok": True, "banned": banned})


@app.route("/api/admin/users/<uid>/reset_password", methods=["POST"])
@admin_required
def api_admin_reset_pw(uid):
    if uid == "admin":
        return jsonify({"error": "Cambia la contraseña del admin desde Ajustes"}), 400
    db = load_db()
    if uid not in db["users"]:
        return jsonify({"error": "No encontrado"}), 404
    new_pw = secrets.token_urlsafe(12)
    db["users"][uid]["password"] = hash_pw(new_pw)
    save_db(db)
    log(session["user_id"], "admin_reset_pw", f"Contraseña reseteada para {uid}")
    log(uid, "password_change", "Contraseña reseteada por administrador")
    return jsonify({"ok": True, "new_password": new_pw})


@app.route("/api/admin/users/<uid>", methods=["DELETE"])
@admin_required
def api_admin_del_user(uid):
    if uid == "admin":
        return jsonify({"error": "No puedes eliminar al admin principal"}), 400
    db = load_db()
    db["users"].pop(uid, None)
    for k in ("library", "activity", "searches", "plays", "notes"):
        db.get(k, {}).pop(uid, None)
    save_db(db)
    log(session["user_id"], "admin_delete", f"Usuario {uid} eliminado")
    return jsonify({"ok": True})


@app.route("/api/admin/users/<uid>/note", methods=["POST"])
@admin_required
def api_admin_note(uid):
    d    = request.get_json(silent=True) or {}
    text = (d.get("text") or "").strip()[:500]
    if not text:
        return jsonify({"error": "Nota vacía"}), 400
    db = load_db()
    if uid not in db["users"]:
        return jsonify({"error": "No encontrado"}), 404
    db.setdefault("notes", {}).setdefault(uid, [])
    note = {
        "id": uuid.uuid4().hex[:8],
        "text": text,
        "author": session["user_id"],
        "ts": datetime.now().isoformat(),
    }
    db["notes"][uid].insert(0, note)
    save_db(db)
    log(session["user_id"], "admin_note", f"Nota en {uid}: {text[:60]}")
    return jsonify({"ok": True, "note": note})


@app.route("/api/admin/users/<uid>/note/<nid>", methods=["DELETE"])
@admin_required
def api_admin_del_note(uid, nid):
    db = load_db()
    db.setdefault("notes", {}).setdefault(uid, [])
    db["notes"][uid] = [n for n in db["notes"][uid] if n.get("id") != nid]
    save_db(db)
    return jsonify({"ok": True})


@app.route("/api/admin/activity")
@admin_required
def api_admin_activity():
    db  = load_db()
    out = []
    for uid, acts in db.get("activity", {}).items():
        for a in acts:
            out.append({**a, "uid": uid})
    out.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return jsonify({"activity": out[:300]})


@app.route("/api/admin/top_downloads")
@admin_required
def api_top_downloads():
    db  = load_db()
    cnt = {}
    for acts in db.get("activity", {}).values():
        for a in acts:
            if a.get("action") == "download":
                t = a.get("title", "?")
                cnt[t] = cnt.get(t, 0) + 1
    top = sorted(cnt.items(), key=lambda x: x[1], reverse=True)[:20]
    return jsonify({"top": [{"title": t, "count": c} for t, c in top]})


@app.route("/api/admin/top_searches")
@admin_required
def api_top_searches():
    db  = load_db()
    cnt = {}
    for srcs in db.get("searches", {}).values():
        for s in srcs:
            q = (s.get("query") or "?").lower().strip()
            cnt[q] = cnt.get(q, 0) + 1
    top = sorted(cnt.items(), key=lambda x: x[1], reverse=True)[:20]
    return jsonify({"top": [{"query": q, "count": c} for q, c in top]})


@app.route("/api/admin/broadcast", methods=["POST"])
@admin_required
def api_broadcast():
    """Log a broadcast message as admin activity (simulated — extend with email/push)"""
    d   = request.get_json(silent=True) or {}
    msg = (d.get("message") or "").strip()[:500]
    if not msg:
        return jsonify({"error": "Mensaje vacío"}), 400
    log(session["user_id"], "admin_note", f"[BROADCAST] {msg}")
    return jsonify({"ok": True})


# ═════════════════════════════════════════════
# YOUTUBE API
# ═════════════════════════════════════════════
@app.route("/api/search", methods=["POST"])
@login_required
def api_search():
    d = request.get_json(silent=True) or {}
    q = (d.get("query") or "").strip()
    if not q:
        return jsonify({"error": "Consulta vacía"}), 400
    uid    = session["user_id"]
    suffix = " music" if d.get("type") == "music" else ""
    log_search(uid, q)
    try:
        opts = {"quiet": True, "no_warnings": True,
                "extract_flat": True, "skip_download": True}
        with yt_dlp.YoutubeDL(opts) as ydl:
            res = ydl.extract_info(f"ytsearch20:{q}{suffix}", download=False)
        items = [
            {
                "id": e["id"], "title": e.get("title", "—"),
                "uploader": e.get("uploader") or "—",
                "duration": e.get("duration", 0),
                "view_count": e.get("view_count", 0),
                "thumbnail": (e.get("thumbnail")
                              or f"https://i.ytimg.com/vi/{e['id']}/hqdefault.jpg"),
                "url": f"https://www.youtube.com/watch?v={e['id']}",
            }
            for e in (res.get("entries") or []) if e and e.get("id")
        ]
        return jsonify({"results": items, "count": len(items)})
    except Exception as exc:
        return jsonify({"error": str(exc)[:300]}), 400


@app.route("/api/trending")
@login_required
def api_trending():
    try:
        opts = {**get_ydl_base_opts(), "extract_flat": True, "skip_download": True, "playlistend": 20}
        url  = ("https://www.youtube.com/feed/trending"
                "?bp=4gIuCggvbS8wNHZtZhIiUExGZ3QxV2hkX2JXSjhJUEVlWGFSbzVkbHFoNmVhOEE%3D")
        with yt_dlp.YoutubeDL(opts) as ydl:
            res = ydl.extract_info(url, download=False)
        items = [
            {
                "id": e["id"], "title": e.get("title", "—"),
                "uploader": e.get("uploader") or "—",
                "duration": e.get("duration", 0),
                "view_count": e.get("view_count", 0),
                "thumbnail": (e.get("thumbnail")
                              or f"https://i.ytimg.com/vi/{e['id']}/hqdefault.jpg"),
                "url": f"https://www.youtube.com/watch?v={e['id']}",
            }
            for e in ((res or {}).get("entries") or [])[:20] if e and e.get("id")
        ]
        return jsonify({"results": items})
    except Exception as exc:
        return jsonify({"results": [], "error": str(exc)[:200]})


@app.route("/api/info", methods=["POST"])
@login_required
def api_info():
    d   = request.get_json(silent=True) or {}
    url = (d.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL requerida"}), 400
    try:
        opts = {**get_ydl_base_opts(), "noplaylist": True}
        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(url, download=False)
        return jsonify({
            "title":       info.get("title", "—"),
            "duration":    info.get("duration", 0),
            "thumbnail":   info.get("thumbnail", ""),
            "uploader":    info.get("uploader", "—"),
            "view_count":  info.get("view_count", 0),
            "like_count":  info.get("like_count", 0),
            "upload_date": info.get("upload_date", ""),
            "description": (info.get("description") or "")[:300],
        })
    except Exception as exc:
        return jsonify({"error": str(exc)[:300]}), 400


@app.route("/api/download", methods=["POST"])
@login_required
def api_download():
    d       = request.get_json(silent=True) or {}
    url     = (d.get("url") or "").strip()
    fmt     = d.get("format", "mp3").lower()
    quality = str(d.get("quality", "192"))

    if not url:
        return jsonify({"error": "URL requerida"}), 400
    if fmt not in ("mp3", "mp4", "wav", "m4a"):
        return jsonify({"error": "Formato no soportado"}), 400

    u    = current_user()
    plan = PLANS.get(u.get("plan", "free"), PLANS["free"])

    if fmt not in plan["formats"]:
        return jsonify({
            "error": f"Tu plan {plan['name']} no incluye {fmt.upper()}. "
                     f"Actualiza tu suscripción."
        }), 403

    if int(quality) > int(plan["max_quality"]):
        quality = plan["max_quality"]

    ok, msg = check_dl_limit(u)
    if not ok:
        return jsonify({"error": msg}), 403

    tid = uuid.uuid4().hex[:10]
    tasks[tid] = {"status": "starting", "percent": 0}
    threading.Thread(
        target=dl_worker,
        args=(url, tid, fmt, quality, session["user_id"],
              d.get("start_time"), d.get("end_time")),
        daemon=True,
    ).start()
    return jsonify({"task_id": tid})


@app.route("/api/progress/<tid>")
@login_required
def api_progress(tid):
    t = tasks.get(tid, {"status": "not_found"})
    return jsonify({k: v for k, v in t.items() if k != "filename"})


@app.route("/api/file/<tid>")
@login_required
def api_file(tid):
    t = tasks.get(tid)
    if not t or t.get("status") != "done":
        abort(404)
    fp = t.get("filename")
    if not fp or not os.path.exists(fp):
        abort(404)
    clean = re.sub(r'^[a-f0-9]{10}_', '', os.path.basename(fp))
    mime  = {".mp3": "audio/mpeg", ".mp4": "video/mp4",
             ".wav": "audio/wav",  ".m4a": "audio/mp4"}
    return send_file(
        fp, as_attachment=True, download_name=clean,
        mimetype=mime.get(Path(fp).suffix.lower(), "application/octet-stream"),
    )


@app.route("/api/stream/<tid>")
@login_required
def api_stream(tid):
    fp = None
    t  = tasks.get(tid)
    if t and t.get("status") == "done":
        fp = t.get("filename")
    if not fp:
        for fname in os.listdir(DOWNLOAD_DIR):
            if fname.startswith(tid):
                fp = os.path.join(DOWNLOAD_DIR, fname)
                break
    if not fp or not os.path.exists(fp):
        abort(404)
    mime = {".mp3": "audio/mpeg", ".mp4": "video/mp4",
            ".wav": "audio/wav",  ".m4a": "audio/mp4"}
    return send_file(fp, mimetype=mime.get(Path(fp).suffix.lower(), "audio/mpeg"))


@app.route("/health")
def health():
    return jsonify({"status": "ok", "tasks": len(tasks)})


@app.route("/api/admin/upload_cookies", methods=["POST"])
@admin_required
def api_upload_cookies():
    """Admin can upload cookies.txt to fix age-restricted / blocked downloads."""
    if "file" not in request.files:
        return jsonify({"error": "No se envió ningún archivo"}), 400
    f = request.files["file"]
    if not f.filename.endswith(".txt"):
        return jsonify({"error": "El archivo debe ser .txt"}), 400
    os.makedirs("data", exist_ok=True)
    f.save(COOKIES_FILE)
    log(session["user_id"], "admin_note", "Cookies de YouTube actualizadas")
    return jsonify({"ok": True, "message": "Cookies subidas correctamente"})


@app.route("/api/admin/cookies_status")
@admin_required
def api_cookies_status():
    exists = os.path.exists(COOKIES_FILE)
    size = os.path.getsize(COOKIES_FILE) if exists else 0
    mtime = ""
    if exists:
        import datetime as dt
        mtime = dt.datetime.fromtimestamp(os.path.getmtime(COOKIES_FILE)).strftime("%d/%m/%Y %H:%M")
    return jsonify({"exists": exists, "size": size, "updated": mtime})


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    print(f"YTDROP v5 -> http://localhost:{port}")
    print(f"Admin: admin / admin123")
    app.run(debug=debug, host="0.0.0.0", port=port)
