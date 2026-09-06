"""
========================================================================
  OBLIVION ORBITAL — Unified Knowledge-Graph & Code-Intelligence Suite
========================================================================
یک برنامه‌ی پایتونی تک‌فایلی که با اجرای همین یک فایل، هم موتور گراف دانش،
هم محیط کد‌نویسی هوشمند (بر پایه‌ی ایده‌های Python LSP) و هم یک سیستم
کنترل داده (احراز هویت + نقش کاربری + ثبت رخداد) را بالا می‌آورد.

این فایل حاصل ادغام و یکپارچه‌سازی فایل‌های زیر است:
  • model_version_1.bin  → هسته‌ی اصلی برنامه (سرور HTTP + گراف دانش + ویرایشگر)
  • __init__.py / hookspecs.py  → سیستم افزونه (Plugin Hooks) برای فرمت‌های ورودی
  • uris.py                     → توابع تبدیل مسیر فایل <-> URI
  • _utils.py                   → ابزارهای کمکی عمومی (merge_dicts و ...)
  • lsp.py / python_ls.py / workspace.py → منطق پایه‌ی Language Server که
    به یک لایه‌ی «هوش کد» (Code Intelligence) سبک برای ویرایشگر توکار
    تبدیل شده: تشخیص خطا (Diagnostics) و تکمیل خودکار (Completion).
  • __main__.py / versioneer.py / _version.py → الگوی خط‌فرمان و شماره‌گذاری
    نسخه، به شکل ساده‌شده در همین فایل بازتولید شده است.

نحوه‌ی اجرا:
    python oblivion_orbital.py
    python oblivion_orbital.py --host 0.0.0.0 --port 8080

کتابخانه‌های مورد نیاز:
    - این برنامه با کتابخانه‌ی استاندارد پایتون (stdlib) به‌تنهایی کار می‌کند.
    - برای فعال‌سازی قابلیت‌های پیشرفته‌ی «هوش کد» (لینت دقیق‌تر و تکمیل
      هوشمند)، نصب اختیاری زیر توصیه می‌شود:

        pip install pyflakes jedi pluggy

      اگر این پکیج‌ها نصب نباشند، برنامه به‌صورت خودکار روی حالت‌های
      جایگزینِ مبتنی بر stdlib (ast / compile) سوییچ می‌کند و باز هم کامل
      اجرا می‌شود.
========================================================================
"""

import argparse
import cgi
import hashlib
import hmac
import http.server
import io
import json
import math
import os
import random
import re
import secrets
import shutil
import socketserver
import sqlite3
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
import zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict, deque, Counter
from datetime import datetime, timedelta
from http import cookies
from pathlib import Path

# ------------------------------------------------------------------ #
#  Optional third-party enhancers (graceful degradation if missing)  #
# ------------------------------------------------------------------ #
try:
    import pyflakes.api as _pyflakes_api          # noqa: F401
    import pyflakes.reporter as _pyflakes_reporter  # noqa: F401
    HAVE_PYFLAKES = True
except Exception:
    HAVE_PYFLAKES = False

try:
    import jedi as _jedi                          # noqa: F401
    HAVE_JEDI = True
except Exception:
    HAVE_JEDI = False

try:
    import pluggy
    HAVE_PLUGGY = True
except Exception:
    HAVE_PLUGGY = False

# ======================================================================
#  APP IDENTITY  (rebrand: "Oblivion XQDatabase" -> "Oblivion Orbital")
# ======================================================================
APP_NAME = "Oblivion Orbital"
APP_VERSION = "1.0.0"
APP_TAGLINE = "Unified Knowledge-Graph & Code-Intelligence Platform"

# ======================================================================
#  CONFIG
# ======================================================================
HOST, PORT = "127.0.0.1", 8080
DATA_DIR = Path("data")
UPLOAD_DIR = DATA_DIR / "files"
DB_PATH = DATA_DIR / "knowledge.db"
for d in [DATA_DIR, UPLOAD_DIR]:
    d.mkdir(parents=True, exist_ok=True)

IS_WIN = os.name == "nt"

# ------------------------------------------------------------------ #
#  ACCESS CODES  (two-tier login, Apollo-style platform gate)        #
#  - FULL_ACCESS_*  : unrestricted, no expiry                        #
#  - TRIAL_ACCESS_* : opens a rolling window of TRIAL_DAYS days,      #
#                      starting the first time it is ever used        #
#                                                                      #
#  The actual codes are never stored as plaintext in this file —     #
#  only their salted PBKDF2 hashes are. A login attempt is checked   #
#  by hashing the submitted value with the stored salt and comparing #
#  the result; the real codes cannot be recovered by reading the     #
#  source. To change a code, generate a new salt/hash pair with:     #
#      python3 -c "from oblivion_orbital import _hash_password as h; print(h('new-code'))" #
# ------------------------------------------------------------------ #
FULL_ACCESS_SALT = "83ffa733ba6ab2ae91706c666ebfa975"
FULL_ACCESS_HASH = "4b117f03251241bbd2006cd18017d1862b60067aee20be2a536d1336f222b097"
TRIAL_ACCESS_SALT = "b3d6a72cf0fb3fc620438894c587c246"
TRIAL_ACCESS_HASH = "7adc5e7f12354dfed0b6bfaf6827b065e74631321d85051f70fe2501a9f1e86b"
TRIAL_DAYS = 10

STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "but", "if", "because", "as", "what", "which",
    "this", "that", "these", "those", "then", "just", "so", "than", "such", "both",
    "through", "about", "for", "is", "of", "while", "during", "to", "from", "in",
    "on", "at", "by", "with", "without", "up", "down", "out", "off", "over", "under",
    "again", "further", "once", "here", "there", "when", "where", "why", "how",
    "all", "each", "every", "few", "more", "most", "other", "some", "no", "nor",
    "not", "only", "own", "same", "too", "very", "can", "will", "should", "now",
    "also", "after", "before", "between", "above", "below", "i", "me", "my", "we",
    "our", "you", "he", "she", "it", "they", "am", "is", "are", "was", "were", "be",
    "been", "being", "have", "has", "had", "doing", "do", "does", "did", "would",
    "could", "should", "may", "might", "must", "shall", "can", "need", "dare", "used",
    "و", "در", "به", "از", "که", "با", "برای", "تا", "را", "این", "آن", "است", "هست",
    "بود", "شد", "شده", "می", "ها", "های", "هر", "هم", "نیز", "اما", "یا", "اگر",
    "چون", "چه", "چرا", "کجا", "کی", "کدام", "همه", "یک", "دو", "سه", "نه", "بله",
    "خیر", "بعد", "قبل", "بالا", "پایین", "بیش", "کم", "بزرگ", "کوچک", "خوب",
    "بد", "نو", "کهنه", "اول", "آخر", "تنها", "چنین", "چنان", "همان", "همین",
    "آنجا", "اینجا", "من", "تو", "او", "ما", "شما", "آنها", "ایشان", "خود", "خویش",
    "همدیگر", "یکدیگر", "هستند", "باشند", "بودند", "شوند", "گردند", "کرد", "کرده",
    "کن", "کنید", "گفت", "گفته", "گوی", "گو", "ز", "بر", "اند", "ای", "ام", "ات",
    "اش", "مان", "تان", "شان"
})

# ======================================================================
#  SMALL UTILITIES  (derived from _utils.py)
# ======================================================================
def merge_dicts(dict_a, dict_b):
    """Merge dict_b into dict_a (shallow, dict_b wins on conflicts)."""
    merged = dict(dict_a)
    merged.update(dict_b)
    return merged


def list_to_string(lst, sep=", "):
    return sep.join(str(x) for x in lst)


def clip_columns(text, limit=4000):
    """Guard against pasting enormous blobs into a single API response field."""
    if text is None:
        return text
    return text if len(text) <= limit else text[:limit] + "\n... [truncated]"


# ======================================================================
#  URI HELPERS  (derived from uris.py — used by the file/import endpoints
#  to give every uploaded/edited file a stable, LSP-style URI identity)
# ======================================================================
RE_DRIVE_LETTER_PATH = re.compile(r'^/[a-zA-Z]:')


def _normalize_win_path(path):
    netloc = ''
    if IS_WIN:
        path = path.replace('\\', '/')
    if path[:2] == '//':
        idx = path.find('/', 2)
        netloc = path[2:] if idx == -1 else path[2:idx]
        if idx != -1:
            path = path[idx:]
    if not path.startswith('/'):
        path = '/' + path
    if RE_DRIVE_LETTER_PATH.match(path):
        path = path[0] + path[1].lower() + path[2:]
    return path, netloc


def from_fs_path(path):
    """Filesystem path -> a stable 'file://' URI, used as a document id."""
    path, netloc = _normalize_win_path(str(path))
    return urllib.parse.urlunparse(('file', netloc, urllib.parse.quote(path), '', '', ''))


def to_fs_path(uri):
    """'file://' URI -> filesystem path."""
    scheme, netloc, path, _p, _q, _f = urllib.parse.urlparse(uri)
    path = urllib.parse.unquote(path)
    if netloc and path and scheme == 'file':
        value = "//{}{}".format(netloc, path)
    elif RE_DRIVE_LETTER_PATH.match(path):
        value = path[1].lower() + path[2:]
    else:
        value = path
    return value.replace('/', '\\') if IS_WIN else value


# ======================================================================
#  PLUGIN / HOOK SYSTEM  (derived from hookspecs.py + __init__.py)
#  Lets new importer formats be registered without touching core code.
# ======================================================================
PLUGIN_NAMESPACE = "oblivion_orbital"

if HAVE_PLUGGY:
    hookspec = pluggy.HookspecMarker(PLUGIN_NAMESPACE)
    hookimpl = pluggy.HookimplMarker(PLUGIN_NAMESPACE)

    class ImporterHookSpecs:
        @hookspec
        def oo_extract_text(self, path, ext):
            """Return extracted plain text for a given uploaded file, or None
            if this plugin does not handle the extension."""

    _plugin_manager = pluggy.PluginManager(PLUGIN_NAMESPACE)
    _plugin_manager.add_hookspecs(ImporterHookSpecs)
else:
    _plugin_manager = None

    def hookimpl(func=None, **kw):  # no-op decorator fallback
        if func is not None:
            return func
        return lambda f: f


# ======================================================================
#  DATA-CONTROL SYSTEM: users, sessions, roles, audit log
# ======================================================================
SESSION_COOKIE = "oo_session"
SESSIONS = {}          # token -> {"user": username, "role": role, "ts": time}
SESSIONS_LOCK = threading.Lock()
SESSION_TTL = 60 * 60 * 8  # 8h


def _hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return salt, digest.hex()


def _verify_password(password, salt, expected_hex):
    _, computed = _hash_password(password, salt)
    return hmac.compare_digest(computed, expected_hex)


class DataControl:
    """Authentication, roles and a tamper-evident audit trail."""

    def __init__(self, path):
        self.path = path
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                ts TEXT DEFAULT (datetime('now')),
                username TEXT,
                action TEXT,
                detail TEXT,
                ip TEXT
            );
            CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """)
            conn.commit()
        # bootstrap a default admin on first run
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
            if row[0] == 0:
                salt, ph = _hash_password(secrets.token_urlsafe(18))
                conn.execute(
                    "INSERT INTO users (username, salt, password_hash, role) VALUES (?,?,?,?)",
                    ("admin", salt, ph, "admin")
                )
                conn.commit()
                print("[Oblivion Orbital] Created default 'admin' account with a random "
                      "password. Use one of the master access codes to sign in, then set "
                      "a real password for this account via /api/users/create or your own "
                      "admin tooling.")

    def create_user(self, username, password, role="viewer"):
        salt, ph = _hash_password(password)
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO users (username, salt, password_hash, role) VALUES (?,?,?,?)",
                (username, salt, ph, role)
            )
            conn.commit()

    def authenticate(self, username, password):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT salt, password_hash, role FROM users WHERE username=?", (username,)
            ).fetchone()
        if not row:
            return None
        salt, ph, role = row
        if _verify_password(password, salt, ph):
            return {"user": username, "role": role}
        return None

    # --- key/value config (used for the trial-password activation window) ---
    def get_config(self, key, default=None):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_config(self, key, value):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO app_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value)
            )
            conn.commit()

    def trial_status(self):
        """Return the trial window's current state without consuming/starting it."""
        start_raw = self.get_config("trial_start")
        if not start_raw:
            return {"started": False, "active": None, "expires_at": None, "days_left": TRIAL_DAYS}
        start = datetime.fromisoformat(start_raw)
        expires = start + timedelta(days=TRIAL_DAYS)
        now = datetime.utcnow()
        days_left = max(0, (expires - now).days + (1 if (expires - now).seconds > 0 else 0))
        return {
            "started": True,
            "active": now <= expires,
            "expires_at": expires.isoformat(),
            "days_left": days_left,
        }

    def trial_login_attempt(self):
        """Start the trial window on first use, then validate against it.
        Returns a session identity dict if the trial code is still valid,
        or None if the 10-day window has already elapsed."""
        start_raw = self.get_config("trial_start")
        now = datetime.utcnow()
        if not start_raw:
            self.set_config("trial_start", now.isoformat())
            start = now
        else:
            start = datetime.fromisoformat(start_raw)
        expires = start + timedelta(days=TRIAL_DAYS)
        if now > expires:
            return None
        return {"user": "trial", "role": "trial", "expires_at": expires.isoformat()}

    def log(self, username, action, detail="", ip=""):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO audit_log (id, username, action, detail, ip) VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), username, action, clip_columns(detail, 500), ip)
            )
            conn.commit()

    def recent_log(self, limit=200):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT ts, username, action, detail, ip FROM audit_log "
                "ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"ts": r[0], "user": r[1], "action": r[2], "detail": r[3], "ip": r[4]} for r in rows]

    # --- sessions ---
    def new_session(self, user, role):
        token = secrets.token_urlsafe(32)
        with SESSIONS_LOCK:
            SESSIONS[token] = {"user": user, "role": role, "ts": time.time()}
        return token

    def session_for(self, token):
        with SESSIONS_LOCK:
            s = SESSIONS.get(token)
            if not s:
                return None
            if time.time() - s["ts"] > SESSION_TTL:
                SESSIONS.pop(token, None)
                return None
            return s

    def drop_session(self, token):
        with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


# ======================================================================
#  SQLite knowledge-graph store  (core engine, unchanged in behaviour)
# ======================================================================
class GraphDB:
    def __init__(self, path):
        self.path = path
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS graphs (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE,
                created REAL DEFAULT (julianday('now'))
            );
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                graph_id TEXT,
                label TEXT,
                x REAL,
                y REAL,
                size REAL DEFAULT 10,
                shape TEXT DEFAULT 'circle',
                color TEXT,
                community INT DEFAULT -1,
                betweenness REAL DEFAULT 0,
                source_file TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(graph_id) REFERENCES graphs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS edges (
                id TEXT PRIMARY KEY,
                graph_id TEXT,
                source TEXT,
                target TEXT,
                weight REAL DEFAULT 1,
                source_file TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(graph_id) REFERENCES graphs(id) ON DELETE CASCADE,
                FOREIGN KEY(source) REFERENCES nodes(id) ON DELETE CASCADE,
                FOREIGN KEY(target) REFERENCES nodes(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_graph ON nodes(graph_id);
            CREATE INDEX IF NOT EXISTS idx_edges_graph ON edges(graph_id);
            CREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(
                label, content='nodes', content_rowid='rowid'
            );
            CREATE TABLE IF NOT EXISTS sentences (
                id TEXT PRIMARY KEY,
                graph_id TEXT,
                filename TEXT,
                text TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(graph_id) REFERENCES graphs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS sentence_nodes (
                sentence_id TEXT,
                node_id TEXT,
                PRIMARY KEY (sentence_id, node_id),
                FOREIGN KEY(sentence_id) REFERENCES sentences(id) ON DELETE CASCADE,
                FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
            );
            """)
            self._migrate(conn)
            conn.commit()

    def _migrate(self, conn):
        for stmt in (
            "ALTER TABLE nodes ADD COLUMN source_file TEXT DEFAULT ''",
            "ALTER TABLE nodes ADD COLUMN created_at TEXT DEFAULT (datetime('now'))",
            "ALTER TABLE edges ADD COLUMN source_file TEXT DEFAULT ''",
            "ALTER TABLE edges ADD COLUMN created_at TEXT DEFAULT (datetime('now'))",
        ):
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass

    def create_graph(self, name):
        gid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT INTO graphs (id, name) VALUES(?,?)", (gid, name))
        return gid

    def get_or_create_master(self):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT id FROM graphs WHERE name='Master Graph'").fetchone()
            if row:
                return row[0]
        return self.create_graph("Master Graph")

    def add_node(self, gid, label, **kw):
        nid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """INSERT INTO nodes
                   (id, graph_id, label, x, y, size, shape, color,
                    community, betweenness, source_file)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (nid, gid, label,
                 kw.get('x', random.uniform(100, 700)),
                 kw.get('y', random.uniform(100, 500)),
                 kw.get('size', 10),
                 kw.get('shape', 'circle'),
                 kw.get('color', '#%06x' % random.randint(0, 0xFFFFFF)),
                 kw.get('community', -1),
                 kw.get('betweenness', 0.0),
                 kw.get('source_file', ''))
            )
        return nid

    def add_edge(self, gid, src, dst, weight=1, source_file=''):
        eid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO edges (id,graph_id,source,target,weight,source_file) VALUES(?,?,?,?,?,?)",
                (eid, gid, src, dst, weight, source_file)
            )
        return eid

    def get_graph(self, gid):
        with sqlite3.connect(self.path) as conn:
            g = conn.execute("SELECT id, name FROM graphs WHERE id=?", (gid,)).fetchone()
            if not g:
                return None
            nodes = []
            for r in conn.execute(
                "SELECT id, label, x, y, size, shape, color, community, betweenness, source_file "
                "FROM nodes WHERE graph_id=?", (gid,)
            ):
                nodes.append({
                    "id": r[0], "label": r[1], "x": r[2], "y": r[3],
                    "size": r[4], "shape": r[5], "color": r[6],
                    "community": r[7], "betweenness": r[8], "source_file": r[9]
                })
            edges = []
            for r in conn.execute(
                "SELECT id, source, target, weight, source_file FROM edges WHERE graph_id=?", (gid,)
            ):
                edges.append({"id": r[0], "source": r[1], "target": r[2],
                               "weight": r[3], "source_file": r[4]})
            return {"graph": {"id": g[0], "name": g[1]}, "nodes": nodes, "edges": edges}

    def get_node_details(self, node_id):
        with sqlite3.connect(self.path) as conn:
            node = conn.execute(
                "SELECT id, label, x, y, size, shape, color, community, betweenness, source_file "
                "FROM nodes WHERE id=?", (node_id,)
            ).fetchone()
            if not node:
                return None
            node_data = {
                "id": node[0], "label": node[1], "x": node[2], "y": node[3],
                "size": node[4], "shape": node[5], "color": node[6],
                "community": node[7], "betweenness": node[8], "source_file": node[9]
            }
            edges = []
            for r in conn.execute(
                "SELECT id, source, target, weight, source_file "
                "FROM edges WHERE source=? OR target=?", (node_id, node_id)
            ):
                edges.append({"id": r[0], "source": r[1], "target": r[2],
                               "weight": r[3], "source_file": r[4]})
            sentences = []
            for r in conn.execute("""
                SELECT s.text, s.filename
                FROM sentences s
                JOIN sentence_nodes sn ON s.id = sn.sentence_id
                WHERE sn.node_id = ?
                ORDER BY s.filename, s.created_at
            """, (node_id,)):
                sentences.append({"text": r[0], "filename": r[1]})
            article = "\n\n".join(f"[{s['filename']}] {s['text']}" for s in sentences[:15])
            if not article:
                article = "No source sentences found for this term."
            return {"node": node_data, "edges": edges, "article": article}

    def search_nodes(self, gid, query):
        with sqlite3.connect(self.path) as conn:
            safe = query.strip()
            if not any(c in safe for c in '*"^'):
                safe = safe + '*'
            rows = conn.execute(
                """SELECT n.id, n.label, n.x, n.y, n.size, n.shape,
                          n.color, n.community, n.betweenness, n.source_file
                   FROM nodes n
                   JOIN nodes_fts f ON n.rowid = f.rowid
                   WHERE n.graph_id = ? AND f.label MATCH ?""",
                (gid, safe)
            ).fetchall()
            return [{
                "id": r[0], "label": r[1], "x": r[2], "y": r[3],
                "size": r[4], "shape": r[5], "color": r[6],
                "community": r[7], "betweenness": r[8], "source_file": r[9]
            } for r in rows]

    def update_node(self, nid, **kw):
        sets = ', '.join(f"{k}=?" for k in kw)
        with sqlite3.connect(self.path) as conn:
            conn.execute(f"UPDATE nodes SET {sets} WHERE id=?", (*kw.values(), nid))

    def get_node_id(self, label, gid):
        with sqlite3.connect(self.path) as conn:
            r = conn.execute(
                "SELECT id FROM nodes WHERE graph_id=? AND label=?", (gid, label)
            ).fetchone()
            return r[0] if r else None

    def store_sentence(self, gid, filename, text, node_ids):
        sid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO sentences (id, graph_id, filename, text) VALUES(?,?,?,?)",
                (sid, gid, filename, text)
            )
            for nid in node_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO sentence_nodes (sentence_id, node_id) VALUES(?,?)",
                    (sid, nid)
                )
        return sid

    def stats(self, gid):
        with sqlite3.connect(self.path) as conn:
            n = conn.execute("SELECT COUNT(*) FROM nodes WHERE graph_id=?", (gid,)).fetchone()[0]
            e = conn.execute("SELECT COUNT(*) FROM edges WHERE graph_id=?", (gid,)).fetchone()[0]
            s = conn.execute("SELECT COUNT(*) FROM sentences WHERE graph_id=?", (gid,)).fetchone()[0]
        return {"nodes": n, "edges": e, "sentences": s}

    # ---- data-lifecycle: remove a previously imported source ----------
    def delete_source_file(self, gid, filename):
        """Cascade-remove everything a single imported file contributed:
        its sentences, any edges tagged with it, and — where a node's
        source list becomes empty as a result — the node itself."""
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(
                "DELETE FROM sentences WHERE graph_id=? AND filename=?", (gid, filename)
            )
            conn.execute(
                "DELETE FROM edges WHERE graph_id=? AND source_file=?", (gid, filename)
            )
            rows = conn.execute(
                "SELECT id, source_file FROM nodes WHERE graph_id=?", (gid,)
            ).fetchall()
            for nid, src in rows:
                parts = [p for p in (src or "").split(",") if p and p != filename]
                new_src = ",".join(parts)
                if new_src != (src or ""):
                    if new_src:
                        conn.execute("UPDATE nodes SET source_file=? WHERE id=?", (new_src, nid))
                    else:
                        conn.execute("DELETE FROM nodes WHERE id=?", (nid,))
            conn.commit()

    def reset_graph(self, gid):
        """Full wipe of a graph's content (nodes/edges/sentences), keeping
        the graph record itself so the console has somewhere to render to."""
        with sqlite3.connect(self.path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("DELETE FROM sentences WHERE graph_id=?", (gid,))
            conn.execute("DELETE FROM edges WHERE graph_id=?", (gid,))
            conn.execute("DELETE FROM nodes WHERE graph_id=?", (gid,))
            conn.commit()


db = GraphDB(DB_PATH)
dc = DataControl(DB_PATH)
master_gid = db.get_or_create_master()


# ======================================================================
#  PLATFORM STORE  (Apollo Control Panel-style operational entities)
#  A single generic table backs Environments / Products & Releases /
#  Release Channels / Teams & Permissions / Change Management /
#  Plans & Constraints, mirroring the "Reference" section of Apollo's
#  navigation sidebar. A lightweight Notifications feed is fed
#  automatically whenever something in these sections changes.
# ======================================================================
PLATFORM_CATEGORIES = {
    "environment": "Environments",
    "product": "Products & Releases",
    "channel": "Release Channels",
    "team": "Teams & Permissions",
    "change": "Change Management",
    "plan": "Upgrades & Plans",
}


class PlatformStore:
    def __init__(self, path):
        self.path = path
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS platform_items (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                fields TEXT DEFAULT '{}',
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_platform_category ON platform_items(category);
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                message TEXT,
                level TEXT DEFAULT 'info',
                created_at TEXT DEFAULT (datetime('now'))
            );
            """)
            conn.commit()

    def list_items(self, category):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT id, category, title, fields, status, created_at "
                "FROM platform_items WHERE category=? ORDER BY created_at DESC",
                (category,)
            ).fetchall()
        out = []
        for r in rows:
            try:
                fields = json.loads(r[3]) if r[3] else {}
            except Exception:
                fields = {}
            out.append({
                "id": r[0], "category": r[1], "title": r[2],
                "fields": fields, "status": r[4], "created_at": r[5]
            })
        return out

    def create_item(self, category, title, fields=None, status="active"):
        if category not in PLATFORM_CATEGORIES:
            raise ValueError("unknown category")
        iid = str(uuid.uuid4())
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO platform_items (id, category, title, fields, status) "
                "VALUES (?,?,?,?,?)",
                (iid, category, title, json.dumps(fields or {}, ensure_ascii=False), status)
            )
            conn.commit()
        self.notify(f"{PLATFORM_CATEGORIES[category]}: \u201c{title}\u201d created.")
        return iid

    def delete_item(self, item_id):
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT category, title FROM platform_items WHERE id=?", (item_id,)
            ).fetchone()
            conn.execute("DELETE FROM platform_items WHERE id=?", (item_id,))
            conn.commit()
        if row:
            cat, title = row
            self.notify(f"{PLATFORM_CATEGORIES.get(cat, cat)}: \u201c{title}\u201d removed.")

    def notify(self, message, level="info"):
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT INTO notifications (id, message, level) VALUES (?,?,?)",
                (str(uuid.uuid4()), message, level)
            )
            conn.commit()

    def recent_notifications(self, limit=100):
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT id, message, level, created_at FROM notifications "
                "ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [{"id": r[0], "message": r[1], "level": r[2], "created_at": r[3]} for r in rows]


platform_store = PlatformStore(DB_PATH)


# ======================================================================
#  Text processing / graph construction
# ======================================================================
def tokenize(text):
    return [w.lower() for w in re.findall(r'\b\w+\b', text) if w.isalpha() and len(w) > 1]


def lemma(w):
    for sf in ['ترین', 'تر', 'ها', 'ان', 'ات', 'ی', 'ای', 'ing', 'ed', 'ly',
               'ment', 'ness', 'tion', 's', 'es', 'er', 'est']:
        if w.endswith(sf) and len(w) > len(sf) + 2:
            w = w[:-len(sf)]
            break
    return w


def extract_sentences(text):
    return re.split(r'(?<=[.!?])\s+', text)


def build_graph_from_text(text, gid, source_file=''):
    tokens = tokenize(text)
    lemmas = [lemma(t) for t in tokens if t not in STOPWORDS]
    if not lemmas:
        return 0
    freq = Counter(lemmas)
    maxf = max(freq.values()) if freq else 1

    adj = defaultdict(lambda: defaultdict(float))
    win = 4
    for i, w in enumerate(lemmas):
        for j in range(max(0, i - win), min(len(lemmas), i + win + 1)):
            if i != j:
                adj[w][lemmas[j]] += 1

    node_ids = {}
    for w, f in freq.items():
        nid = db.get_node_id(w, gid)
        if nid:
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute(
                    "SELECT source_file, size FROM nodes WHERE id=?", (nid,)
                ).fetchone()
            old_sources = row[0] if row else ''
            if source_file and source_file not in old_sources:
                new_sources = (old_sources + ',' + source_file).strip(',')
            else:
                new_sources = old_sources
            old_size = row[1] if row else 10
            new_size = old_size + (5 + (f / maxf) * 10)
            db.update_node(nid, source_file=new_sources, size=new_size)
            node_ids[w] = nid
        else:
            size = 5 + (f / maxf) * 25
            nid = db.add_node(gid, w, size=size, source_file=source_file)
            node_ids[w] = nid

    for src, neigh in adj.items():
        if src not in node_ids or node_ids[src] is None:
            continue
        for dst, wgt in neigh.items():
            if src < dst and dst in node_ids and node_ids[dst] is not None:
                db.add_edge(gid, node_ids[src], node_ids[dst], wgt, source_file=source_file)

    comms = louvain(adj)
    for w, c in comms.items():
        if w in node_ids and node_ids[w]:
            db.update_node(node_ids[w], community=c)

    bcs = betweenness(adj)
    for w, bc in bcs.items():
        if w in node_ids and node_ids[w]:
            db.update_node(node_ids[w], betweenness=bc)

    sentences = extract_sentences(text)
    for sent in sentences:
        sent = sent.strip()
        if len(sent) < 10:
            continue
        sent_tokens = tokenize(sent)
        sent_lemmas = {lemma(t) for t in sent_tokens if t not in STOPWORDS}
        linked_node_ids = [node_ids[lem] for lem in sent_lemmas
                            if lem in node_ids and node_ids[lem] is not None]
        if linked_node_ids:
            db.store_sentence(gid, source_file, sent, linked_node_ids)

    return len(node_ids)


def louvain(adj, max_iter=50):
    nodes = list(adj.keys())
    if not nodes:
        return {}
    comm = {n: i for i, n in enumerate(nodes)}
    m = sum(sum(nb.values()) for nb in adj.values()) / 2
    if m == 0:
        return comm
    for _ in range(max_iter):
        changed = False
        random.shuffle(nodes)
        for n in nodes:
            cur = comm[n]
            nb_comms = {comm[nb] for nb in adj[n] if nb in comm}
            comm_w = defaultdict(float)
            for nn, cc in comm.items():
                for nb, w in adj[nn].items():
                    if comm.get(nb) == cc:
                        comm_w[cc] += w
            best_gain, best = 0, cur
            for c in nb_comms:
                k_i = sum(adj[n].values())
                k_i_in = sum(w for nb, w in adj[n].items() if comm.get(nb) == c)
                sum_tot = comm_w.get(c, 0)
                gain = (k_i_in / (2 * m)) - (sum_tot * k_i / (2 * m) ** 2)
                if gain > best_gain:
                    best_gain, best = gain, c
            if best != cur:
                comm[n] = best
                changed = True
        if not changed:
            break
    mapping = {o: i for i, o in enumerate(sorted(set(comm.values())))}
    return {n: mapping[c] for n, c in comm.items()}


def betweenness(adj):
    nodes = list(adj.keys())
    C = {n: 0.0 for n in nodes}
    for s in nodes:
        S, P = [], {n: [] for n in nodes}
        sigma = {n: 0 for n in nodes}
        sigma[s] = 1
        d = {n: -1 for n in nodes}
        d[s] = 0
        Q = deque([s])
        while Q:
            v = Q.popleft()
            S.append(v)
            for w in adj[v]:
                if d[w] < 0:
                    Q.append(w)
                    d[w] = d[v] + 1
                if d[w] == d[v] + 1:
                    sigma[w] += sigma[v]
                    P[w].append(v)
        delta = {n: 0.0 for n in nodes}
        while S:
            w = S.pop()
            for v in P[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != s:
                C[w] += delta[w]
    n = len(nodes)
    if n > 2:
        for nn in C:
            C[nn] /= ((n - 1) * (n - 2))
    return C


def extract_docx(path):
    try:
        with zipfile.ZipFile(path) as z:
            xml = z.read('word/document.xml')
            root = ET.fromstring(xml)
            ns = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
            paragraphs = []
            for p in root.iter(f'{{{ns}}}p'):
                texts = [t.text or '' for t in p.iter(f'{{{ns}}}t')]
                paragraphs.append(''.join(texts))
            return '\n'.join(paragraphs)
    except Exception:
        return ""


def extract_ipynb_text(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            nb = json.load(f)
        texts = []
        for cell in nb.get('cells', []):
            if cell.get('cell_type') in ('code', 'markdown'):
                texts.append(''.join(cell.get('source', [])))
        return '\n'.join(texts)
    except Exception:
        return ""


def read_text_file(path):
    try:
        return Path(path).read_text(encoding='utf-8')
    except Exception:
        return ""


@hookimpl
def _builtin_extract_text(path, ext):
    """Default importer plugin: txt/py/md/csv/rst/tex/log, docx, ipynb, else best-effort text."""
    if ext in ('txt', 'py', 'md', 'csv', 'rst', 'tex', 'log'):
        return read_text_file(path)
    if ext == 'docx':
        return extract_docx(path)
    if ext == 'ipynb':
        return extract_ipynb_text(path)
    return read_text_file(path)


if HAVE_PLUGGY:
    class _BuiltinImporterPlugin:
        oo_extract_text = staticmethod(_builtin_extract_text)
    _plugin_manager.register(_BuiltinImporterPlugin())


def extract_text_for_file(path, ext):
    """Run through registered import plugins (pluggy) first, then the builtin fallback."""
    if HAVE_PLUGGY:
        for result in _plugin_manager.hook.oo_extract_text(path=str(path), ext=ext):
            if result:
                return result
    return _builtin_extract_text(path, ext)


# ======================================================================
#  CODE INTELLIGENCE  (derived from lsp.py / python_ls.py / workspace.py)
#  A light in-process substitute for the stdio Language Server protocol,
#  exposed over plain HTTP so the built-in web editor gets diagnostics
#  and completions without needing an external editor client.
# ======================================================================
class DiagnosticSeverity:
    ERROR = 1
    WARNING = 2
    INFORMATION = 3
    HINT = 4


class CodeDocument:
    """Mirrors workspace.py's Document: tracks a source buffer + version."""

    def __init__(self, uri, source=""):
        self.uri = uri
        self.source = source
        self.version = 0

    def apply_change(self, new_source):
        self.source = new_source
        self.version += 1


class CodeIntelligence:
    """In-process code intelligence engine (diagnostics + completions)."""

    def __init__(self):
        self._docs = {}
        self._lock = threading.Lock()

    def open(self, uri, source):
        with self._lock:
            doc = self._docs.get(uri)
            if doc is None:
                doc = CodeDocument(uri, source)
                self._docs[uri] = doc
            else:
                doc.apply_change(source)
            return doc

    # ---- diagnostics -------------------------------------------------
    def diagnostics(self, uri, source):
        self.open(uri, source)
        if HAVE_PYFLAKES:
            return self._diagnostics_pyflakes(source)
        return self._diagnostics_stdlib(source)

    def _diagnostics_pyflakes(self, source):
        import ast as _ast

        class _Collector(_pyflakes_reporter.Reporter):
            def __init__(self):
                self.messages = []

            def unexpectedError(self, filename, msg):
                self.messages.append((1, str(msg)))

            def syntaxError(self, filename, msg, lineno, offset, text):
                self.messages.append((lineno or 1, str(msg)))

            def flake(self, message):
                self.messages.append((message.lineno, str(message)))

        collector = _Collector()
        try:
            _pyflakes_api.check(source, "editor_buffer", reporter=collector)
        except Exception as e:  # pyflakes internal error -> fall back
            return self._diagnostics_stdlib(source) or [{
                "line": 1, "severity": DiagnosticSeverity.WARNING, "message": str(e)
            }]
        return [{"line": ln, "severity": DiagnosticSeverity.WARNING, "message": msg}
                for ln, msg in collector.messages]

    def _diagnostics_stdlib(self, source):
        """No pyflakes available: fall back to a plain compile() syntax check."""
        try:
            compile(source, "editor_buffer", "exec")
            return []
        except SyntaxError as e:
            return [{
                "line": e.lineno or 1,
                "severity": DiagnosticSeverity.ERROR,
                "message": f"SyntaxError: {e.msg}"
            }]
        except Exception as e:
            return [{"line": 1, "severity": DiagnosticSeverity.ERROR, "message": str(e)}]

    # ---- completions ---------------------------------------------------
    def complete(self, uri, source, line, column):
        self.open(uri, source)
        if HAVE_JEDI:
            try:
                script = _jedi.Script(code=source, path=uri)
                completions = script.complete(line=line, column=column)
                return [{"label": c.name, "detail": c.type} for c in completions[:30]]
            except Exception:
                pass
        return self._complete_keywords(source, line, column)

    _PY_KEYWORDS = sorted([
        "def", "class", "return", "import", "from", "if", "elif", "else",
        "for", "while", "try", "except", "finally", "with", "as", "lambda",
        "yield", "global", "nonlocal", "pass", "break", "continue", "print",
        "len", "range", "self", "None", "True", "False", "and", "or", "not",
        "in", "is", "raise", "assert", "async", "await"
    ])

    def _complete_keywords(self, source, line, column):
        lines = source.splitlines() or [""]
        idx = max(0, min(line, len(lines) - 1))
        text_before = lines[idx][:column] if idx < len(lines) else ""
        m = re.search(r'([A-Za-z_][A-Za-z0-9_]*)$', text_before)
        prefix = m.group(1) if m else ""
        matches = [kw for kw in self._PY_KEYWORDS if kw.startswith(prefix)] if prefix else self._PY_KEYWORDS[:15]
        return [{"label": kw, "detail": "keyword"} for kw in matches]


code_intel = CodeIntelligence()


# ======================================================================
#  HTTP REQUEST HANDLER
# ======================================================================
PUBLIC_PATHS = {"/login", "/api/login"}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"{APP_NAME.replace(' ', '')}/{APP_VERSION}"

    # ---- auth helpers --------------------------------------------------
    def _get_cookie(self, name):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie()
        jar.load(raw)
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def _current_session(self):
        token = self._get_cookie(SESSION_COOKIE)
        if not token:
            return None
        return dc.session_for(token)

    def _require_auth(self):
        session = self._current_session()
        if not session:
            self._json({"error": "authentication required"}, 401)
            return None
        return session

    def _require_admin(self):
        session = self._require_auth()
        if session and session["role"] != "admin":
            self._json({"error": "admin role required"}, 403)
            return None
        return session

    def _client_ip(self):
        return self.client_address[0] if self.client_address else ""

    # ---- routing ---------------------------------------------------
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)

        if p.path not in PUBLIC_PATHS and p.path not in ("/login.html",):
            if p.path in ("/", "/dashboard") and not self._current_session():
                self._redirect("/login")
                return

        if p.path == '/' or p.path == '/dashboard':
            self._dash()
        elif p.path == '/login':
            self._login_page()
        elif p.path == '/api/whoami':
            self._json(self._current_session() or {})
        elif p.path == '/api/master':
            if not self._require_auth():
                return
            self._json(db.get_graph(master_gid))
        elif p.path == '/api/stats':
            if not self._require_auth():
                return
            self._json(db.stats(master_gid))
        elif p.path == '/api/search':
            if not self._require_auth():
                return
            self._search(q)
        elif p.path == '/api/node':
            if not self._require_auth():
                return
            self._node_detail(q)
        elif p.path == '/api/files':
            if not self._require_auth():
                return
            self._json([f.name for f in UPLOAD_DIR.iterdir() if f.is_file()])
        elif p.path == '/api/file':
            if not self._require_auth():
                return
            self._file(q)
        elif p.path == '/api/audit':
            if not self._require_admin():
                return
            self._json(dc.recent_log())
        elif p.path == '/api/trial/status':
            if not self._require_auth():
                return
            self._json(dc.trial_status())
        elif p.path == '/api/platform':
            if not self._require_auth():
                return
            category = q.get('category', [''])[0]
            if category not in PLATFORM_CATEGORIES:
                self._json({'error': 'unknown category'}, 400)
                return
            self._json(platform_store.list_items(category))
        elif p.path == '/api/notifications':
            if not self._require_auth():
                return
            self._json(platform_store.recent_notifications())
        else:
            self.send_error(404)

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == '/api/login':
            self._do_login()
            return
        if p.path == '/api/logout':
            self._do_logout()
            return

        if p.path == '/api/import':
            if not self._require_auth():
                return
            self._import()
        elif p.path == '/api/run':
            if not self._require_auth():
                return
            self._run()
        elif p.path == '/api/notebook':
            if not self._require_auth():
                return
            self._notebook()
        elif p.path == '/api/lsp/diagnostics':
            if not self._require_auth():
                return
            self._lsp_diagnostics()
        elif p.path == '/api/lsp/complete':
            if not self._require_auth():
                return
            self._lsp_complete()
        elif p.path == '/api/users/create':
            if not self._require_admin():
                return
            self._create_user()
        elif p.path == '/api/platform/create':
            if not self._require_auth():
                return
            self._platform_create()
        elif p.path == '/api/platform/delete':
            if not self._require_admin():
                return
            self._platform_delete()
        elif p.path == '/api/file/delete':
            if not self._require_admin():
                return
            self._file_delete()
        elif p.path == '/api/graph/reset':
            if not self._require_admin():
                return
            self._graph_reset()
        else:
            self.send_error(404)

    # ---- responses ---------------------------------------------------
    def _redirect(self, location):
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()

    def _dash(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(DASHBOARD.encode())

    def _login_page(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(LOGIN_PAGE.encode())

    def _json(self, data, code=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    # ---- auth endpoints ---------------------------------------------
    def _issue_session(self, username, role, extra=None):
        token = dc.new_session(username, role)
        self.send_response(200)
        cookie = cookies.SimpleCookie()
        cookie[SESSION_COOKIE] = token
        cookie[SESSION_COOKIE]["path"] = "/"
        cookie[SESSION_COOKIE]["httponly"] = True
        self.send_header('Set-Cookie', cookie[SESSION_COOKIE].OutputString())
        payload = {"ok": True, "user": username, "role": role}
        if extra:
            payload.update(extra)
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _do_login(self):
        data = self._read_json_body()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        # --- Access code 1: unrestricted, no expiry ---
        if password and _verify_password(password, FULL_ACCESS_SALT, FULL_ACCESS_HASH):
            user = username or "admin"
            dc.log(user, "login_success_full", ip=self._client_ip())
            self._issue_session(user, "admin")
            return

        # --- Access code 2: rolling 10-day trial window ---
        if password and _verify_password(password, TRIAL_ACCESS_SALT, TRIAL_ACCESS_HASH):
            trial = dc.trial_login_attempt()
            if not trial:
                dc.log(username or "trial", "login_failed_trial_expired", ip=self._client_ip())
                self._json({"error": "دوره ۱۰ روزه‌ی این رمز عبور به پایان رسیده است."}, 403)
                return
            user = username or "trial"
            dc.log(user, "login_success_trial", detail=f"expires {trial['expires_at']}",
                   ip=self._client_ip())
            self._issue_session(user, "trial", {"trial_expires": trial["expires_at"]})
            return

        # --- fallback: any additional accounts created via /api/users/create ---
        result = dc.authenticate(username, password)
        if not result:
            dc.log(username or "?", "login_failed", ip=self._client_ip())
            self._json({"error": "invalid credentials"}, 401)
            return
        dc.log(result["user"], "login_success", ip=self._client_ip())
        self._issue_session(result["user"], result["role"])

    def _do_logout(self):
        token = self._get_cookie(SESSION_COOKIE)
        session = dc.session_for(token) if token else None
        if token:
            dc.drop_session(token)
        if session:
            dc.log(session["user"], "logout", ip=self._client_ip())
        self._json({"ok": True})

    def _create_user(self):
        data = self._read_json_body()
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = data.get("role") or "viewer"
        if not username or not password:
            self._json({"error": "username and password required"}, 400)
            return
        try:
            dc.create_user(username, password, role)
        except sqlite3.IntegrityError:
            self._json({"error": "user already exists"}, 409)
            return
        session = self._current_session()
        dc.log(session["user"], "user_created", detail=f"{username} ({role})", ip=self._client_ip())
        self._json({"ok": True})

    # ---- Apollo-style platform panels (Environments, Products, ------
    #      Release Channels, Teams, Change Mgmt, Plans) ----------------
    def _platform_create(self):
        session = self._current_session()
        data = self._read_json_body()
        category = data.get("category", "")
        title = (data.get("title") or "").strip()
        fields = data.get("fields") or {}
        status = data.get("status") or "active"
        if category not in PLATFORM_CATEGORIES or not title:
            self._json({"error": "category and title are required"}, 400)
            return
        iid = platform_store.create_item(category, title, fields, status)
        dc.log(session["user"], "platform_item_created",
               detail=f"{category}: {title}", ip=self._client_ip())
        self._json({"ok": True, "id": iid})

    def _platform_delete(self):
        session = self._current_session()
        data = self._read_json_body()
        item_id = data.get("id")
        if not item_id:
            self._json({"error": "id required"}, 400)
            return
        platform_store.delete_item(item_id)
        dc.log(session["user"], "platform_item_deleted", detail=item_id, ip=self._client_ip())
        self._json({"ok": True})

    # ---- data lifecycle: delete previously imported data --------------
    def _file_delete(self):
        session = self._current_session()
        data = self._read_json_body()
        name = (data.get("name") or "").strip()
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            self._json({"error": "invalid filename"}, 400)
            return
        path = UPLOAD_DIR / name
        if not path.exists():
            self._json({"error": "not found"}, 404)
            return
        db.delete_source_file(master_gid, name)
        path.unlink()
        dc.log(session["user"], "file_deleted", detail=name, ip=self._client_ip())
        platform_store.notify(f"Imported data \u201c{name}\u201d was deleted from the knowledge graph.")
        self._json({"ok": True})

    def _graph_reset(self):
        session = self._current_session()
        db.reset_graph(master_gid)
        for f in UPLOAD_DIR.iterdir():
            if f.is_file():
                f.unlink()
        dc.log(session["user"], "graph_reset", ip=self._client_ip())
        platform_store.notify("The master knowledge graph and all imported files were reset.", "warn")
        self._json({"ok": True})

    # ---- graph endpoints ---------------------------------------------
    def _search(self, q):
        term = q.get('q', [''])[0]
        gid = q.get('gid', [master_gid])[0]
        self._json(db.search_nodes(gid, term) if term else [])

    def _node_detail(self, q):
        nid = q.get('id', [None])[0]
        if not nid:
            self._json({'error': 'missing id'}, 400)
            return
        details = db.get_node_details(nid)
        if not details:
            self._json({'error': 'node not found'}, 404)
            return
        self._json(details)

    def _file(self, q):
        name = q.get('name', [None])[0]
        if not name:
            self._json({'error': 'no name'}, 400)
            return
        path = UPLOAD_DIR / name
        if not path.exists():
            self._json({'error': 'not found'}, 404)
            return
        try:
            self._json({'content': path.read_text(encoding='utf-8'), 'uri': from_fs_path(path)})
        except Exception:
            self._json({'error': 'binary'}, 400)

    def _import(self):
        session = self._current_session()
        ct = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in ct:
            self._json({'error': 'multipart required'}, 400)
            return
        form = cgi.FieldStorage(
            fp=self.rfile, headers=self.headers,
            environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': ct}
        )
        item = form['file']
        if not item.file:
            self._json({'error': 'no file'}, 400)
            return
        fname = Path(item.filename).name
        dest = UPLOAD_DIR / fname
        with open(dest, 'wb') as f:
            shutil.copyfileobj(item.file, f)

        ext = fname.lower().rsplit('.', 1)[-1] if '.' in fname else ''
        text = extract_text_for_file(dest, ext)

        added = build_graph_from_text(text, master_gid, source_file=fname) if text.strip() else 0
        dc.log(session["user"], "import_file", detail=f"{fname} (+{added} nodes)", ip=self._client_ip())
        self._json({'status': 'ok', 'filename': fname, 'new_nodes': added, 'uri': from_fs_path(dest)})

    def _run(self):
        session = self._current_session()
        data = self._read_json_body()
        code = data.get('code', '')
        old = sys.stdout
        sys.stdout = io.StringIO()
        out = err = None
        try:
            exec(code, {'__builtins__': __builtins__})
            out = sys.stdout.getvalue()
        except Exception as e:
            out = traceback.format_exc()
            err = str(e)
        finally:
            sys.stdout = old
        dc.log(session["user"], "run_code", detail=code[:200], ip=self._client_ip())
        self._json({'output': out, 'error': err})

    def _notebook(self):
        session = self._current_session()
        nb = self._read_json_body()
        code = '\n'.join(
            ''.join(c.get('source', []))
            for c in nb.get('cells', [])
            if c.get('cell_type') == 'code'
        )
        old = sys.stdout
        sys.stdout = io.StringIO()
        out = err = None
        try:
            exec(code, {'__builtins__': __builtins__})
            out = sys.stdout.getvalue()
        except Exception as e:
            out = traceback.format_exc()
            err = str(e)
        finally:
            sys.stdout = old
        dc.log(session["user"], "run_notebook", ip=self._client_ip())
        self._json({'output': out, 'error': err})

    # ---- code intelligence endpoints ---------------------------------
    def _lsp_diagnostics(self):
        data = self._read_json_body()
        source = data.get('source', '')
        uri = data.get('uri', 'inmemory://editor_buffer')
        self._json({'diagnostics': code_intel.diagnostics(uri, source),
                     'engine': 'pyflakes' if HAVE_PYFLAKES else 'stdlib-compile'})

    def _lsp_complete(self):
        data = self._read_json_body()
        source = data.get('source', '')
        uri = data.get('uri', 'inmemory://editor_buffer')
        line = int(data.get('line', 0))
        column = int(data.get('column', 0))
        self._json({'completions': code_intel.complete(uri, source, line, column),
                     'engine': 'jedi' if HAVE_JEDI else 'keyword-fallback'})

    # quieter logging
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{APP_NAME}] {self.address_string()} - {fmt % args}\n")


# ======================================================================
#  FRONTEND — Login page
# ======================================================================
LOGIN_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OBLIVION ORBITAL — Secure Access</title>
<link rel="icon" href="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAQDAwMDAgQDAwMEBAQFBgoGBgUFBgwICQcKDgwPDg4MDQ0PERYTDxAVEQ0NExoTFRcYGRkZDxIbHRsYHRYYGRj/2wBDAQQEBAYFBgsGBgsYEA0QGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBj/wAARCABHAFADASIAAhEBAxEB/8QAGwABAAIDAQEAAAAAAAAAAAAAAAcIAQMGCQL/xAArEAABBAEDAwMDBQEAAAAAAAABAAIDBAUGBxEIEiETMWEiQVEJFBVCcZL/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A8/0REBERAREQEREBERAREQFtrVbN25HUpwS2J5XBkcUTS973H2AA8k/4tSnDpo3wymy+t8lJh9D1dV38zAynSrFobPHZ7+IzG8Mc/g9zmljeO7lvnwEHU7XdDu8mvmw5DUFOLRWHeA42Mw0/uHN/Law+r/ssHysbo9D28egWzZDT9OLWuHYC4WMO0/uGt/Lqx+r/AILx8qzmq9tN0twdHNzfUzv1R26wtz20zhpIqleMHz2SzSPAlf5HLT6gH5TSu2m6W3uj3Zrpm36obi4Wn76ZzMkVuvJx57Ipo3kRPPHho9MH8oPNCzVs0rclS5BLBPE4skilaWPY4e4IPkH/AFalN/UtvhlN6NcY2XL6Hq6Uv4au+ndrBodPJZ7+JDI8sa/gdrWhjue3h3nyVCCAiIgIiICt7+nzo7E5jfLO6zy0LJhprF+tWDhz6c0ri31B8iNsoHy7n7KoSsx0RbrYjbfqFfi9R2oquG1LV/jZLEzu2OGbvDoXPJ9mk9zCT4HqAngAoIl3h3V1HvDurktX5+5NIyWVzaNRziY6dfn6ImN9gAOOSPc8k+SvnaDdTUmz+6mN1fp65LG2KVrbtRriI7lfn64pG+xBHPHPseCPIUndQPSluDthuFkbOntNZLN6QsTuloXsfA6wYI3HkRTNYCWObz29xHDgAQfJAz0+9KW4O524eOtai03kcJpCtO2W/eyEDq5nY08mKFrwC9zuO3uA7Wgkk+ACHZfqDaOxOH3zwWssTC2Ealxfr2Q0cepNE4M9Q/JY6IH5bz91UJWW63N18TuV1DNx2nLMVrDabq/xkViEh0c03eXTOYR7tB7WAjwfT5HghVpQEREBERAREQWB216zN79tMHBg6uZp57F12hkFXOwmwYWD+rZGubIGgcAAuIH2AWNy+sre/czBWMHczVPBYuw0snq4OE1zMw/1dI5zpC0jwQHAH7gqv6ICIiAiIgIiICIiAiIgIiICIiD/2Q==">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{
    --black:#050607; --panel:#0c0f11; --panel-2:#111518;
    --line:#232a2e; --line-soft:#1a2023;
    --ink:#eceeee; --ink-dim:#8a969b;
    --steel:#5c8fb5; --steel-2:#3f6a8a; --steel-glow:rgba(92,143,181,0.16);
    --err:#c1655d;
  }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{
    height:100vh;background:var(--black);color:var(--ink);
    font-family:'Inter',sans-serif;display:flex;flex-direction:column;
    align-items:center;justify-content:center;position:relative;overflow:hidden;
  }
  h1,h2,h3{font-family:'Space Grotesk',sans-serif;font-weight:600;letter-spacing:-0.01em;}
  .mono{font-family:'IBM Plex Mono',monospace;}
  .bg-grid{
    position:absolute;inset:0;
    background-image:linear-gradient(var(--line-soft) 1px, transparent 1px),linear-gradient(90deg, var(--line-soft) 1px, transparent 1px);
    background-size:56px 56px;opacity:0.4;
    mask-image:radial-gradient(ellipse 65% 55% at 50% 45%, black 20%, transparent 75%);
  }
  .brandmark{position:relative;z-index:2;display:flex;align-items:center;gap:12px;margin-bottom:26px;}
  .brandmark img{width:34px;height:auto;filter:drop-shadow(0 0 30px var(--steel-glow));}
  .brandmark span{font-size:14px;font-weight:700;letter-spacing:0.14em;}
  .eyebrow{
    position:relative;z-index:2;font-size:12px;color:var(--steel);letter-spacing:0.14em;
    display:flex;align-items:center;gap:10px;margin-bottom:16px;
  }
  .eyebrow::before,.eyebrow::after{content:'';width:20px;height:1px;background:var(--steel);}
  h1.title{position:relative;z-index:2;font-size:clamp(36px,6vw,54px);letter-spacing:0.02em;text-align:center;}
  .sub{position:relative;z-index:2;margin-top:12px;color:var(--ink-dim);font-size:14.5px;text-align:center;max-width:380px;line-height:1.6;}

  .panel{
    position:relative;z-index:2;margin-top:38px;width:360px;max-width:90vw;
    background:var(--panel);border:1px solid var(--line);padding:34px 32px;
  }
  .field-label{font-size:11px;color:var(--ink-dim);letter-spacing:0.08em;margin-bottom:6px;display:block;}
  input{
    width:100%;padding:11px 12px;margin-bottom:18px;
    background:var(--panel-2);border:1px solid var(--line);color:var(--ink);
    font-size:14px;font-family:'Inter',sans-serif;transition:border-color .2s;
  }
  input:focus{outline:none;border-color:var(--steel);}
  button.btn-primary{
    width:100%;background:var(--ink);color:var(--black);border:none;
    padding:13px;font-size:14px;font-weight:500;cursor:pointer;transition:background .2s;
    font-family:'Inter',sans-serif;
  }
  button.btn-primary:hover{background:var(--steel);}
  #msg{color:var(--err);font-size:12.5px;margin-top:14px;min-height:14px;text-align:center;}
  :focus-visible{outline:2px solid var(--steel);outline-offset:2px;}
</style>
</head>
<body>
  <div class="bg-grid"></div>
  <div class="brandmark">
    <img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAQDAwMDAgQDAwMEBAQFBgoGBgUFBgwICQcKDgwPDg4MDQ0PERYTDxAVEQ0NExoTFRcYGRkZDxIbHRsYHRYYGRj/2wBDAQQEBAYFBgsGBgsYEA0QGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBj/wAARCABHAFADASIAAhEBAxEB/8QAGwABAAIDAQEAAAAAAAAAAAAAAAcIAQMGCQL/xAArEAABBAEDAwMDBQEAAAAAAAABAAIDBAUGBxEIEiETMWEiQVEJFBVCcZL/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A8/0REBERAREQEREBERAREQFtrVbN25HUpwS2J5XBkcUTS973H2AA8k/4tSnDpo3wymy+t8lJh9D1dV38zAynSrFobPHZ7+IzG8Mc/g9zmljeO7lvnwEHU7XdDu8mvmw5DUFOLRWHeA42Mw0/uHN/Law+r/ssHysbo9D28egWzZDT9OLWuHYC4WMO0/uGt/Lqx+r/AILx8qzmq9tN0twdHNzfUzv1R26wtz20zhpIqleMHz2SzSPAlf5HLT6gH5TSu2m6W3uj3Zrpm36obi4Wn76ZzMkVuvJx57Ipo3kRPPHho9MH8oPNCzVs0rclS5BLBPE4skilaWPY4e4IPkH/AFalN/UtvhlN6NcY2XL6Hq6Uv4au+ndrBodPJZ7+JDI8sa/gdrWhjue3h3nyVCCAiIgIiICt7+nzo7E5jfLO6zy0LJhprF+tWDhz6c0ri31B8iNsoHy7n7KoSsx0RbrYjbfqFfi9R2oquG1LV/jZLEzu2OGbvDoXPJ9mk9zCT4HqAngAoIl3h3V1HvDurktX5+5NIyWVzaNRziY6dfn6ImN9gAOOSPc8k+SvnaDdTUmz+6mN1fp65LG2KVrbtRriI7lfn64pG+xBHPHPseCPIUndQPSluDthuFkbOntNZLN6QsTuloXsfA6wYI3HkRTNYCWObz29xHDgAQfJAz0+9KW4O524eOtai03kcJpCtO2W/eyEDq5nY08mKFrwC9zuO3uA7Wgkk+ACHZfqDaOxOH3zwWssTC2Ealxfr2Q0cepNE4M9Q/JY6IH5bz91UJWW63N18TuV1DNx2nLMVrDabq/xkViEh0c03eXTOYR7tB7WAjwfT5HghVpQEREBERAREQWB216zN79tMHBg6uZp57F12hkFXOwmwYWD+rZGubIGgcAAuIH2AWNy+sre/czBWMHczVPBYuw0snq4OE1zMw/1dI5zpC0jwQHAH7gqv6ICIiAiIgIiICIiAiIgIiICIiD/2Q==" alt="OBLIVION mark">
    <span>OBLIVION</span>
  </div>
  <div class="eyebrow mono">[ AUTHENTICATION REQUIRED ]</div>
  <h1 class="title">ORBITAL</h1>
  <div class="sub">Unified knowledge-graph &amp; code-intelligence console. Sign in to continue.</div>

  <form class="panel" id="f">
    <label class="field-label mono">USERNAME (optional)</label>
    <input id="u" autocomplete="username" placeholder="admin">
    <label class="field-label mono">ACCESS CODE</label>
    <input id="p" type="password" autocomplete="current-password" required>
    <button class="btn-primary" type="submit">Sign in</button>
    <div id="msg"></div>
  </form>

<script>
document.getElementById('f').onsubmit = async (e) => {
  e.preventDefault();
  const username = document.getElementById('u').value;
  const password = document.getElementById('p').value;
  const r = await fetch('/api/login', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username, password})
  });
  if (r.ok) { window.location.href = '/dashboard'; }
  else {
    const d = await r.json();
    document.getElementById('msg').textContent = d.error || 'Login failed';
  }
};
</script>
</body>
</html>"""


# ======================================================================
#  FRONTEND — Main dashboard
# ======================================================================
DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OBLIVION ORBITAL — Console</title>
<link rel="icon" href="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAQDAwMDAgQDAwMEBAQFBgoGBgUFBgwICQcKDgwPDg4MDQ0PERYTDxAVEQ0NExoTFRcYGRkZDxIbHRsYHRYYGRj/2wBDAQQEBAYFBgsGBgsYEA0QGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBj/wAARCABHAFADASIAAhEBAxEB/8QAGwABAAIDAQEAAAAAAAAAAAAAAAcIAQMGCQL/xAArEAABBAEDAwMDBQEAAAAAAAABAAIDBAUGBxEIEiETMWEiQVEJFBVCcZL/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A8/0REBERAREQEREBERAREQFtrVbN25HUpwS2J5XBkcUTS973H2AA8k/4tSnDpo3wymy+t8lJh9D1dV38zAynSrFobPHZ7+IzG8Mc/g9zmljeO7lvnwEHU7XdDu8mvmw5DUFOLRWHeA42Mw0/uHN/Law+r/ssHysbo9D28egWzZDT9OLWuHYC4WMO0/uGt/Lqx+r/AILx8qzmq9tN0twdHNzfUzv1R26wtz20zhpIqleMHz2SzSPAlf5HLT6gH5TSu2m6W3uj3Zrpm36obi4Wn76ZzMkVuvJx57Ipo3kRPPHho9MH8oPNCzVs0rclS5BLBPE4skilaWPY4e4IPkH/AFalN/UtvhlN6NcY2XL6Hq6Uv4au+ndrBodPJZ7+JDI8sa/gdrWhjue3h3nyVCCAiIgIiICt7+nzo7E5jfLO6zy0LJhprF+tWDhz6c0ri31B8iNsoHy7n7KoSsx0RbrYjbfqFfi9R2oquG1LV/jZLEzu2OGbvDoXPJ9mk9zCT4HqAngAoIl3h3V1HvDurktX5+5NIyWVzaNRziY6dfn6ImN9gAOOSPc8k+SvnaDdTUmz+6mN1fp65LG2KVrbtRriI7lfn64pG+xBHPHPseCPIUndQPSluDthuFkbOntNZLN6QsTuloXsfA6wYI3HkRTNYCWObz29xHDgAQfJAz0+9KW4O524eOtai03kcJpCtO2W/eyEDq5nY08mKFrwC9zuO3uA7Wgkk+ACHZfqDaOxOH3zwWssTC2Ealxfr2Q0cepNE4M9Q/JY6IH5bz91UJWW63N18TuV1DNx2nLMVrDabq/xkViEh0c03eXTOYR7tB7WAjwfT5HghVpQEREBERAREQWB216zN79tMHBg6uZp57F12hkFXOwmwYWD+rZGubIGgcAAuIH2AWNy+sre/czBWMHczVPBYuw0snq4OE1zMw/1dI5zpC0jwQHAH7gqv6ICIiAiIgIiICIiAiIgIiICIiD/2Q==">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Inter:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --black:#050607; --panel:#0c0f11; --panel-2:#111518;
  --line:#232a2e; --line-soft:#1a2023;
  --ink:#eceeee; --ink-dim:#8a969b;
  --steel:#5c8fb5; --steel-2:#3f6a8a; --steel-glow:rgba(92,143,181,0.16);
  --warn:#c9a35f; --err:#c1655d; --ok:#5fae8d;
}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;}
body{
  display:flex;flex-direction:column;background:var(--black);color:var(--ink);
  font-family:'Inter',sans-serif;overflow:hidden;
}
h1,h2,h3{font-family:'Space Grotesk',sans-serif;font-weight:600;letter-spacing:-0.01em;}
.mono{font-family:'IBM Plex Mono',monospace;}
::selection{background:var(--steel);color:#000;}

/* ---- TOP NAV ---- */
#topnav{
  height:56px;flex:0 0 56px;display:flex;align-items:center;justify-content:space-between;
  padding:0 22px;border-bottom:1px solid var(--line);background:var(--panel);z-index:50;
}
#topnav .brand{display:flex;align-items:center;gap:10px;font-size:13.5px;font-weight:700;letter-spacing:0.1em;}
#topnav .brand img{width:22px;height:auto;}
#topnav .status{margin-left:18px;font-size:11px;color:var(--steel);letter-spacing:0.1em;display:flex;align-items:center;gap:8px;}
.dot{width:6px;height:6px;border-radius:50%;background:var(--ok);box-shadow:0 0 8px var(--ok);}
#topnav-right{display:flex;align-items:center;gap:14px;}
#whoami{font-size:12px;color:var(--ink-dim);}
.navbtn{
  font-size:12px;border:1px solid var(--line);padding:7px 14px;color:var(--ink);
  background:transparent;cursor:pointer;font-family:'Inter',sans-serif;transition:border-color .2s,color .2s;
}
.navbtn:hover{border-color:var(--steel);color:var(--steel);}

/* ---- APP BODY ---- */
#appbody{flex:1;display:flex;min-height:0;}

/* ---- SIDEBAR ---- */
#sidebar{width:250px;flex:0 0 250px;background:var(--panel);border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0;}
.side-tag{padding:14px 16px 8px;font-size:11px;color:var(--steel);letter-spacing:0.12em;}
#files{flex:1;overflow-y:auto;padding:0 8px;}
.file{padding:8px 10px;cursor:pointer;font-size:13px;color:var(--ink-dim);border-left:2px solid transparent;transition:.15s;}
.file:hover{background:var(--panel-2);color:var(--ink);border-left-color:var(--steel);}
#import-btn{
  margin:14px;padding:11px;background:var(--ink);color:var(--black);border:none;
  font-weight:500;cursor:pointer;font-size:13px;transition:background .2s;
}
#import-btn:hover{background:var(--steel);}
#userbar{display:none;} /* legacy anchor kept for JS ids; visuals moved to topnav */

/* ---- MAIN ---- */
#main{flex:1;display:flex;flex-direction:column;min-width:0;}
#toolbar{
  background:var(--panel);padding:10px 18px;display:flex;gap:10px;align-items:center;
  border-bottom:1px solid var(--line);
}
.btn-outline{
  font-size:12.5px;border:1px solid var(--line);padding:8px 16px;color:var(--ink);
  background:transparent;cursor:pointer;font-family:'Inter',sans-serif;transition:border-color .2s,color .2s;
}
.btn-outline:hover{border-color:var(--steel);color:var(--steel);}
#stats{margin-left:auto;font-size:12px;color:var(--ink-dim);}
#stats.mono{letter-spacing:0.04em;}

#panels{flex:1;display:flex;min-height:0;}
#editor-panel{width:46%;display:flex;flex-direction:column;border-right:1px solid var(--line);position:relative;min-height:0;}
.panel-label{
  padding:9px 16px;font-size:11px;color:var(--steel);letter-spacing:0.12em;
  border-bottom:1px solid var(--line-soft);background:var(--panel);
}
#editor{
  flex:1;background:var(--black);color:#c9d6db;border:none;padding:14px 16px;
  font-family:'IBM Plex Mono',monospace;resize:none;font-size:13px;line-height:1.6;
}
#editor:focus{outline:none;}
#completions{
  position:absolute;background:var(--panel);border:1px solid var(--line);
  max-height:170px;overflow-y:auto;display:none;z-index:20;font-size:12.5px;
}
.comp-item{padding:6px 12px;cursor:pointer;font-family:'IBM Plex Mono',monospace;}
.comp-item:hover{background:var(--panel-2);color:var(--steel);}
#diag-bar{max-height:76px;overflow-y:auto;background:var(--panel-2);border-top:1px solid var(--line);font-size:11.5px;font-family:'IBM Plex Mono',monospace;}
.diag-item{padding:4px 14px;border-bottom:1px solid var(--line-soft);color:var(--warn);}
.diag-item.err{color:var(--err);}
#output{
  height:150px;flex:0 0 150px;background:var(--black);color:var(--ok);border-top:1px solid var(--line);
  padding:10px 16px;overflow:auto;font-size:11.5px;white-space:pre-wrap;font-family:'IBM Plex Mono',monospace;
}

#graph-panel{flex:1;position:relative;background:var(--panel-2);}
#graph-panel::before{
  content:'';position:absolute;inset:0;pointer-events:none;
  background-image:linear-gradient(var(--line-soft) 1px, transparent 1px),linear-gradient(90deg, var(--line-soft) 1px, transparent 1px);
  background-size:44px 44px;opacity:0.5;
}
#search-wrap{position:absolute;top:14px;left:14px;z-index:5;width:220px;}
#search{
  width:100%;padding:9px 12px;background:var(--panel);border:1px solid var(--line);
  color:var(--ink);font-size:12.5px;font-family:'Inter',sans-serif;
}
#search:focus{outline:none;border-color:var(--steel);}
#search-results{
  position:absolute;top:100%;left:0;width:100%;background:var(--panel);
  border:1px solid var(--line);border-top:none;max-height:160px;overflow-y:auto;display:none;z-index:10;
}
.search-item{padding:8px 12px;cursor:pointer;font-size:12.5px;color:var(--ink-dim);border-bottom:1px solid var(--line-soft);}
.search-item:hover{background:var(--panel-2);color:var(--ink);}
canvas{display:block;position:relative;z-index:1;}

/* ---- MODALS ---- */
.modal{display:none;position:fixed;z-index:100;left:0;top:0;width:100%;height:100%;background:rgba(5,6,7,0.82);}
.modal-content{
  background:var(--panel);margin:5% auto;padding:28px 30px;border:1px solid var(--line);
  width:620px;max-width:90vw;max-height:80vh;overflow-y:auto;color:var(--ink);
}
.modal-content h3{font-size:19px;margin-bottom:4px;}
.close{color:var(--ink-dim);float:right;font-size:22px;font-weight:400;cursor:pointer;line-height:1;}
.close:hover{color:var(--ink);}
.modal-table{width:100%;border-collapse:collapse;font-size:13px;margin-top:14px;}
.modal-table td,.modal-table th{padding:7px 6px;border-bottom:1px solid var(--line-soft);text-align:left;}
.modal-table th{color:var(--ink-dim);width:140px;font-weight:500;font-size:12px;}
.article-box{
  background:var(--panel-2);border:1px solid var(--line);padding:14px;margin-top:10px;
  max-height:280px;overflow-y:auto;white-space:pre-wrap;font-size:13px;line-height:1.6;color:var(--ink-dim);
}
h4.modal-h{margin-top:20px;font-size:12px;color:var(--steel);letter-spacing:0.1em;font-family:'IBM Plex Mono',monospace;font-weight:500;}
#audit-modal .modal-content{width:760px;}
#audit-table{width:100%;font-size:11.5px;border-collapse:collapse;font-family:'IBM Plex Mono',monospace;}
#audit-table th{text-align:left;padding:6px;color:var(--steel);border-bottom:1px solid var(--line);font-weight:500;}
#audit-table td{padding:6px;border-bottom:1px solid var(--line-soft);color:var(--ink-dim);}

::-webkit-scrollbar{width:9px;height:9px;}
::-webkit-scrollbar-track{background:var(--black);}
::-webkit-scrollbar-thumb{background:var(--line);}
::-webkit-scrollbar-thumb:hover{background:var(--steel-2);}
:focus-visible{outline:2px solid var(--steel);outline-offset:2px;}

/* ---- APOLLO-STYLE PLATFORM NAVIGATION ---- */
#nav-platform{padding:0 8px 14px;overflow-y:auto;}
.nav-item{
  padding:9px 10px;cursor:pointer;font-size:12.5px;color:var(--ink-dim);
  border-left:2px solid transparent;transition:.15s;display:flex;flex-direction:column;gap:1px;
}
.nav-item .nav-sub{font-size:10.5px;color:#5c6a70;}
.nav-item:hover{background:var(--panel-2);color:var(--ink);}
.nav-item.active{background:var(--panel-2);color:var(--ink);border-left-color:var(--steel);}
.nav-item.active .nav-sub{color:var(--steel);}

.trial-badge{
  font-size:10.5px;color:var(--warn);border:1px solid var(--warn);padding:3px 8px;
  letter-spacing:0.06em;margin-left:10px;
}

/* ---- SECTION PANELS (Environments / Products / Teams / etc.) ---- */
.section-panel{flex:1;display:flex;flex-direction:column;min-height:0;overflow:hidden;}
.section-panel.hidden{display:none;}
.section-head{
  padding:14px 22px;border-bottom:1px solid var(--line);background:var(--panel);
  display:flex;align-items:baseline;justify-content:space-between;
}
.section-head h2{font-size:16px;}
.section-head .section-desc{font-size:12px;color:var(--ink-dim);margin-top:3px;}
.section-body{flex:1;overflow-y:auto;padding:20px 22px;}

.platform-form{
  display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;background:var(--panel);
  border:1px solid var(--line);padding:16px;margin-bottom:18px;
}
.platform-form .f-group{display:flex;flex-direction:column;gap:5px;}
.platform-form label{font-size:10.5px;color:var(--ink-dim);letter-spacing:0.06em;}
.platform-form input,.platform-form select{
  background:var(--panel-2);border:1px solid var(--line);color:var(--ink);
  padding:8px 10px;font-size:12.5px;font-family:'Inter',sans-serif;min-width:160px;
}
.platform-form input:focus,.platform-form select:focus{outline:none;border-color:var(--steel);}
.btn-add{
  background:var(--ink);color:var(--black);border:none;padding:9px 18px;
  font-size:12.5px;font-weight:500;cursor:pointer;transition:background .2s;
}
.btn-add:hover{background:var(--steel);}
.btn-danger{
  background:transparent;color:var(--err);border:1px solid var(--err);padding:5px 12px;
  font-size:11.5px;cursor:pointer;transition:.2s;
}
.btn-danger:hover{background:var(--err);color:#fff;}

.data-table{width:100%;border-collapse:collapse;font-size:12.5px;}
.data-table th{text-align:left;padding:9px 10px;color:var(--steel);border-bottom:1px solid var(--line);font-weight:500;font-size:11.5px;letter-spacing:0.04em;}
.data-table td{padding:9px 10px;border-bottom:1px solid var(--line-soft);color:var(--ink);}
.data-table tr:hover td{background:var(--panel-2);}
.badge{font-size:10.5px;padding:3px 9px;border:1px solid var(--line);letter-spacing:0.04em;display:inline-block;}
.badge-ok{color:var(--ok);border-color:var(--ok);}
.badge-warn{color:var(--warn);border-color:var(--warn);}
.badge-err{color:var(--err);border-color:var(--err);}
.empty-row{color:var(--ink-dim);font-style:italic;padding:14px 0;}
.notif-item{padding:10px 0;border-bottom:1px solid var(--line-soft);font-size:12.5px;}
.notif-item .notif-ts{font-size:10.5px;color:var(--ink-dim);margin-right:8px;font-family:'IBM Plex Mono',monospace;}
</style>
</head>
<body>

<div id="topnav">
  <div style="display:flex;align-items:center;">
    <div class="brand"><img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAQDAwMDAgQDAwMEBAQFBgoGBgUFBgwICQcKDgwPDg4MDQ0PERYTDxAVEQ0NExoTFRcYGRkZDxIbHRsYHRYYGRj/2wBDAQQEBAYFBgsGBgsYEA0QGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBj/wAARCABHAFADASIAAhEBAxEB/8QAGwABAAIDAQEAAAAAAAAAAAAAAAcIAQMGCQL/xAArEAABBAEDAwMDBQEAAAAAAAABAAIDBAUGBxEIEiETMWEiQVEJFBVCcZL/xAAUAQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A8/0REBERAREQEREBERAREQFtrVbN25HUpwS2J5XBkcUTS973H2AA8k/4tSnDpo3wymy+t8lJh9D1dV38zAynSrFobPHZ7+IzG8Mc/g9zmljeO7lvnwEHU7XdDu8mvmw5DUFOLRWHeA42Mw0/uHN/Law+r/ssHysbo9D28egWzZDT9OLWuHYC4WMO0/uGt/Lqx+r/AILx8qzmq9tN0twdHNzfUzv1R26wtz20zhpIqleMHz2SzSPAlf5HLT6gH5TSu2m6W3uj3Zrpm36obi4Wn76ZzMkVuvJx57Ipo3kRPPHho9MH8oPNCzVs0rclS5BLBPE4skilaWPY4e4IPkH/AFalN/UtvhlN6NcY2XL6Hq6Uv4au+ndrBodPJZ7+JDI8sa/gdrWhjue3h3nyVCCAiIgIiICt7+nzo7E5jfLO6zy0LJhprF+tWDhz6c0ri31B8iNsoHy7n7KoSsx0RbrYjbfqFfi9R2oquG1LV/jZLEzu2OGbvDoXPJ9mk9zCT4HqAngAoIl3h3V1HvDurktX5+5NIyWVzaNRziY6dfn6ImN9gAOOSPc8k+SvnaDdTUmz+6mN1fp65LG2KVrbtRriI7lfn64pG+xBHPHPseCPIUndQPSluDthuFkbOntNZLN6QsTuloXsfA6wYI3HkRTNYCWObz29xHDgAQfJAz0+9KW4O524eOtai03kcJpCtO2W/eyEDq5nY08mKFrwC9zuO3uA7Wgkk+ACHZfqDaOxOH3zwWssTC2Ealxfr2Q0cepNE4M9Q/JY6IH5bz91UJWW63N18TuV1DNx2nLMVrDabq/xkViEh0c03eXTOYR7tB7WAjwfT5HghVpQEREBERAREQWB216zN79tMHBg6uZp57F12hkFXOwmwYWD+rZGubIGgcAAuIH2AWNy+sre/czBWMHczVPBYuw0snq4OE1zMw/1dI5zpC0jwQHAH7gqv6ICIiAiIgIiICIiAiIgIiICIiD/2Q==" alt="OBLIVION mark">OBLIVION ORBITAL</div>
    <div class="status mono"><span class="dot"></span>[ SYSTEM ONLINE ]</div>
  </div>
  <div id="topnav-right">
    <span id="trial-badge" class="trial-badge mono" style="display:none"></span>
    <span id="whoami" class="mono">...</span>
    <button id="audit-btn" class="navbtn" style="display:none">Audit Log</button>
    <button id="logout-btn" class="navbtn">Logout</button>
  </div>
</div>

<div id="appbody">
  <div id="sidebar">
    <div class="side-tag mono">FILES</div>
    <div id="files"></div>
    <button id="import-btn">Import File</button>
    <input type="file" id="file-input" hidden multiple>
    <div id="userbar"></div>
    <div class="side-tag mono">REFERENCE</div>
    <div id="nav-platform">
      <div class="nav-item active" data-section="console" onclick="switchSection('console')">
        <span>Console</span><span class="nav-sub">Code &amp; knowledge graph</span>
      </div>
      <div class="nav-item" data-section="data" onclick="switchSection('data')">
        <span>Data</span><span class="nav-sub">Imported sources &amp; reset</span>
      </div>
      <div class="nav-item" data-section="environment" onclick="switchSection('environment')">
        <span>Environments</span><span class="nav-sub">Where things run</span>
      </div>
      <div class="nav-item" data-section="product" onclick="switchSection('product')">
        <span>Products &amp; Releases</span><span class="nav-sub">Versions in flight</span>
      </div>
      <div class="nav-item" data-section="channel" onclick="switchSection('channel')">
        <span>Release Channels</span><span class="nav-sub">Promotion sequence</span>
      </div>
      <div class="nav-item" data-section="team" onclick="switchSection('team')">
        <span>Teams &amp; Permissions</span><span class="nav-sub">RBAC roster</span>
      </div>
      <div class="nav-item" data-section="change" onclick="switchSection('change')">
        <span>Change Management</span><span class="nav-sub">Approvals &amp; compliance</span>
      </div>
      <div class="nav-item" data-section="plan" onclick="switchSection('plan')">
        <span>Upgrades &amp; Plans</span><span class="nav-sub">Plans &amp; constraints</span>
      </div>
      <div class="nav-item" data-section="notifications" onclick="switchSection('notifications')">
        <span>Notifications</span><span class="nav-sub">Platform activity feed</span>
      </div>
    </div>
  </div>
  <div id="main">

    <div id="section-console" class="section-panel">
      <div id="toolbar">
        <button id="run-btn" class="btn-outline">Run Python</button>
        <button id="nb-btn" class="btn-outline">Run Notebook</button>
        <button id="graph-refresh" class="btn-outline">Refresh Graph</button>
        <span id="stats" class="mono"></span>
      </div>
      <div id="panels">
        <div id="editor-panel">
          <div class="panel-label mono">[ CODE INTELLIGENCE ]</div>
          <textarea id="editor" spellcheck="false" placeholder="Write or load Python code..."></textarea>
          <div id="completions"></div>
          <div id="diag-bar"></div>
          <div id="output">[Output]</div>
        </div>
        <div id="graph-panel">
          <div id="search-wrap">
            <input id="search" placeholder="Search nodes...">
            <div id="search-results"></div>
          </div>
          <canvas id="c"></canvas>
        </div>
      </div>
    </div>

    <div id="section-data" class="section-panel hidden">
      <div class="section-head">
        <div><h2>Data</h2><div class="section-desc">Every file imported into the master knowledge graph. Deleting a file removes its sentences, its edges, and any node left with no remaining source.</div></div>
        <button id="reset-graph-btn" class="btn-danger" style="display:none">Reset entire graph</button>
      </div>
      <div class="section-body">
        <table class="data-table">
          <thead><tr><th>File</th><th></th></tr></thead>
          <tbody id="data-table-body"></tbody>
        </table>
      </div>
    </div>

    <div id="section-environment" class="section-panel hidden"></div>
    <div id="section-product" class="section-panel hidden"></div>
    <div id="section-channel" class="section-panel hidden"></div>
    <div id="section-team" class="section-panel hidden"></div>
    <div id="section-change" class="section-panel hidden"></div>
    <div id="section-plan" class="section-panel hidden"></div>

    <div id="section-notifications" class="section-panel hidden">
      <div class="section-head">
        <div><h2>Notifications</h2><div class="section-desc">Automatic feed of platform activity — created/removed environments, products, channels, teams, change requests and plans.</div></div>
      </div>
      <div class="section-body" id="notif-list"></div>
    </div>

  </div>
</div>

<div id="node-modal" class="modal">
  <div class="modal-content">
    <span class="close" onclick="closeModal()">&times;</span>
    <h3 id="modal-title">Node Details</h3>
    <table class="modal-table" id="modal-info"></table>
    <h4 class="modal-h">CONNECTED EDGES</h4>
    <table class="modal-table" id="modal-edges"></table>
    <h4 class="modal-h">SOURCE ARTICLE</h4>
    <div class="article-box" id="modal-article"></div>
  </div>
</div>

<div id="audit-modal" class="modal">
  <div class="modal-content">
    <span class="close" onclick="document.getElementById('audit-modal').style.display='none'">&times;</span>
    <h3>Audit Log</h3>
    <table id="audit-table"><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead>
    <tbody id="audit-body"></tbody></table>
  </div>
</div>

<script>
let graphData = null, currentFile = null, currentUri = 'inmemory://editor_buffer.py';
const canvas = document.getElementById('c'), ctx = canvas.getContext('2d');
let panX = 0, panY = 0, zoom = 1;
let dragNode = null, isPan = false, lastMouse = {};
let clickCandidate = null;
const CLICK_THRESH = 3;

function resize(){
  canvas.width = canvas.parentElement.clientWidth;
  canvas.height = canvas.parentElement.clientHeight;
  draw();
}
window.onresize = resize; resize();

let currentRole = null;
fetch('/api/whoami').then(r=>r.json()).then(me=>{
  if(!me.user){ window.location.href = '/login'; return; }
  currentRole = me.role;
  document.getElementById('whoami').textContent = me.user + ' (' + me.role + ')';
  if(me.role === 'admin'){
    document.getElementById('audit-btn').style.display = 'inline-block';
    document.getElementById('reset-graph-btn').style.display = 'inline-block';
  }
  if(me.role === 'trial'){
    fetch('/api/trial/status').then(r=>r.json()).then(t=>{
      const badge = document.getElementById('trial-badge');
      if(t.active === false){
        badge.textContent = 'TRIAL EXPIRED';
      } else {
        badge.textContent = 'TRIAL — ' + t.days_left + ' day(s) left';
      }
      badge.style.display = 'inline-block';
    });
  }
});

document.getElementById('reset-graph-btn').onclick = () => {
  if(!confirm('This permanently deletes every imported file and the entire knowledge graph. Continue?')) return;
  fetch('/api/graph/reset', {method:'POST'}).then(r=>r.json()).then(()=>{
    loadDataTable(); loadFiles(); loadMaster();
  });
};

/* ---- Section navigation (Apollo-style Reference sidebar) ---- */
const PLATFORM_SECTIONS = {
  environment: {
    label: 'Environments',
    desc: 'Where this software is deployed — mirrors Apollo\u2019s Namespaces &amp; Environments panel.',
    fields: [
      {key:'default_channel', label:'Default Channel', placeholder:'stable'},
      {key:'status', label:'Health', placeholder:'healthy'}
    ]
  },
  product: {
    label: 'Products & Releases',
    desc: 'Registered products and the version currently released to each.',
    fields: [
      {key:'version', label:'Version', placeholder:'1.4.2'},
      {key:'channel', label:'Channel', placeholder:'stable'}
    ]
  },
  channel: {
    label: 'Release Channels',
    desc: 'The promotion sequence a release travels through (e.g. develop \u2192 staging \u2192 stable).',
    fields: [
      {key:'order', label:'Order', placeholder:'1'}
    ]
  },
  team: {
    label: 'Teams & Permissions',
    desc: 'Role-based access control — Administrator manages settings, Viewer is read-only.',
    fields: [
      {key:'role', label:'Role', placeholder:'Administrator / Viewer'}
    ]
  },
  change: {
    label: 'Change Management',
    desc: 'Tracked change requests awaiting or holding approval.',
    fields: [
      {key:'requester', label:'Requester', placeholder:'name'},
      {key:'approver', label:'Approver', placeholder:'name'},
      {key:'status', label:'Status', placeholder:'pending / approved / rejected'}
    ]
  },
  plan: {
    label: 'Upgrades & Plans',
    desc: 'Upgrade plans and the constraints that must hold while they run.',
    fields: [
      {key:'constraint', label:'Constraint', placeholder:'e.g. max 1 environment at a time'},
      {key:'status', label:'Status', placeholder:'scheduled / running / complete'}
    ]
  }
};

function switchSection(name){
  document.querySelectorAll('.nav-item').forEach(el=>{
    el.classList.toggle('active', el.dataset.section === name);
  });
  document.querySelectorAll('.section-panel').forEach(el=>{
    el.classList.toggle('hidden', el.id !== 'section-' + name);
  });
  if(name === 'data') loadDataTable();
  else if(name === 'notifications') loadNotifications();
  else if(PLATFORM_SECTIONS[name]) loadPlatformSection(name);
}

function renderPlatformSection(name){
  const cfg = PLATFORM_SECTIONS[name];
  const extraInputs = cfg.fields.map(f =>
    `<div class="f-group"><label>${f.label}</label><input id="pf-${name}-${f.key}" placeholder="${f.placeholder||''}"></div>`
  ).join('');
  const extraCols = cfg.fields.map(f => `<th>${f.label}</th>`).join('');
  const isAdmin = currentRole === 'admin';
  return `
    <div class="section-head"><div><h2>${cfg.label}</h2><div class="section-desc">${cfg.desc}</div></div></div>
    <div class="section-body">
      <div class="platform-form">
        <div class="f-group"><label>Name</label><input id="pf-${name}-title" placeholder="Name"></div>
        ${extraInputs}
        <button class="btn-add" onclick="createPlatformItem('${name}')">Add</button>
      </div>
      <table class="data-table">
        <thead><tr><th>Name</th>${extraCols}<th>Created</th><th></th></tr></thead>
        <tbody id="platform-table-${name}"></tbody>
      </table>
    </div>`;
}

function loadPlatformSection(name){
  const container = document.getElementById('section-' + name);
  if(!container.dataset.built){
    container.innerHTML = renderPlatformSection(name);
    container.dataset.built = '1';
  }
  fetch('/api/platform?category=' + name).then(r=>r.json()).then(items=>{
    const cfg = PLATFORM_SECTIONS[name];
    const body = document.getElementById('platform-table-' + name);
    const isAdmin = currentRole === 'admin';
    if(!items.length){
      body.innerHTML = `<tr><td colspan="${cfg.fields.length+3}" class="empty-row">No entries yet.</td></tr>`;
      return;
    }
    body.innerHTML = items.map(it => {
      const cols = cfg.fields.map(f => `<td>${(it.fields && it.fields[f.key]) || ''}</td>`).join('');
      const delBtn = isAdmin ? `<button class="btn-danger" onclick="deletePlatformItem('${name}','${it.id}')">Delete</button>` : '';
      return `<tr><td>${it.title}</td>${cols}<td class="mono">${it.created_at||''}</td><td>${delBtn}</td></tr>`;
    }).join('');
  });
}

function createPlatformItem(name){
  const cfg = PLATFORM_SECTIONS[name];
  const title = document.getElementById(`pf-${name}-title`).value.trim();
  if(!title){ alert('Name is required'); return; }
  const fields = {};
  cfg.fields.forEach(f => {
    fields[f.key] = document.getElementById(`pf-${name}-${f.key}`).value.trim();
  });
  fetch('/api/platform/create', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({category:name, title, fields})
  }).then(r=>r.json()).then(d=>{
    if(d.error){ alert(d.error); return; }
    document.getElementById(`pf-${name}-title`).value = '';
    cfg.fields.forEach(f => { document.getElementById(`pf-${name}-${f.key}`).value = ''; });
    loadPlatformSection(name);
  });
}

function deletePlatformItem(name, id){
  if(!confirm('Delete this entry?')) return;
  fetch('/api/platform/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id})
  }).then(r=>r.json()).then(()=> loadPlatformSection(name));
}

function loadDataTable(){
  fetch('/api/files').then(r=>r.json()).then(fs=>{
    const isAdmin = currentRole === 'admin';
    const body = document.getElementById('data-table-body');
    if(!fs.length){
      body.innerHTML = '<tr><td colspan="2" class="empty-row">No files imported yet.</td></tr>';
      return;
    }
    body.innerHTML = fs.map(f => {
      const delBtn = isAdmin ? `<button class="btn-danger" onclick="deleteDataFile('${f}')">Delete</button>` : '';
      return `<tr><td>${f}</td><td>${delBtn}</td></tr>`;
    }).join('');
  });
}

function deleteDataFile(name){
  if(!confirm(`Delete "${name}" and everything it contributed to the graph?`)) return;
  fetch('/api/file/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({name})
  }).then(r=>r.json()).then(d=>{
    if(d.error){ alert(d.error); return; }
    loadDataTable(); loadFiles(); loadMaster();
  });
}

function loadNotifications(){
  fetch('/api/notifications').then(r=>r.json()).then(rows=>{
    const list = document.getElementById('notif-list');
    if(!rows.length){
      list.innerHTML = '<div class="empty-row">No activity yet.</div>';
      return;
    }
    list.innerHTML = rows.map(n =>
      `<div class="notif-item"><span class="notif-ts mono">${n.created_at}</span>${n.message}</div>`
    ).join('');
  });
}

document.getElementById('logout-btn').onclick = () => {
  fetch('/api/logout', {method:'POST'}).then(()=> window.location.href = '/login');
};

document.getElementById('audit-btn').onclick = () => {
  fetch('/api/audit').then(r=>r.json()).then(rows=>{
    document.getElementById('audit-body').innerHTML = rows.map(r=>
      `<tr><td>${r.ts}</td><td>${r.user||''}</td><td>${r.action||''}</td><td>${(r.detail||'').slice(0,80)}</td><td>${r.ip||''}</td></tr>`
    ).join('');
    document.getElementById('audit-modal').style.display = 'block';
  });
};

function loadFiles(){
  fetch('/api/files').then(r=>r.json()).then(fs=>{
    document.getElementById('files').innerHTML = fs.map(f=>
      `<div class="file" onclick="loadFile('${f}')">${f}</div>`
    ).join('');
  });
}
loadFiles();

function loadFile(name){
  fetch('/api/file?name='+encodeURIComponent(name)).then(r=>r.json()).then(d=>{
    if(d.error) alert(d.error);
    else{
      document.getElementById('editor').value = d.content;
      currentFile = name;
      currentUri = d.uri || currentUri;
      runDiagnostics();
    }
  });
}

document.getElementById('import-btn').onclick = ()=> document.getElementById('file-input').click();
document.getElementById('file-input').onchange = function(){
  for(let f of this.files){
    let fd = new FormData(); fd.append('file', f);
    fetch('/api/import', {method:'POST', body:fd})
      .then(r=>r.json()).then(d=>{ loadFiles(); loadMaster(); });
  }
};

function loadMaster(){
  fetch('/api/master').then(r=>r.json()).then(d=>{
    graphData = d;
    draw();
    document.getElementById('stats').textContent =
      `Nodes: ${d.nodes.length}  Edges: ${d.edges.length}`;
  });
}
loadMaster();
document.getElementById('graph-refresh').onclick = loadMaster;

const communityColors = [
  '#ff6b6b','#4ecdc4','#ffe66d','#a06cd5','#6abf69','#ff8c42','#45b7d1','#f9ca24',
  '#e056a0','#7f8c8d','#2ecc71','#9b59b6','#f39c12','#1abc9c','#e74c3c','#3498db',
  '#c0392b','#16a085','#d35400','#8e44ad'
];

function draw(){
  ctx.clearRect(0,0,canvas.width,canvas.height);
  if(!graphData) return;
  ctx.save();
  ctx.translate(panX, panY);
  ctx.scale(zoom, zoom);

  (graphData.edges||[]).forEach(e=>{
    let src = graphData.nodes.find(n=>n.id===e.source);
    let tgt = graphData.nodes.find(n=>n.id===e.target);
    if(!src||!tgt) return;
    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = 'rgba(255,255,255,0.2)';
    ctx.lineWidth = Math.min(e.weight*0.8, 3);
    ctx.stroke();
  });

  const searchTerm = document.getElementById('search').value.trim().toLowerCase();
  (graphData.nodes||[]).forEach(n=>{
    ctx.beginPath();
    let s = n.size||10, x = n.x||100, y = n.y||100;
    if(n.shape==='square'){
      ctx.rect(x-s/2, y-s/2, s, s);
    } else if(n.shape==='triangle'){
      ctx.moveTo(x, y-s/2);
      ctx.lineTo(x+s/2, y+s/2);
      ctx.lineTo(x-s/2, y+s/2);
      ctx.closePath();
    } else {
      ctx.arc(x, y, s/2, 0, Math.PI*2);
    }
    let color = n.color;
    if(n.community>=0){
      color = communityColors[n.community % communityColors.length];
    }
    ctx.fillStyle = color;
    ctx.fill();
    if(searchTerm && n.label.toLowerCase().includes(searchTerm)){
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 3;
      ctx.stroke();
    }
    ctx.fillStyle = '#fff';
    ctx.font = `${Math.max(8, s/2.5)}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText(n.label, x, y - s/2 - 4);
  });

  ctx.restore();
}

canvas.onmousedown = e => {
  if(!graphData) return;
  const rect = canvas.getBoundingClientRect();
  const mx = (e.clientX - rect.left - panX) / zoom;
  const my = (e.clientY - rect.top - panY) / zoom;
  const node = graphData.nodes.find(n=>{
    const dx = n.x - mx, dy = n.y - my;
    return Math.sqrt(dx*dx+dy*dy) < (n.size||10);
  });
  if(node){
    clickCandidate = { node, startX: e.clientX, startY: e.clientY };
    dragNode = null;
    isPan = false;
  } else {
    isPan = true;
    lastMouse = { x: e.clientX, y: e.clientY };
  }
};

canvas.onmousemove = e => {
  if(dragNode){
    const rect = canvas.getBoundingClientRect();
    dragNode.x = (e.clientX - rect.left - panX) / zoom;
    dragNode.y = (e.clientY - rect.top - panY) / zoom;
    draw();
  } else if(isPan){
    panX += e.clientX - lastMouse.x;
    panY += e.clientY - lastMouse.y;
    lastMouse = { x: e.clientX, y: e.clientY };
    draw();
  } else if(clickCandidate){
    const dx = e.clientX - clickCandidate.startX;
    const dy = e.clientY - clickCandidate.startY;
    if(Math.sqrt(dx*dx+dy*dy) > CLICK_THRESH){
      dragNode = clickCandidate.node;
      clickCandidate = null;
    }
  }
};

canvas.onmouseup = e => {
  if(clickCandidate){
    openNodeDetail(clickCandidate.node);
    clickCandidate = null;
  }
  dragNode = null;
  isPan = false;
};

canvas.onwheel = e => {
  e.preventDefault();
  zoom *= e.deltaY < 0 ? 1.1 : 0.9;
  draw();
};

const searchInput = document.getElementById('search');
const searchResults = document.getElementById('search-results');
let searchTimeout;

searchInput.addEventListener('input', () => {
  draw();
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(doSearch, 200);
});

function doSearch(){
  const term = searchInput.value.trim();
  if(!term || !graphData){
    searchResults.style.display = 'none';
    return;
  }
  fetch('/api/search?q='+encodeURIComponent(term))
    .then(r=>r.json())
    .then(nodes=>{
      if(!nodes.length){
        searchResults.style.display = 'none';
        return;
      }
      searchResults.innerHTML = nodes.map(n=>
        `<div class="search-item" data-id="${n.id}">${n.label} (comm:${n.community})</div>`
      ).join('');
      searchResults.style.display = 'block';
      document.querySelectorAll('.search-item').forEach(el=>{
        el.onclick = ()=>{
          const nid = el.dataset.id;
          const node = graphData.nodes.find(n=>n.id===nid);
          if(node) openNodeDetail(node);
          searchResults.style.display = 'none';
        };
      });
    });
}

document.addEventListener('click', e => {
  if(!e.target.closest('#search-wrap')){
    searchResults.style.display = 'none';
  }
});

function openNodeDetail(node){
  document.getElementById('modal-title').textContent = 'Node: ' + node.label;
  const infoTable = document.getElementById('modal-info');
  const edgesTable = document.getElementById('modal-edges');
  const articleDiv = document.getElementById('modal-article');
  infoTable.innerHTML = `
    <tr><th>Label</th><td>${node.label}</td></tr>
    <tr><th>Community</th><td>${node.community>=0?node.community:'N/A'}</td></tr>
    <tr><th>Betweenness</th><td>${node.betweenness.toFixed(4)}</td></tr>
    <tr><th>Size</th><td>${node.size.toFixed(1)}</td></tr>
    <tr><th>Source File</th><td>${node.source_file||'N/A'}</td></tr>
  `;
  fetch('/api/node?id=' + encodeURIComponent(node.id))
    .then(r=>r.json())
    .then(detail=>{
      const connected = detail.edges || [];
      edgesTable.innerHTML = connected.length ?
        connected.map(e=>{
          const otherId = e.source===node.id ? e.target : e.source;
          const otherNode = graphData.nodes.find(n=>n.id===otherId);
          const otherLabel = otherNode ? otherNode.label : otherId;
          return `<tr><td>${otherLabel}</td><td>weight: ${e.weight.toFixed(1)}</td><td>${e.source_file||''}</td></tr>`;
        }).join('') :
        '<tr><td colspan="3">No edges</td></tr>';
      articleDiv.textContent = detail.article || 'No article information.';
    })
    .catch(()=>{
      edgesTable.innerHTML = '<tr><td colspan="3">Error loading edges.</td></tr>';
      articleDiv.textContent = 'Error loading article.';
    });
  document.getElementById('node-modal').style.display = 'block';
}

function closeModal(){
  document.getElementById('node-modal').style.display = 'none';
}
window.onclick = function(event){
  if(event.target === document.getElementById('node-modal')) closeModal();
  if(event.target === document.getElementById('audit-modal')) document.getElementById('audit-modal').style.display='none';
};

document.getElementById('run-btn').onclick = ()=>{
  fetch('/api/run',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({code: document.getElementById('editor').value})
  })
  .then(r=>r.json())
  .then(d=> document.getElementById('output').textContent = d.output || d.error);
};

document.getElementById('nb-btn').onclick = ()=>{
  let nb;
  try{ nb = JSON.parse(document.getElementById('editor').value); }
  catch(e){ alert('Invalid JSON notebook'); return; }
  fetch('/api/notebook',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(nb)
  })
  .then(r=>r.json())
  .then(d=> document.getElementById('output').textContent = d.output || d.error);
};

/* ---- Code Intelligence: diagnostics + completions ---- */
const editor = document.getElementById('editor');
const diagBar = document.getElementById('diag-bar');
const compBox = document.getElementById('completions');
let diagTimeout, compTimeout;

function cursorLineCol(){
  const pos = editor.selectionStart;
  const before = editor.value.slice(0, pos);
  const lines = before.split('\n');
  return { line: lines.length - 1, column: lines[lines.length-1].length };
}

function runDiagnostics(){
  fetch('/api/lsp/diagnostics', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({source: editor.value, uri: currentUri})
  }).then(r=>r.json()).then(d=>{
    const diags = d.diagnostics || [];
    diagBar.innerHTML = diags.length ?
      diags.map(x=>`<div class="diag-item ${x.severity===1?'err':''}">Line ${x.line}: ${x.message}</div>`).join('') :
      `<div class="diag-item" style="color:#4ec9b0">No issues found (${d.engine})</div>`;
  }).catch(()=>{});
}

editor.addEventListener('input', ()=>{
  clearTimeout(diagTimeout);
  diagTimeout = setTimeout(runDiagnostics, 500);
  clearTimeout(compTimeout);
  compTimeout = setTimeout(requestCompletions, 300);
});

function requestCompletions(){
  const {line, column} = cursorLineCol();
  fetch('/api/lsp/complete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({source: editor.value, uri: currentUri, line, column})
  }).then(r=>r.json()).then(d=>{
    const items = d.completions || [];
    if(!items.length){ compBox.style.display='none'; return; }
    compBox.innerHTML = items.map(c=>`<div class="comp-item">${c.label} <span style="color:#888">${c.detail||''}</span></div>`).join('');
    compBox.style.display = 'block';
    const rect = editor.getBoundingClientRect();
    compBox.style.left = (rect.left + 20) + 'px';
    compBox.style.top = (rect.top + 40) + 'px';
    compBox.style.width = '260px';
    document.querySelectorAll('.comp-item').forEach((el, i)=>{
      el.onclick = ()=>{
        insertCompletion(items[i].label);
        compBox.style.display = 'none';
      };
    });
  }).catch(()=>{ compBox.style.display='none'; });
}

function insertCompletion(word){
  const pos = editor.selectionStart;
  const before = editor.value.slice(0, pos);
  const after = editor.value.slice(pos);
  const m = before.match(/([A-Za-z_][A-Za-z0-9_]*)$/);
  const start = m ? pos - m[1].length : pos;
  editor.value = editor.value.slice(0, start) + word + after;
  editor.selectionStart = editor.selectionEnd = start + word.length;
  editor.focus();
}

document.addEventListener('click', e=>{
  if(!e.target.closest('#completions') && e.target !== editor) compBox.style.display = 'none';
});

runDiagnostics();
</script>
</body>
</html>"""


# ======================================================================
#  CLI ENTRYPOINT  (pattern derived from __main__.py)
# ======================================================================
def add_arguments(parser):
    parser.description = f"{APP_NAME} — {APP_TAGLINE}"
    parser.add_argument("--host", default=HOST, help="Bind address (default: %(default)s)")
    parser.add_argument("--port", type=int, default=PORT, help="Bind port (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                         help="Increase log verbosity")


def print_banner(host, port):
    engines = []
    engines.append("pyflakes" if HAVE_PYFLAKES else "stdlib-compile")
    engines.append("jedi" if HAVE_JEDI else "keyword-fallback")
    engines.append("pluggy hooks" if HAVE_PLUGGY else "no plugin manager")
    print("=" * 72)
    print(f"  {APP_NAME} v{APP_VERSION} — {APP_TAGLINE}")
    print("=" * 72)
    print(f"  URL:              http://{host}:{port}")
    print(f"  Diagnostics via:  {engines[0]}")
    print(f"  Completions via:  {engines[1]}")
    print(f"  Plugin system:    {engines[2]}")
    print(f"  Data store:       {DB_PATH.resolve()}")
    print("-" * 72)
    print("  Optional upgrade:  pip install pyflakes jedi pluggy")
    print("=" * 72)


def main():
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args()

    print_banner(args.host, args.port)
    server = socketserver.ThreadingTCPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Oblivion Orbital] Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
