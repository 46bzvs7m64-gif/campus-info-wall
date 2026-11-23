# -*- coding: utf-8 -*-
"""校园信息墙 · 后端（零依赖：只用 Python 标准库 + SQLite）

启动：
    python server/app.py            # 默认 http://127.0.0.1:8099
    python server/app.py 9000       # 换端口

它同时做两件事：
1. 把上一级目录的静态站点当静态资源发出去（index.html / img/）；
2. 提供一套 JSON API，让「账号、我发的内容、我的收藏」真正存在服务器上，
   换一台设备登录同一个账号，看到的是同一份数据。

API
    POST /api/register  {nick, sid, pass}      -> {token, user}
    POST /api/login     {nick, pass}           -> {token, user}
    GET  /api/me        (Authorization)        -> {user, items, favs}
    PUT  /api/me/items  (Authorization) {items} -> {ok, count}
    PUT  /api/me/favs   (Authorization) {favs}  -> {ok}
    GET  /api/feed                             -> {items: [所有用户发布的内容]}
    GET  /api/ping                             -> {ok:true, users:n, items:n}

安全说明（写在明面上，面试被问也不虚）：
- 密码用 pbkdf2-hmac-sha256 + 每用户随机 salt 存哈希，不存明文；
- 会话是随机 token，存在 sessions 表里，带过期时间；
- 这是「能跑通的小后端」，不是生产级：没做限流、没做 CSRF、没做邮箱验证。
"""
import json
import os
import re
import sqlite3
import sys
import hashlib
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 静态站点目录：仓库里在子目录；如果 index.html 就在上层（部署包那种结构），直接用 ROOT
SITE = os.path.join(ROOT, "项目01_校园信息墙")
if not os.path.isfile(os.path.join(SITE, "index.html")):
    SITE = ROOT
DB_PATH = os.path.join(ROOT, "server", "data.sqlite3")
TOKEN_TTL = 60 * 60 * 24 * 30  # 30 天

MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".webmanifest": "application/manifest+json",
}


# ---------------------------------------------------------------- 数据库
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, nick TEXT UNIQUE NOT NULL, sid TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL, pwhash TEXT NOT NULL, role TEXT DEFAULT 'user',
            created_at INTEGER NOT NULL, data TEXT DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, json TEXT NOT NULL,
            created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, uid TEXT NOT NULL, expires INTEGER NOT NULL);
        """)


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 120000).hex()


def uid(prefix="u_"):
    return prefix + secrets.token_hex(5)


# ---------------------------------------------------------------- 业务
def register(nick, sid, pw):
    nick, sid, pw = (nick or "").strip(), (sid or "").strip(), pw or ""
    if len(nick) < 2:
        return 400, {"error": "昵称至少 2 个字"}
    if not re.match(r"^\d{8,12}$", sid):
        return 400, {"error": "学号要填 8-12 位数字"}
    if len(pw) < 6:
        return 400, {"error": "密码至少 6 位"}
    salt = secrets.token_hex(16)
    with db() as c:
        if c.execute("SELECT 1 FROM users WHERE nick=?", (nick,)).fetchone():
            return 409, {"error": "这个昵称已经有人用了"}
        if c.execute("SELECT 1 FROM users WHERE sid=?", (sid,)).fetchone():
            return 409, {"error": "这个学号已经注册过，直接登录就行"}
        u = uid()
        c.execute("INSERT INTO users(id,nick,sid,salt,pwhash,role,created_at) VALUES(?,?,?,?,?,?,?)",
                  (u, nick, sid, salt, hash_pw(pw, salt), "user", int(time.time() * 1000)))
        tok = secrets.token_urlsafe(24)
        c.execute("INSERT INTO sessions(token,uid,expires) VALUES(?,?,?)",
                  (tok, u, int(time.time()) + TOKEN_TTL))
    return 200, {"token": tok, "user": {"id": u, "nick": nick, "sid": sid, "role": "user"}}


def login(nick, pw):
    nick = (nick or "").strip()
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE nick=? OR sid=?", (nick, nick)).fetchone()
    if not row or hash_pw(pw or "", row["salt"]) != row["pwhash"]:
        return 401, {"error": "昵称/学号或密码不对"}
    tok = secrets.token_urlsafe(24)
    with db() as c:
        c.execute("INSERT INTO sessions(token,uid,expires) VALUES(?,?,?)",
                  (tok, row["id"], int(time.time()) + TOKEN_TTL))
    return 200, {"token": tok, "user": {"id": row["id"], "nick": row["nick"], "sid": row["sid"], "role": row["role"]}}


def user_by_token(token):
    if not token:
        return None
    with db() as c:
        s = c.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
        if not s or s["expires"] < int(time.time()):
            return None
        return c.execute("SELECT * FROM users WHERE id=?", (s["uid"],)).fetchone()


def my_state(uid_):
    with db() as c:
        u = c.execute("SELECT id,nick,sid,role,data FROM users WHERE id=?", (uid_,)).fetchone()
        rows = c.execute("SELECT json FROM items WHERE owner=? ORDER BY created_at DESC", (uid_,)).fetchall()
    if not u:
        return None
    meta = json.loads(u["data"] or "{}")
    return {
        "user": {"id": u["id"], "nick": u["nick"], "sid": u["sid"], "role": u["role"]},
        "items": [json.loads(r["json"]) for r in rows],
        "favs": meta.get("favs", []),
    }


def save_my(uid_, items=None, favs=None):
    with db() as c:
        if items is not None:
            c.execute("DELETE FROM items WHERE owner=?", (uid_,))
            for it in items[:200]:
                c.execute("INSERT OR REPLACE INTO items(id,owner,json,created_at) VALUES(?,?,?,?)",
                          (it.get("id") or uid("it_"), uid_, json.dumps(it, ensure_ascii=False),
                           int(it.get("createdAt") or time.time() * 1000)))
        if favs is not None:
            row = c.execute("SELECT data FROM users WHERE id=?", (uid_,)).fetchone()
            meta = json.loads((row["data"] if row else "{}") or "{}")
            meta["favs"] = favs[:500]
            c.execute("UPDATE users SET data=? WHERE id=?", (json.dumps(meta, ensure_ascii=False), uid_))
    return True


def feed():
    with db() as c:
        rows = c.execute("SELECT i.json FROM items i JOIN users u ON u.id=i.owner "
                         "ORDER BY i.created_at DESC LIMIT 500").fetchall()
        n_users = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        n_items = c.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    return {"items": [json.loads(r["json"]) for r in rows], "users": n_users, "items_total": n_items}


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "CampusWall/2.0"

    def log_message(self, fmt, *a):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % a))

    # ---- 工具
    def _send(self, code, payload, ctype="application/json; charset=utf-8", extra=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def _token(self):
        h = self.headers.get("Authorization") or ""
        return h[7:].strip() if h.lower().startswith("bearer ") else ""

    # ---- 路由
    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        path = unquote(urlparse(self.path).path)
        if path == "/api/ping":
            f = feed()
            return self._send(200, {"ok": True, "users": f["users"], "items": f["items_total"]})
        if path == "/api/feed":
            return self._send(200, feed())
        if path == "/api/me":
            u = user_by_token(self._token())
            if not u:
                return self._send(401, {"error": "登录已过期，请重新登录"})
            return self._send(200, my_state(u["id"]))
        return self._static(path)

    def do_POST(self):
        path = urlparse(self.path).path
        b = self._body()
        if path == "/api/register":
            return self._send(*register(b.get("nick"), b.get("sid"), b.get("pass")))
        if path == "/api/login":
            return self._send(*login(b.get("nick"), b.get("pass")))
        return self._send(404, {"error": "no route"})

    def do_PUT(self):
        path = urlparse(self.path).path
        u = user_by_token(self._token())
        if not u:
            return self._send(401, {"error": "登录已过期，请重新登录"})
        b = self._body()
        if path == "/api/me/items":
            save_my(u["id"], items=b.get("items") or [])
            return self._send(200, {"ok": True})
        if path == "/api/me/favs":
            save_my(u["id"], favs=b.get("favs") or [])
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "no route"})

    # ---- 静态文件
    def _static(self, path):
        if path in ("/", ""):
            path = "/index.html"
        fp = os.path.abspath(os.path.join(SITE, path.lstrip("/")))
        if not fp.startswith(SITE) or not os.path.isfile(fp):
            return self._send(404, {"error": "not found"})
        ext = os.path.splitext(fp)[1].lower()
        with open(fp, "rb") as f:
            data = f.read()
        self._send(200, data, MIME.get(ext, "application/octet-stream"))


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    init_db()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("校园信息墙服务已启动： http://127.0.0.1:%d/" % port)
    print("数据文件：%s" % DB_PATH)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")


if __name__ == "__main__":
    main()
