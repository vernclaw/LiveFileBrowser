#!/usr/bin/env python3
"""LiveFileBrowser — password-gated downloads with temporary auth tokens."""
import argparse, json, os, secrets, sys, time, urllib.parse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
PASSFILE = os.path.expanduser("~/.file-browser/passwords.json")
PORT = 8000
BIND = "127.0.0.1"
TOKEN_TTL = 86400  # 1 day
DEPLOY_TS = 1774106558  # cache-bust version — bump on each deploy


# ── Token store ───────────────────────────────────────────────────────────────

_token_store = {}

def _make_token(fn: str) -> str:
    tok = secrets.token_urlsafe(32)
    _token_store[tok] = {"fn": fn, "exp": time.time() + TOKEN_TTL}
    return tok

def _check_token(tok: str):
    e = _token_store.get(tok)
    if e is None: return None
    if time.time() > e["exp"]:
        del _token_store[tok]
        return None
    return e["fn"]

def _purge():
    now = time.time()
    for t in [k for k, v in _token_store.items() if now > v["exp"]]:
        del _token_store[t]


# ── Password store ────────────────────────────────────────────────────────────

def _pw_load():
    if os.path.exists(PASSFILE):
        with open(PASSFILE) as f:
            return json.load(f)
    return {}

def _is_protected(fn: str) -> bool:
    return fn in _pw_load()

def _check_pw(fn: str, pw: str) -> bool:
    return _pw_load().get(fn) == pw

def _pw_set(fn: str, pw: str):
    p = _pw_load()
    p[fn] = pw
    os.makedirs(os.path.dirname(PASSFILE), exist_ok=True)
    with open(PASSFILE, "w") as f:
        json.dump(p, f, indent=2)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _mtime(path: str) -> str:
    return datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M")

def _size(n: int) -> str:
    if n >= 1048576: return f"{n/1048576:.1f} MB"
    if n >= 1024: return f"{n/1024:.1f} KB"
    return f"{n} B"

def _safe_path(base: str, rel: str) -> str | None:
    """Return absolute path if rel is inside base, else None."""
    abs_base = os.path.abspath(base)
    abs_path = os.path.abspath(os.path.join(base, rel))
    if os.path.commonpath([abs_path, abs_base]) != abs_base:
        return None
    return abs_path


# ── HTML builder ────────────────────────────────────────────────────────────

def html_escape(s: str) -> str:
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def build_page(rows_html: str, crumb: str = "", error: str = "") -> str:
    _purge()
    err = f"<div class='error-banner'>{html_escape(error)}</div>" if error else ""
    return (
        "<!DOCTYPE html><html lang='en'>"
        "<head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>File Browser</title>"
        "<link rel='icon' href='/favicon.ico' type='image/x-icon'>"
        f"<link rel='stylesheet' href='/static/style.css?t={DEPLOY_TS}'>"
        "</head>"
        "<body>"
        "<div class='card'>"
        "<div class='header'>"
        "<h1>&#128193; File Browser</h1>"
        f"<div class='crumbs'>{crumb}</div>"
        "</div>"
        f"{err}"
        "<table><thead><tr>"
        "<th style='width:48px'></th>"
        "<th>Name</th>"
        "<th style='width:130px'>Modified</th>"
        "<th style='width:80px'>Size</th>"
        "<th style='width:120px'>Action</th>"
        "</tr></thead><tbody>\n" + rows_html + "</tbody></table>"
        f"<div class='footer'>LiveFileBrowser</div>"
        "</div>"
        "<div class='modal' id='pwdModal'>"
        "<div class='modal-box'>"
        "<h3 id='pwdTitle'>&#128274; Password Required</h3>"
        "<input type='password' id='pwdInput' placeholder='Enter password' onkeydown=\"pwdKeydown(event)\">"
        "<div style='display:flex;gap:8px;margin-top:4px'>"
        "<button class='btn-ghost' onclick='closeModal()'>Cancel</button>"
        "<button class='btn-primary' onclick='submitPwd()'>Verify</button>"
        "</div>"
        "<div class='info' id='pwdInfo'></div>"
        "</div></div>"
        f"<script src='/static/script.js?t={DEPLOY_TS}'></script>"
        "</body></html>"
    )

def make_rows(base_dir: str, entries: list, subdir: str = "") -> str:
    """Build table rows HTML. subdir is relative path from FILES_DIR (e.g. '' or 'sub/')."""
    pw = _pw_load()
    rows = ""
    # Sort: folders first, then alphabetically
    folders = sorted([n for n in entries if os.path.isdir(os.path.join(base_dir, n))], key=str.lower)
    files   = sorted([n for n in entries if os.path.isdir(os.path.join(base_dir, n)) == False], key=str.lower)
    for name in folders + files:
        rel_path = name if not subdir else subdir.rstrip("/") + "/" + name
        full = os.path.join(base_dir, name)
        is_dir = os.path.isdir(full)
        href = urllib.parse.quote(rel_path, safe="/")
        icon = "&#128194;" if is_dir else (
            "&#128221;" if name.endswith(".md") else
            "&#128203;" if name.endswith(".json") else
            "&#128215;" if name.endswith(".pdf") else "&#128196;")
        mtime = _mtime(full)
        sz = "-" if is_dir else _size(os.path.getsize(full))
        protected = rel_path in pw

        if is_dir:
            onclick = f"folderClick('{href}/')"
            display_name = name + "/"
            lock = ""
            action = f"<a href='/b/{href}/' class='btn'>&#128194; Open</a>"
            row_class = "folder-row"
            name_cell = f"<span class='name folder-name'>{html_escape(display_name)}</span>"
        elif protected:
            lock = "&#128274;"
            onclick = f"promptPwd('{href}','{html_escape(rel_path)}')"
            display_name = name
            action = f"<button class='btn btn-lock' onclick=\"{onclick}\">&#128274;</button>"
            row_class = "protected"
            name_cell = f"<span class='name'>{html_escape(display_name)}</span>{lock}"
        else:
            lock = ""
            display_name = name
            action = (
                f"<button class='btn btn-secondary' onclick='copyDirectLink(\"{href}\")'>&#128203;</button>"
                f"<a href='/f/{href}' class='btn' download>&#11015;</a>"
            )
            row_class = ""
            name_cell = f"<span class='name'>{html_escape(display_name)}</span>{lock}"

        rows += (
            f"<tr class='{row_class}'>" +
            f"<td style='text-align:center'>{icon}</td>" +
            f"<td>{name_cell}</td>" +
            f"<td style='color:#636e72;font-size:13px;white-space:nowrap'>{mtime}</td>" +
            f"<td style='color:#636e72;font-size:13px;white-space:nowrap'>{sz}</td>" +
            f"<td style='white-space:nowrap;text-align:right'>{action}</td>" +
            f"</tr>\n"
        )
    return rows


# ── HTTP Handler ────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        # Parse path and query
        if "?" in self.path:
            path, query = self.path.split("?", 1)
        else:
            path, query = self.path, ""
        params = {}
        for kv in query.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[urllib.parse.unquote(k)] = urllib.parse.unquote(v)

        # Route
        if path == "/":
            self._list("")
        elif path.startswith("/static/"):
            self._static(path)
        elif path == "/favicon.ico":
            self._favicon()
        elif path.startswith("/s/"):
            self._success(path, params)
        elif path.rstrip("/").startswith("/b/"):
            sub = path[3:].lstrip("/")  # e.g. "subdir" or "subdir/nested"
            self._browse(sub)
        elif path.startswith("/f/"):
            self._file(path[3:])
        elif path.startswith("/d/"):
            self._download(path[3:], params)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path.startswith("/v/"):
            self._verify(self.path[3:])
        else:
            self.send_error(404)

    def _list(self, subdir: str):
        """List root directory. subdir is ignored (always '')."""
        base = FILES_DIR
        try:
            entries = sorted(os.listdir(base))
        except PermissionError:
            return self.send_error(403)
        crumb = "<a href='/'>Home</a>"
        body = build_page(make_rows(base, entries, ""), crumb).encode()
        self._html(body)

    def _browse(self, subdir: str):
        """Browse subdirectory. subdir e.g. 'other' or 'other/nested'."""
        if subdir:
            base = os.path.join(FILES_DIR, subdir)
            rel_prefix = subdir.rstrip("/") + "/"
            crumb = "<a href='/'>Home</a>"
            for part in subdir.split("/"):
                crumb += f" <span style='color:rgba(255,255,255,.4)'>&#8250;</span> <a href='/b/{rel_prefix}'>{html_escape(part)}</a>"
        else:
            return self._list("")
        if not os.path.isdir(base):
            return self.send_error(404)
        if _safe_path(FILES_DIR, subdir) is None:
            return self.send_error(403)
        try:
            entries = sorted(os.listdir(base))
        except PermissionError:
            return self.send_error(403)
        body = build_page(make_rows(base, entries, rel_prefix), crumb).encode()
        self._html(body)

    def _file(self, rel_path: str):
        """Serve a file directly (no auth needed for non-protected)."""
        name = urllib.parse.unquote(rel_path)
        safe = _safe_path(FILES_DIR, name)
        if safe is None or not os.path.isfile(safe):
            return self.send_error(404)
        if _is_protected(name):
            return self.send_error(403)
        try:
            data = open(safe, "rb").read()
        except PermissionError:
            return self.send_error(403)
        self._send_file(name, data)

    def _download(self, rel_path: str, params: dict):
        """Download with ?auth=token or password-required check."""
        name = urllib.parse.unquote(rel_path)
        safe = _safe_path(FILES_DIR, name)
        if safe is None or not os.path.isfile(safe):
            return self.send_error(404)

        # Token check
        tok = params.get("auth")
        if tok:
            valid_fn = _check_token(tok)
            if valid_fn != name:
                return self.send_error(403, "Invalid or expired token")
            try:
                data = open(safe, "rb").read()
            except PermissionError:
                return self.send_error(403)
            return self._send_file(name, data)

        # No token — must be unprotected
        if _is_protected(name):
            return self.send_error(403, "Password required")
        try:
            data = open(safe, "rb").read()
        except PermissionError:
            return self.send_error(403)
        return self._send_file(name, data)

    def _favicon(self):
        ico_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "favicon.ico")
        if not os.path.isfile(ico_path):
            return self.send_error(404)
        try:
            data = open(ico_path, "rb").read()
        except PermissionError:
            return self.send_error(403)
        self.send_response(200)
        self.send_header("Content-type", "image/x-icon")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    def _static(self, path: str):
        """Serve static files from /static/ directory."""
        # path like /static/style.css?t=123 → serve static/style.css
        filename = path[8:].split("?")[0]  # strip "/static/" and "?t=..."
        if ".." in filename:
            return self.send_error(403)
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
        file_path = os.path.join(static_dir, filename)
        if not os.path.isfile(file_path):
            return self.send_error(404)
        try:
            data = open(file_path, "rb").read()
        except PermissionError:
            return self.send_error(403)
        if filename.endswith(".css"):
            ct = "text/css"
        elif filename.endswith(".js"):
            ct = "application/javascript"
        else:
            ct = "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-type", ct + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    def _success(self, path: str, params: dict):
        """Show success page with download and copy link buttons."""
        # path like /s/filename?auth=token
        name = urllib.parse.unquote(path[3:])  # strip "/s/"
        tok = params.get("auth", "")
        valid_fn = _check_token(tok)
        if valid_fn is None or valid_fn != name:
            return self.send_error(403, "Invalid or expired link")
        dl_url = f"/d/{urllib.parse.quote(name, safe='/')}?auth={tok}"
        body = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Download Ready</title>"
            "<link rel='icon' href='/favicon.ico' type='image/x-icon'>"
            "<link rel='stylesheet' href='/static/style.css?t=" + str(DEPLOY_TS) + "'>"
            "</head><body>"
            "<div class='card' style='max-width:600px;margin:40px auto;text-align:center;padding:32px'>"
            "<h2 style='font-size:22px;color:#2d3436;margin-bottom:8px'>&#9989; Password verified</h2>"
            "<p style='font-size:14px;color:#636e72;margin-bottom:24px'>Your download link is valid for <strong>24 hours</strong>.</p>"
            "<div style='display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-bottom:20px'>"
            "<a class='btn' href='" + dl_url + "' download>&#11015; Download Now</a>"
            "<button class='btn btn-secondary' onclick='copyLink()'>&#128203; Copy Link</button>"
            "</div>"
            "<p style='font-size:13px;color:#636e72;margin-bottom:6px;text-align:left'>Full download link:</p>"
            "<div id='dlUrl' style='background:#f8f9ff;border-radius:8px;padding:14px;word-break:break-all;font-size:13px;color:#667eea;margin-bottom:16px;text-align:left;font-family:monospace;border:1px solid #e0e0e0'></div>"
            "<p style='font-size:12px;color:#b2bec3;margin-top:16px'>Bookmark or paste the link within 24 hours — no account needed.</p>"
            "</div>"
            "<script src='/static/success.js?t=" + str(DEPLOY_TS) + "'></script>"
            "<script>document.getElementById('dlUrl').textContent=window.location.origin+'" + dl_url + "';</script>"
            "</body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _verify(self, rel_path: str):
        """Verify password and return token URL."""
        name = urllib.parse.unquote(rel_path)
        safe = _safe_path(FILES_DIR, name)
        if safe is None or not os.path.isfile(safe):
            return self.send_error(404)

        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl).decode()
        pw = ""
        for part in body.split("&"):
            if part.startswith("password="):
                pw = urllib.parse.unquote(part[9:])

        if not _check_pw(name, pw):
            entries = sorted(os.listdir(FILES_DIR))
            rows = make_rows(FILES_DIR, entries, "")
            page = build_page(rows, "", "Incorrect password")
            data = page.encode()
            self.send_response(401)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # Password correct — generate token and show link
        tok = _make_token(name)
        dl_url = f"/d/{urllib.parse.quote(name, safe='/')}?auth={tok}"

        # Detect fetch request via X-Requested-With header
        is_fetch = self.headers.get("X-Requested-With") == "fetch"

        if is_fetch:
            # Return token as plain text for fetch
            body = tok.encode()
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Normal browser request: full HTML page
        body = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Download Ready</title>"
            "<style>"
            "*{box-sizing:border-box;margin:0;padding:0}"
            "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:16px;background:#f0f2f5}"
            ".card{background:#fff;border-radius:14px;padding:24px;max-width:480px;margin:40px auto;box-shadow:0 4px 24px rgba(0,0,0,.1);text-align:center}"
            "h2{font-size:20px;color:#2d3436;margin-bottom:8px}"
            "p{font-size:14px;color:#636e72;margin-bottom:20px;line-height:1.5}"
            ".link-box{background:#f8f9ff;border-radius:8px;padding:14px;word-break:break-all;font-size:13px;color:#667eea;margin:12px 0;text-align:left}"
            ".btn{display:inline-flex;align-items:center;gap:8px;background:#667eea;color:#fff;border:none;padding:12px 20px;border-radius:8px;cursor:pointer;font-size:14px;text-decoration:none;margin:4px}"
            ".btn:hover{background:#5a71d6}"
            ".btn-secondary{background:#f1f3f6;color:#636e72}"
            ".btn-secondary:hover{background:#e2e6ea}"
            ".hint{font-size:12px;color:#b2bec3;margin-top:16px;line-height:1.5}"
            ".btn-row{display:flex;gap:8px;flex-wrap:wrap;justify-content:center}"
            "@media(max-width:480px){.card{margin:16px 8px;padding:20px 16px}.btn{width:100%;justify-content:center}}"
            "</style></head><body>"
            "<div class='card'>"
            "<h2>&#9989; Password verified</h2>"
            "<p>Your download link is valid for <strong>24 hours</strong>.</p>"
            "<div class='btn-row'>"
            "<a class='btn' href='" + dl_url + "' download>&#11015; Download Now</a>"
            "<button class='btn btn-secondary' onclick='copyLink()'>&#128203; Copy Link</button>"
            "</div>"
            "<div class='link-box' id='dlUrl'></div>"
            "<p class='hint'>Bookmark or paste the link within 24 hours — no account needed.</p>"
            "</div>"
            "<script>"
            "var u=window.location.origin+'" + dl_url + "';"
            "document.getElementById('dlUrl').textContent=u;"
            "function copyLink(){navigator.clipboard?navigator.clipboard.writeText(u):prompt('Copy:',u);}"
            "<\\/script></body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, data: bytes):
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, name: str, data: bytes):
        # Always serve as attachment (no browser rendering)
        filename = name.split("/")[-1]  # use basename for Content-Disposition
        enc_name = urllib.parse.quote(filename, safe="")
        self.send_response(200)
        self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{enc_name}")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[{self.log_date_time_string()}] {args[0]}\n")


# ── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--bind", default=BIND)
    args = ap.parse_args()

    if len(sys.argv) >= 3 and sys.argv[1] == "protect":
        pwd = sys.argv[3] if len(sys.argv) > 3 else input("Password: ").strip()
        _pw_set(sys.argv[2], pwd)
        print(f"Password set for {sys.argv[2]}")
    elif sys.argv[1:2] == ["list-passwords"]:
        pw = _pw_load()
        print(f"Store: {PASSFILE}")
        for k in pw:
            print(f"  {k}")
    elif len(sys.argv) >= 3 and sys.argv[1] == "unprotect":
        p = _pw_load()
        fn = sys.argv[2]
        if fn in p:
            del p[fn]
            with open(PASSFILE, "w") as f:
                json.dump(p, f, indent=2)
            print(f"Removed protection from {fn}")
        else:
            print(f"{fn} is not protected")
    else:
        srv = HTTPServer((args.bind, args.port), Handler)
        sys.stderr.write(f"Serving {FILES_DIR} on http://{args.bind}:{args.port}/\n")
        srv.serve_forever()
