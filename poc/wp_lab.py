#!/usr/bin/env python3
"""Shared helpers for the WordPress Interactivity API `data-wp-bind--href` lab PoCs.

LAB ONLY. Every script in this repository is meant to run against a WordPress
instance that *you* started on loopback. Nothing here contacts a third party.

Configuration (environment variables, all optional):

    WP_BASE          default: http://127.0.0.1:18080
    WP_CONTAINER     docker container running WordPress (default: wpsite)
    WP_AUTHOR_USER   default: author
    WP_AUTHOR_PASS   default: labauthorpass
    WP_ADMIN_USER    default: bindadmin
    WP_ADMIN_PASS    default: labadminpass
    CHROME_PATH      explicit Chromium/Chrome binary; otherwise auto-detected
    WP_OUT_DIR       output directory (default: <repo>/out)
"""
from __future__ import annotations

import glob
import html
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

DEFAULT_BASE = "http://127.0.0.1:18080"
DEFAULT_CONTAINER = "wpsite"
DEFAULT_AUTHOR = ("author", "labauthorpass")
DEFAULT_ADMIN = ("bindadmin", "labadminpass")

#: Absolute path of the plugin file the escalation overwrites, inside the container.
PLUGIN_PATH = "/var/www/html/wp-content/plugins/hello.php"

_NONCE_PATTERNS = (
    re.compile(r'createNonceMiddleware\(\s*"([a-f0-9]{8,})"'),
    re.compile(r'wpApiSettings\s*=\s*\{[^}]*?"nonce"\s*:\s*"([a-f0-9]{8,})"'),
    re.compile(r'"nonce"\s*:\s*"([a-f0-9]{8,})"'),
)


@dataclass
class Session:
    name: str
    session: requests.Session
    nonce: str | None = None
    uid: int | None = None
    roles: list[str] | None = None
    display: str | None = None

    def rest(self, method: str, route: str, data=None, timeout: int = 30):
        """Call the WordPress REST API through the `?rest_route=` entry point."""
        url = cfg().base + "/?rest_route=" + route
        headers = {"Accept": "application/json"}
        if self.nonce:
            headers["X-WP-Nonce"] = self.nonce
        body = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data)
        return self.session.request(method, url, data=body, headers=headers, timeout=timeout)

    def get(self, path: str, **kw):
        return self.session.get(cfg().base + path, **kw)


@dataclass
class Config:
    base: str
    container: str
    author_user: str
    author_pass: str
    admin_user: str
    admin_pass: str
    chrome: str | None
    out_dir: Path


_CFG: Config | None = None


def cfg() -> Config:
    global _CFG
    if _CFG is None:
        _CFG = Config(
            base=os.environ.get("WP_BASE", DEFAULT_BASE).rstrip("/"),
            container=os.environ.get("WP_CONTAINER", DEFAULT_CONTAINER),
            author_user=os.environ.get("WP_AUTHOR_USER", DEFAULT_AUTHOR[0]),
            author_pass=os.environ.get("WP_AUTHOR_PASS", DEFAULT_AUTHOR[1]),
            admin_user=os.environ.get("WP_ADMIN_USER", DEFAULT_ADMIN[0]),
            admin_pass=os.environ.get("WP_ADMIN_PASS", DEFAULT_ADMIN[1]),
            chrome=os.environ.get("CHROME_PATH") or find_chrome(),
            out_dir=Path(os.environ.get("WP_OUT_DIR", REPO / "out")),
        )
        _CFG.out_dir.mkdir(parents=True, exist_ok=True)
    return _CFG


def find_chrome() -> str | None:
    """Return an explicit Chrome/Chromium binary, or None to let Playwright decide."""
    explicit = os.environ.get("CHROME_PATH")
    if explicit and Path(explicit).exists():
        return explicit
    patterns = [
        str(Path.home() / ".cache/ms-playwright/chromium-*/chrome-linux*/chrome"),
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
    ]
    for pattern in patterns:
        for candidate in sorted(glob.glob(pattern), reverse=True):
            if Path(candidate).exists():
                return candidate
    return None


def login(user: str, password: str, name: str = "") -> Session:
    """Cookie + nonce login (application passwords are disabled in the lab)."""
    c = cfg()
    s = requests.Session()
    s.headers.update({"User-Agent": "wp-bind-href-poc/1.0 (lab)"})
    s.get(c.base + "/wp-login.php", timeout=30)  # sets wordpress_test_cookie
    s.post(
        c.base + "/wp-login.php",
        data={
            "log": user,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": c.base + "/wp-admin/",
            "testcookie": "1",
        },
        timeout=30,
    )
    admin_page = s.get(c.base + "/wp-admin/", timeout=30)
    nonce = None
    for pattern in _NONCE_PATTERNS:
        match = pattern.search(admin_page.text)
        if match:
            nonce = match.group(1)
            break
    uid = roles = display = None
    try:
        me = s.get(
            c.base + "/?rest_route=/wp/v2/users/me&context=edit",
            headers={"X-WP-Nonce": nonce} if nonce else {},
            timeout=30,
        ).json()
        if isinstance(me, dict):
            uid, roles = me.get("id"), me.get("roles")
            display = me.get("name") or me.get("slug")
    except Exception:
        pass
    return Session(name or user, s, nonce, uid, roles, display)


def login_author() -> Session:
    c = cfg()
    return login(c.author_user, c.author_pass, "author")


def login_admin() -> Session:
    c = cfg()
    return login(c.admin_user, c.admin_pass, "admin")


def island(ctx: dict, body: str, namespace: str = "pwn") -> str:
    encoded = html.escape(json.dumps(ctx), quote=True)
    return (
        f'<div id="isl" data-wp-interactive="{namespace}" '
        f'data-wp-context="{encoded}">{body}</div>'
    )


def accordion(inner: str) -> str:
    """Wrap content in a core/accordion block so the front end loads Interactivity."""
    return (
        '<!-- wp:accordion -->\n<div role="group" class="wp-block-accordion">'
        '<!-- wp:accordion-item -->\n<div class="wp-block-accordion-item">'
        '<!-- wp:accordion-heading -->\n<h3 class="wp-block-accordion-heading">'
        '<button type="button" class="wp-block-accordion-heading__toggle">'
        '<span class="wp-block-accordion-heading__toggle-title">Click me</span>'
        "</button></h3>\n"
        "<!-- /wp:accordion-heading -->\n\n<!-- wp:accordion-panel -->\n"
        '<div role="region" class="wp-block-accordion-panel">'
        "<!-- wp:html -->\n" + inner + "\n<!-- /wp:html --></div>\n"
        "<!-- /wp:accordion-panel --></div>\n"
        "<!-- /wp:accordion-item --></div>\n<!-- /wp:accordion -->"
    )


def publish(session: Session, title: str, content: str) -> tuple[dict, int]:
    response = session.rest(
        "POST",
        "/wp/v2/posts",
        {"title": title, "status": "publish", "content": content},
    )
    try:
        payload = response.json()
    except ValueError:
        payload = {"raw": response.text[:500]}
    return payload, response.status_code


# --- docker helpers (optional; skipped cleanly when docker is unavailable) ---

def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def docker_ready() -> bool:
    c = cfg()
    if not shutil.which("docker"):
        return False
    return _run(["docker", "inspect", "-f", "{{.State.Running}}", c.container]) == "true"


def docker_exec(*command: str, root: bool = True) -> str:
    c = cfg()
    args = ["docker", "exec"]
    if root:
        args += ["-u", "0"]
    args += [c.container, *command]
    return _run(args)


def remote_sha256(path: str = PLUGIN_PATH) -> str | None:
    if not docker_ready():
        return None
    out = docker_exec("sha256sum", path)
    return out.split()[0] if out else None


def remote_read(path: str = PLUGIN_PATH) -> str | None:
    if not docker_ready():
        return None
    return docker_exec("cat", path)


def restore_file(local_backup: Path, path: str = PLUGIN_PATH) -> bool | None:
    """Copy a local backup into the container. Returns None if docker is absent."""
    if not docker_ready():
        return None
    c = cfg()
    _run(["docker", "cp", str(local_backup), f"{c.container}:{path}"])
    return True


def delete_post(session: Session, post_id: int) -> bool:
    # `rest()` builds "/?rest_route=" + route, so the second query parameter is "&".
    response = session.rest("DELETE", f"/wp/v2/posts/{post_id}&force=true")
    if response.status_code in (200, 204):
        return True
    try:
        return bool(response.json().get("deleted"))
    except ValueError:
        return False


def write_json(name: str, payload: dict) -> Path:
    path = cfg().out_dir / name
    path.write_text(json.dumps(payload, indent=2) + "\n")
    return path


def banner(text: str) -> None:
    print(f"\n=== {text} ===")
