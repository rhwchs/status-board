#!/usr/bin/env python3
"""Puts an access code on a built page, so a published copy is not readable by just anyone.

    ACCESS_CODE=... python3 lock_page.py site/index.html

The page is ENCRYPTED (AES-256, key made from the code with PBKDF2 at 600,000 rounds) and replaced by a small page that asks
for the code and decrypts it in the visitor's own browser. What is published is ciphertext, so the dashboard cannot be read
without the code, not just hidden. Link with the code built in:  https://YOUR-LINK/#the-code   (the part after # is never
sent to any server). Needs the `openssl` command, which Macs, Linux and GitHub's servers all have.
Limits: everyone shares one code, there is no way to remove one person, and anyone who has the code can pass it on.
"""
import base64
import os
import subprocess
import sys
import tempfile

ITER = 600_000

LOCK_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Status"><title>Status board (private)</title>
<style>
  :root{--bg:#0e1116;--panel:#171c24;--line:#2a323d;--text:#e8edf3;--dim:#93a0b2;--link:#6cb2ff}
  @media (prefers-color-scheme: light){:root{--bg:#f3f5f8;--panel:#fff;--line:#d9dee6;--text:#14181f;--dim:#5b6676;--link:#0b64c0}}
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);
  font:16px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:16px}
  main{width:100%;max-width:380px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px}
  h1{font-size:20px;margin:0 0 6px}p{margin:0 0 14px;color:var(--dim);font-size:14px}
  input[type=text]{width:100%;font:inherit;font-size:18px;padding:12px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--text)}
  button{width:100%;margin-top:12px;font:inherit;font-weight:700;padding:12px;border:0;border-radius:10px;background:var(--link);color:#fff}
  label{display:block;margin-top:10px;font-size:14px;color:var(--dim)}#msg{margin-top:10px;font-size:14px;min-height:1.2em;color:#e5584d}
</style></head><body><main>
<h1>Status board</h1><p>This page is private. Enter the access code you were given.</p>
<form id="f"><input id="c" type="text" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="Access code" aria-label="Access code">
<label><input id="r" type="checkbox" checked> Remember on this device</label><button id="b">Open</button></form><div id="msg"></div>
<script>
const BLOB = "__BLOB__", ITER = __ITER__;
const msg = t => { document.getElementById('msg').textContent = t || ''; };
async function unlock(code) {
  const raw = Uint8Array.from(atob(BLOB), ch => ch.charCodeAt(0));
  const salt = raw.slice(8, 16), ct = raw.slice(16);
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(code), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256'}, km, 384));
  const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-CBC', false, ['decrypt']);
  const txt = new TextDecoder().decode(await crypto.subtle.decrypt({name: 'AES-CBC', iv: bits.slice(32, 48)}, key, ct));
  if (!txt.startsWith('OKAY1')) throw new Error('bad code');
  return txt.slice(6);
}
async function go(code, remember, fromAuto) {
  if (!code) return;
  msg(fromAuto ? '' : 'Checking…');
  try {
    const html = await unlock(code.trim());
    try { remember ? localStorage.setItem('sb_code', code.trim()) : localStorage.removeItem('sb_code'); } catch (e) {}
    document.open(); document.write(html); document.close();
  } catch (e) {
    try { localStorage.removeItem('sb_code'); } catch (e2) {}
    msg(window.crypto && crypto.subtle ? 'That code did not work.' : 'This browser cannot open private pages (it needs https).');
  }
}
document.getElementById('f').onsubmit = e => { e.preventDefault(); go(document.getElementById('c').value, document.getElementById('r').checked); };
(function () {
  let c = decodeURIComponent((location.hash || '').slice(1)), fromLink = !!c;
  if (!c) { try { c = localStorage.getItem('sb_code') || ''; } catch (e) {} }
  if (c) go(c, true, true).then(() => { if (fromLink) msg('The code in that link did not work.'); });
})();
</script></main></body></html>
"""


def lock(path, code):
    with open(path, "rb") as f:
        plain = b"OKAY1" + f.read()
    with tempfile.TemporaryDirectory() as d:
        src, dst = os.path.join(d, "p"), os.path.join(d, "c")
        with open(src, "wb") as f:
            f.write(plain)
        env = dict(os.environ, PAGE_LOCK_CODE=code)          # passed by environment so it never shows in a process list
        subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", str(ITER), "-md", "sha256", "-salt",
                        "-pass", "env:PAGE_LOCK_CODE", "-in", src, "-out", dst], check=True, env=env)
        with open(dst, "rb") as f:
            blob = base64.b64encode(f.read()).decode()
    with open(path, "w", encoding="utf-8") as f:
        f.write(LOCK_HTML.replace("__BLOB__", blob).replace("__ITER__", str(ITER)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: ACCESS_CODE=... python3 lock_page.py PAGE.html")
    code = os.environ.get("ACCESS_CODE", "")
    if len(code) < 4:
        sys.exit("ACCESS_CODE must be set and at least 4 characters.")
    lock(sys.argv[1], code)
    print("Locked", sys.argv[1])
