#!/usr/bin/env python3
"""
ShadowMap — Passive / Manual External Recon Toolkit
----------------------------------------------------
Replicates a 5-step passive recon methodology:
  1. DNS resolution
  2. Subdomain enumeration via crt.sh (Certificate Transparency logs)
  3. Consolidation of discovered subdomains
  4. HTTP status code enumeration across discovered hosts
  5. Directory/path fuzzing against a single in-scope host

You just paste a URL or a bare domain and it runs the whole scan
automatically. Results are shown as tables and auto-saved to JSON.

IMPORTANT: Only run this against domains/hosts you are authorized to test.
This script performs read-only, unauthenticated requests only (no bruteforce
of credentials, no exploitation).
"""

import json
import os
import random
import shutil
import socket
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
from collections import defaultdict


# --------------------------------------------------------------------------
# VIEH Group logo (embedded as base64 PNG so the HTML report stays a single
# self-contained file). Shown in the header of the HTML report.
# --------------------------------------------------------------------------

LOGO_B64 = "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"


# --------------------------------------------------------------------------
# Terminal colors / styling
# --------------------------------------------------------------------------

class C:
    """ANSI color codes. Falls back to no color if the terminal doesn't
    support it (best-effort check)."""
    _enabled = sys.stdout.isatty()

    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""

    RED = "\033[31m" if _enabled else ""
    GREEN = "\033[32m" if _enabled else ""
    YELLOW = "\033[33m" if _enabled else ""
    BLUE = "\033[34m" if _enabled else ""
    MAGENTA = "\033[35m" if _enabled else ""
    CYAN = "\033[36m" if _enabled else ""
    GREY = "\033[90m" if _enabled else ""


def term_width(default=70):
    try:
        return shutil.get_terminal_size((default, 20)).columns
    except Exception:
        return default


def hr(char="-"):
    print(C.GREY + char * min(term_width(), 78) + C.RESET)


# --------------------------------------------------------------------------
# ShadowMap ASCII banner (animated "decrypt" reveal)
# --------------------------------------------------------------------------

# Hand-built 5-row pixel font for a clean block-style logo.
_FONT = {
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "H": ["#   #", "#   #", "#####", "#   #", "#   #"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "W": ["#   #", "#   #", "# # #", "## ##", "#   #"],
    "M": ["#   #", "## ##", "# # #", "#   #", "#   #"],
    "P": ["#### ", "#   #", "#### ", "#    ", "#    "],
}


def _render_word(word, gap=1):
    """Build a list of 5 text rows spelling `word` using the pixel font."""
    rows = ["" for _ in range(5)]
    for i, letter in enumerate(word.upper()):
        glyph = _FONT.get(letter, ["     "] * 5)
        for r in range(5):
            rows[r] += glyph[r] + (" " * gap)
    return rows


SHADOWMAP_ART = _render_word("SHADOWMAP")


def _print_static_banner():
    """Fallback: print the logo instantly, no animation (used for
    non-interactive terminals or piped output)."""
    for row in SHADOWMAP_ART:
        print(C.CYAN + C.BOLD + row + C.RESET)


def _animate_decrypt(lines, frames=10, delay=0.035):
    """
    'Matrix decrypt' reveal: each non-space character starts scrambled and
    progressively resolves into the real character over a few frames.
    """
    charset = "!@#$%^&*<>/\\|=+~01?"
    height = len(lines)

    # Reserve vertical space, then redraw it in place each frame.
    for _ in range(height):
        print()

    for frame in range(frames):
        sys.stdout.write(f"\033[{height}A")  # cursor up `height` lines
        scramble_chance = 1 - (frame + 1) / frames
        for line in lines:
            rendered = "".join(
                random.choice(charset) if ch != " " and random.random() < scramble_chance else ch
                for ch in line
            )
            sys.stdout.write(C.CYAN + C.BOLD + rendered + C.RESET + " " * 4 + "\n")
        sys.stdout.flush()
        time.sleep(delay)


def _typewriter(text, delay=0.015, style=""):
    for ch in text:
        sys.stdout.write(style + ch + (C.RESET if style else ""))
        sys.stdout.flush()
        time.sleep(delay)
    print()


def banner(animate=True):
    if animate and sys.stdout.isatty():
        try:
            _animate_decrypt(SHADOWMAP_ART)
        except (KeyboardInterrupt, Exception):
            _print_static_banner()
        print()
        _typewriter("  Passive / Unauthenticated external recon toolkit", style=C.GREY)
        _typewriter("  \u26a0  Only test hosts you are explicitly authorized to assess.", style=C.YELLOW)
    else:
        _print_static_banner()
        print(C.GREY + "  Passive / Unauthenticated external recon toolkit" + C.RESET)
        print(C.YELLOW + "  \u26a0  Only test hosts you are explicitly authorized to assess." + C.RESET)
    hr("=")


def section(title, step_no=None, total_steps=5):
    hr()
    tag = f"[{step_no}/{total_steps}] " if step_no else ""
    print(f"{C.BOLD}{C.BLUE}{tag}{title}{C.RESET}")
    hr()


def status_color(code):
    if code == 0:
        return C.GREY
    if 200 <= code < 300:
        return C.GREEN
    if code in (301, 302, 303, 307, 308):
        return C.YELLOW
    if code in (401, 403):
        return C.MAGENTA
    if 400 <= code < 500:
        return C.YELLOW
    if code >= 500:
        return C.RED
    return C.RESET


def fmt_status(code):
    return f"{status_color(code)}{code:<3}{C.RESET}"


def status_note(code):
    if code == 0:
        return "no response / inactive"
    if 200 <= code < 300:
        return "live"
    if code in (301, 302, 303, 307, 308):
        return "redirect"
    if code == 401:
        return "auth required"
    if code == 403:
        return "blocked / forbidden"
    if code == 404:
        return "not found"
    if code >= 500:
        return "server error"
    return "-"


def make_table(headers, rows):
    """
    Render a plain ASCII table (no external deps). `rows` is a list of
    lists/tuples of already-stringified cell values, same length as headers.
    ANSI color codes in cell values are ignored for width calculation so
    columns still line up even when text is colored.
    """
    import re
    ansi_re = re.compile(r"\033\[[0-9;]*m")

    def visible_len(s):
        return len(ansi_re.sub("", str(s)))

    widths = [visible_len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], visible_len(cell))

    def pad(cell, width):
        extra = width - visible_len(cell)
        return str(cell) + " " * max(extra, 0)

    def sep(left, mid, right, fill="─"):
        return left + mid.join(fill * (w + 2) for w in widths) + right

    lines = [sep("┌", "┬", "┐")]
    header_line = "│ " + " │ ".join(
        f"{C.BOLD}{pad(h, widths[i])}{C.RESET}" for i, h in enumerate(headers)
    ) + " │"
    lines.append(header_line)
    lines.append(sep("├", "┼", "┤"))
    for row in rows:
        line = "│ " + " │ ".join(pad(cell, widths[i]) for i, cell in enumerate(row)) + " │"
        lines.append(line)
    lines.append(sep("└", "┴", "┘"))
    return "\n".join(lines)


def resolve_ip(hostname, timeout=3):
    """Best-effort single-IP resolution for table display. Returns the
    first IPv4/IPv6 address found, or 'N/A' if resolution fails."""
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(hostname, None)
        return infos[0][4][0] if infos else "N/A"
    except Exception:
        return "N/A"
    finally:
        socket.setdefaulttimeout(None)


# --------------------------------------------------------------------------
# Progress bar
# --------------------------------------------------------------------------

def progress_bar(current, total, start_time, label="", bar_len=30):
    """
    Render a single-line, in-place progress bar:
      [########------------]  40%  (4/10)  ETA 6s   checking: api.example.com
    Call once per completed item; ends with a newline when current == total.
    """
    total = max(total, 1)
    fraction = min(current / total, 1.0)
    filled = int(bar_len * fraction)
    bar = "#" * filled + "-" * (bar_len - filled)

    elapsed = time.time() - start_time
    rate = current / elapsed if elapsed > 0 else 0
    remaining = (total - current) / rate if rate > 0 else 0
    eta = f"{remaining:4.0f}s" if current < total else "  0s"

    line = (
        f"\r  {C.CYAN}[{bar}]{C.RESET} "
        f"{C.BOLD}{fraction*100:5.1f}%{C.RESET} "
        f"({current}/{total})  ETA {eta}   {C.GREY}{label:<40}{C.RESET}"
    )
    # Pad/truncate to terminal width so leftover characters from a longer
    # previous line don't linger on screen.
    width = term_width()
    line = line[: width + 20]  # allow room for ANSI codes
    sys.stdout.write(line)
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\n")


# --------------------------------------------------------------------------
# Input helpers
# --------------------------------------------------------------------------

def ask(prompt, default=None):
    suffix = f" {C.GREY}[{default}]{C.RESET}" if default is not None else ""
    val = input(f"{C.CYAN}?{C.RESET} {prompt}{suffix}: ").strip()
    return val if val else default


def ask_yes_no(prompt, default="n"):
    val = ask(prompt + " (y/n)", default).lower()
    return val.startswith("y")


def normalize_target(raw):
    """
    Accepts either a bare domain ("app.example.com"), a domain with no
    scheme but a path ("app.example.com/foo"), or a full URL
    ("https://app.example.com/foo?bar=1") and returns a dict with:
      - scheme: "http" or "https" (defaults to "https" if none given)
      - host:   just the hostname, no port/path/query
      - path:   leftover path+query (without leading "/"), or "" if none
    """
    raw = raw.strip()
    candidate = raw if "://" in raw else f"https://{raw}"

    parsed = urllib.parse.urlparse(candidate)
    host = parsed.hostname or ""
    scheme = parsed.scheme if "://" in raw else "https"

    path = parsed.path.lstrip("/")
    if parsed.query:
        path = f"{path}?{parsed.query}" if path else f"?{parsed.query}"

    return {"scheme": scheme, "host": host, "path": path, "raw": raw}


def ask_target(prompt):
    while True:
        raw = ask(prompt)
        if not raw:
            return None
        info = normalize_target(raw)
        if not info["host"]:
            print(f"  {C.RED}Could not extract a hostname from '{raw}'.{C.RESET} "
                  f"Try 'example.com' or 'https://example.com/path'.")
            continue
        if info["host"] != raw:
            note = f"  {C.GREEN}Parsed ->{C.RESET} host: {C.BOLD}{info['host']}{C.RESET}, scheme: {info['scheme']}"
            if info["path"]:
                note += f", path: /{info['path']}"
            print(note)
        return info


def http_get(url, timeout=8, follow_redirects=True, headers=None):
    """
    Minimal HTTP GET using urllib. Returns (status_code, final_url, body_bytes)
    or (0, None, b"") on any connection-level failure.
    """
    headers = headers or {"User-Agent": "manual-recon-script/1.0"}

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = (
        urllib.request.build_opener()
        if follow_redirects
        else urllib.request.build_opener(NoRedirect)
    )

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, resp.geturl(), body
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b""
        return e.code, e.geturl() if hasattr(e, "geturl") else url, body
    except Exception:
        return 0, None, b""


# --------------------------------------------------------------------------
# Step 1 - DNS Resolution
# --------------------------------------------------------------------------

def step1_dns_resolution(hostname):
    section(f"Resolving {hostname}", 1)
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = sorted({info[4][0] for info in infos})
        for ip in ips:
            print(f"  {hostname} {C.GREY}->{C.RESET} {C.GREEN}{ip}{C.RESET}")
        if not ips:
            print(f"  {C.YELLOW}No addresses returned.{C.RESET}")
        return ips
    except socket.gaierror as e:
        print(f"  {C.RED}Resolution failed: {e}{C.RESET}")
        return []


# --------------------------------------------------------------------------
# Step 2 - Subdomain enumeration via crt.sh
# --------------------------------------------------------------------------

def _source_crtsh(root_domain, timeout):
    """crt.sh (Certificate Transparency log search, sectigo-backed)."""
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    status, _, body = http_get(url, timeout=timeout)
    if status != 200 or not body:
        return None, f"status={status}"

    try:
        data = json.loads(body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None, "invalid JSON"

    names = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.splitlines():
            line = line.strip().lower()
            if line.startswith("*."):
                line = line[2:]
            if line.endswith(root_domain):
                names.add(line)
    return names, None


def _source_certspotter(root_domain, timeout):
    """Cert Spotter public API (SSLMate) - another CT-log aggregator,
    independent infrastructure from crt.sh, so it often stays up when
    crt.sh is down."""
    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={root_domain}&include_subdomains=true&expand=dns_names"
    )
    status, _, body = http_get(url, timeout=timeout)
    if status != 200 or not body:
        return None, f"status={status}"

    try:
        data = json.loads(body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None, "invalid JSON"

    names = set()
    for entry in data:
        for dns_name in entry.get("dns_names", []):
            line = dns_name.strip().lower()
            if line.startswith("*."):
                line = line[2:]
            if line.endswith(root_domain):
                names.add(line)
    return names, None


def _source_hackertarget(root_domain, timeout):
    """HackerTarget hostsearch - DNS-based passive subdomain lookup
    (different method than CT logs, so it also catches hosts that never
    got a public cert). Rate-limited on the free tier, so failures here
    are expected/normal, not necessarily an outage."""
    url = f"https://api.hackertarget.com/hostsearch/?q={root_domain}"
    status, _, body = http_get(url, timeout=timeout)
    if status != 200 or not body:
        return None, f"status={status}"

    text = body.decode("utf-8", errors="ignore").strip()
    if "error" in text.lower() or "API count exceeded" in text:
        return None, text.splitlines()[0][:80]

    names = set()
    for line in text.splitlines():
        host = line.split(",")[0].strip().lower()
        if host.endswith(root_domain):
            names.add(host)
    return names, None


def step2_crtsh_enum(root_domain, timeout=15):
    """
    Passive subdomain enumeration using multiple independent public
    sources. Queries each source, merges + dedupes the results, and
    reports per-source status so you can see which ones actually
    responded. Any source can fail (down, rate-limited, etc.) without
    stopping the scan - we just proceed with whatever the others found.
    """
    section(f"Passive subdomain enumeration for *.{root_domain}", 2)

    sources = [
        ("crt.sh", _source_crtsh),
        ("Cert Spotter", _source_certspotter),
        ("HackerTarget", _source_hackertarget),
    ]

    all_names = set()
    source_summary = []  # (name, count_or_None, error_or_None)

    for label, fn in sources:
        print(f"  Querying {C.GREY}{label}{C.RESET} ...", end=" ")
        sys.stdout.flush()
        try:
            names, err = fn(root_domain, timeout)
        except Exception as e:
            names, err = None, str(e)[:80]

        if names is None:
            print(f"{C.RED}failed{C.RESET} {C.GREY}({err}){C.RESET}")
            source_summary.append((label, None, err))
        else:
            print(f"{C.GREEN}ok{C.RESET} {C.GREY}({len(names)} names){C.RESET}")
            source_summary.append((label, len(names), None))
            all_names |= names

    all_names.add(root_domain)

    working = [s for s in source_summary if s[1] is not None]
    if not working:
        print(f"\n  {C.RED}All sources failed/unreachable. "
              f"Falling back to just the root domain.{C.RESET}")
    else:
        print(f"\n  {C.GREEN}Merged + de-duplicated: {len(all_names)} unique "
              f"hostnames from {len(working)}/{len(sources)} source(s).{C.RESET}")

    return sorted(all_names)


# --------------------------------------------------------------------------
# Step 3/4 - Consolidate + status-check each discovered host
# --------------------------------------------------------------------------

def step34_status_check(hostnames, scheme="https", timeout=8, delay=0.0):
    """
    Returns a list of dicts: [{"host": ..., "ip": ..., "status": ...}, ...]
    (resolves an IP for each host in addition to the HTTP status code, so
    the final summary table can show both).
    """
    section(f"Status-checking {len(hostnames)} host(s)", "3/4", total_steps=5)
    results = []
    start = time.time()
    interrupted = False
    try:
        for i, host in enumerate(hostnames, start=1):
            ip = resolve_ip(host, timeout=min(timeout, 3))
            url = f"{scheme}://{host}/"
            status, _, _ = http_get(url, timeout=timeout, follow_redirects=False)
            results.append({"host": host, "ip": ip, "status": status})
            progress_bar(i, len(hostnames), start, label=host)
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        interrupted = True
        print(f"\n  {C.YELLOW}Interrupted — showing {len(results)}/{len(hostnames)} results collected so far.{C.RESET}")

    print()
    rows = [
        [str(i + 1), r["host"], r["ip"], fmt_status(r["status"]), status_note(r["status"])]
        for i, r in enumerate(results)
    ]
    print(make_table(["#", "Subdomain", "IP Address", "Status", "Notes"], rows))
    if interrupted:
        raise KeyboardInterrupt  # propagate so main() can stop remaining steps too
    return results


# --------------------------------------------------------------------------
# Step 5 - Directory / path fuzzing against a single in-scope host
# --------------------------------------------------------------------------

DEFAULT_WORDLIST = [
    "robots.txt", ".git", ".env", ".svn", ".htaccess", "wp-config.php",
    "admin", "login", "api", "api/v1", "config", "backup", "sitemap.xml",
    "health", "status", "version", "swagger", "swagger-ui", "graphql",
    "manifest.json", "static", "assets", "auth", "auth/login",
    ".well-known/security.txt",
]


def load_wordlist():
    use_file = ask_yes_no("Load paths from a wordlist file instead of the small built-in default list?", "n")
    if use_file:
        path = ask("Path to wordlist file (one path per line)")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                paths = [line.strip() for line in f if line.strip()]
            print(f"  {C.GREEN}Loaded {len(paths)} paths from {path}{C.RESET}")
            return paths
        except OSError as e:
            print(f"  {C.RED}Could not read file ({e}). Falling back to default list.{C.RESET}")
            return DEFAULT_WORDLIST
    else:
        print(f"  Using built-in default list ({len(DEFAULT_WORDLIST)} paths).")
        return DEFAULT_WORDLIST


def step5_dir_fuzz(base_host, paths, scheme="https", timeout=8, delay=0.0):
    """Returns a list of dicts: [{"path": ..., "status": ...}, ...]"""
    section(f"Fuzzing {len(paths)} path(s) against {scheme}://{base_host}", 5)
    results = []
    start = time.time()
    interrupted = False
    try:
        for i, path in enumerate(paths, start=1):
            url = f"{scheme}://{base_host}/{path.lstrip('/')}"
            status, _, _ = http_get(url, timeout=timeout, follow_redirects=False)
            results.append({"path": path, "status": status})
            progress_bar(i, len(paths), start, label=path)
            if delay:
                time.sleep(delay)
    except KeyboardInterrupt:
        interrupted = True
        print(f"\n  {C.YELLOW}Interrupted — showing {len(results)}/{len(paths)} results collected so far.{C.RESET}")

    print()
    rows = [
        [str(i + 1), r["path"], fmt_status(r["status"]), status_note(r["status"])]
        for i, r in enumerate(results)
    ]
    print(make_table(["#", "Path", "Status", "Notes"], rows))
    if interrupted:
        raise KeyboardInterrupt
    return results


# --------------------------------------------------------------------------
# HTML report generation (modern dark dashboard, single self-contained file)
# --------------------------------------------------------------------------

def _html_status_class(code):
    if code == 0:
        return "st-none"
    if 200 <= code < 300:
        return "st-ok"
    if code in (301, 302, 303, 307, 308):
        return "st-redirect"
    if code in (401, 403):
        return "st-auth"
    if 400 <= code < 500:
        return "st-warn"
    if code >= 500:
        return "st-error"
    return "st-none"


def _esc(s):
    """Minimal HTML-escaping for values interpolated into the report."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def generate_html_report(target, scheme, status_results, fuzz_results, out_path):
    """Write a modern, self-contained dark-theme HTML dashboard summarizing
    the scan results (subdomain table + directory fuzzing table)."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S %Z") or time.strftime("%Y-%m-%d %H:%M:%S")

    total_hosts = len(status_results)
    live_hosts = sum(1 for r in status_results if r["status"] not in (0,))
    total_paths = len(fuzz_results)
    live_paths = sum(1 for r in fuzz_results if 200 <= r["status"] < 300)

    # VIEH Group logo, shown on a light "pill" so the dark lettering stays
    # readable against the dark dashboard background.
    logo_html = (
        f'<div class="brand-logo"><img src="data:image/png;base64,{LOGO_B64}" alt="VIEH Group"></div>'
        if LOGO_B64 and not LOGO_B64.startswith("__") else ""
    )

    def status_rows():
        rows = ""
        for i, r in enumerate(sorted(status_results, key=lambda x: x["host"]), start=1):
            cls = _html_status_class(r["status"])
            rows += f"""
            <tr>
              <td class="num">{i}</td>
              <td class="mono">{_esc(r['host'])}</td>
              <td class="mono">{_esc(r['ip'])}</td>
              <td><span class="badge {cls}">{r['status']}</span></td>
              <td class="note">{_esc(status_note(r['status']))}</td>
            </tr>"""
        return rows

    def fuzz_rows():
        rows = ""
        for i, r in enumerate(fuzz_results, start=1):
            cls = _html_status_class(r["status"])
            rows += f"""
            <tr>
              <td class="num">{i}</td>
              <td class="mono">/{_esc(r['path'])}</td>
              <td><span class="badge {cls}">{r['status']}</span></td>
              <td class="note">{_esc(status_note(r['status']))}</td>
            </tr>"""
        return rows

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShadowMap Report — {_esc(target)}</title>
<style>
  :root {{
    --bg: #0b0f14;
    --panel: #10161d;
    --panel-2: #141c25;
    --border: #223041;
    --text: #dbe6f0;
    --text-dim: #7f92a3;
    --accent: #22d3ee;
    --accent-2: #a78bfa;
    --ok: #34d399;
    --warn: #fbbf24;
    --redirect: #facc15;
    --auth: #c084fc;
    --error: #f87171;
    --none: #64748b;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: radial-gradient(1200px 600px at 10% -10%, #14202b 0%, var(--bg) 60%);
    color: var(--text);
    font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Consolas, monospace;
    padding: 32px 20px 60px;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; }}

  header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
    padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 28px;
  }}
  .brand {{ display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }}
  .brand-logo {{
    background: #ffffff;
    border-radius: 10px;
    padding: 6px 12px;
    display: flex;
    align-items: center;
    box-shadow: 0 0 0 1px var(--border), 0 4px 18px rgba(34, 211, 238, 0.12);
  }}
  .brand-logo img {{ height: 46px; width: auto; display: block; }}
  .logo {{
    font-size: 26px;
    font-weight: 700;
    letter-spacing: 1px;
    background: linear-gradient(90deg, var(--accent), var(--accent-2));
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }}
  .subtitle {{ color: var(--text-dim); font-size: 13px; margin-top: 4px; }}
  .meta {{ text-align: right; color: var(--text-dim); font-size: 12px; }}
  .meta .target {{ color: var(--text); font-size: 15px; font-weight: 600; }}

  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 14px;
    margin-bottom: 32px;
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
  }}
  .card .label {{ color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
  .card .value {{ font-size: 26px; font-weight: 700; margin-top: 6px; }}
  .card.accent .value {{ color: var(--accent); }}
  .card.ok .value {{ color: var(--ok); }}
  .card.warn .value {{ color: var(--warn); }}

  section {{ margin-bottom: 36px; }}
  h2 {{
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--accent);
    margin: 0 0 14px 0;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  h2::before {{ content: ''; width: 6px; height: 6px; background: var(--accent); border-radius: 50%; display: inline-block; }}

  .table-wrap {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  thead th {{
    text-align: left;
    background: var(--panel-2);
    color: var(--text-dim);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 11px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
  }}
  tbody td {{ padding: 10px 16px; border-bottom: 1px solid var(--border); }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: rgba(34, 211, 238, 0.05); }}
  td.num {{ color: var(--text-dim); width: 40px; }}
  td.mono {{ color: var(--text); }}
  td.note {{ color: var(--text-dim); }}

  .badge {{
    display: inline-block;
    min-width: 42px;
    text-align: center;
    padding: 3px 8px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 12px;
    border: 1px solid transparent;
  }}
  .st-ok       {{ color: var(--ok);       background: rgba(52,211,153,0.12);  border-color: rgba(52,211,153,0.35); }}
  .st-redirect {{ color: var(--redirect); background: rgba(250,204,21,0.12);  border-color: rgba(250,204,21,0.35); }}
  .st-auth     {{ color: var(--auth);     background: rgba(192,132,252,0.12); border-color: rgba(192,132,252,0.35); }}
  .st-warn     {{ color: var(--warn);     background: rgba(251,191,36,0.12);  border-color: rgba(251,191,36,0.35); }}
  .st-error    {{ color: var(--error);    background: rgba(248,113,113,0.12); border-color: rgba(248,113,113,0.35); }}
  .st-none     {{ color: var(--none);     background: rgba(100,116,139,0.12); border-color: rgba(100,116,139,0.3); }}

  .empty {{ color: var(--text-dim); font-size: 13px; padding: 20px; text-align: center; }}

  footer {{
    margin-top: 40px;
    padding-top: 18px;
    border-top: 1px solid var(--border);
    color: var(--text-dim);
    font-size: 11px;
    text-align: center;
  }}
  footer .warn-note {{ color: var(--warn); }}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="brand">
      {logo_html}
      <div>
        <div class="logo">ShadowMap</div>
        <div class="subtitle">Passive / Unauthenticated External Recon Report</div>
      </div>
    </div>
    <div class="meta">
      <div class="target">{_esc(scheme)}://{_esc(target)}</div>
      <div>Generated {_esc(timestamp)}</div>
    </div>
  </header>

  <div class="cards">
    <div class="card accent"><div class="label">Hosts Checked</div><div class="value">{total_hosts}</div></div>
    <div class="card ok"><div class="label">Live Hosts</div><div class="value">{live_hosts}</div></div>
    <div class="card accent"><div class="label">Paths Fuzzed</div><div class="value">{total_paths}</div></div>
    <div class="card warn"><div class="label">Live Paths (2xx)</div><div class="value">{live_paths}</div></div>
  </div>

  <section>
    <h2>Subdomain / Host Results</h2>
    <div class="table-wrap">
      {"<table><thead><tr><th>#</th><th>Subdomain</th><th>IP Address</th><th>Status</th><th>Notes</th></tr></thead><tbody>" + status_rows() + "</tbody></table>" if status_results else '<div class="empty">No subdomain/status results collected.</div>'}
    </div>
  </section>

  <section>
    <h2>Directory Fuzzing Results — {_esc(target)}</h2>
    <div class="table-wrap">
      {"<table><thead><tr><th>#</th><th>Path</th><th>Status</th><th>Notes</th></tr></thead><tbody>" + fuzz_rows() + "</tbody></table>" if fuzz_results else '<div class="empty">No fuzzing results collected.</div>'}
    </div>
  </section>

  <footer>
    Generated by ShadowMap — passive, unauthenticated, read-only recon only.<br>
    <span class="warn-note">Only test hosts you are explicitly authorized to assess.</span>
  </footer>

</div>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


# --------------------------------------------------------------------------
# Status-code file export (one text file per status code)
# --------------------------------------------------------------------------

def save_status_code_files(base_dir, status_results, fuzz_results):
    """
    Organizes results into one text file per status code:

      <base_dir>/
        Subdomain/
          200_result.txt
          301_result.txt
          404_result.txt
          ...
        Directories/
          200_result.txt
          403_result.txt
          ...

    Each file is plain text, one entry per line. For subdomains each line
    is "domain , ip"; for directory fuzzing each line is the bare path.
    Returns (subdomain_dir, directories_dir, list_of_status_codes_written).
    """
    subdomain_dir = os.path.join(base_dir, "Subdomain")
    dirs_dir = os.path.join(base_dir, "Directories")

    codes_written = set()

    def write_group(folder, grouped):
        os.makedirs(folder, exist_ok=True)
        for code, entries in grouped.items():
            file_path = os.path.join(folder, f"{code}_result.txt")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(entries)) + "\n")
            codes_written.add(code)

    if status_results:
        grouped = defaultdict(list)
        for r in status_results:
            grouped[r["status"]].append(f"{r['host']} , {r['ip']}")
        write_group(subdomain_dir, grouped)

    if fuzz_results:
        grouped = defaultdict(list)
        for r in fuzz_results:
            grouped[r["status"]].append(r["path"])
        write_group(dirs_dir, grouped)

    return subdomain_dir, dirs_dir, sorted(codes_written)


# --------------------------------------------------------------------------
# Main / orchestration
# --------------------------------------------------------------------------

def main():
    banner()

    target = ask_target("Enter a URL or domain to scan")
    if not target:
        print(f"{C.RED}No target provided. Exiting.{C.RESET}")
        sys.exit(1)

    in_scope_host = target["host"]
    scheme = target["scheme"]
    leftover_path = target["path"]

    # Optional one-time advanced settings; everything defaults sensibly so
    # a bare "enter" here just runs the full scan automatically.
    advanced = ask_yes_no("Customize scan settings? (timeouts, wordlist, etc.)", "n")
    timeout = 8
    delay = 0.0
    wordlist_path = None
    if advanced:
        timeout = int(ask("Per-request timeout in seconds", "8"))
        delay = float(ask("Delay between requests in seconds (be polite)", "0"))
        if ask_yes_no("Use a custom wordlist file for directory fuzzing?", "n"):
            wordlist_path = ask("Path to wordlist file (one path per line)")

    total_steps = 5
    completed = 0

    def mark_done():
        nonlocal completed
        completed += 1
        print(f"{C.GREEN}✔ Step {completed}/{total_steps} complete.{C.RESET}\n")

    print(f"\n{C.CYAN}Running full automated scan against "
          f"{C.BOLD}{scheme}://{in_scope_host}{C.RESET}{C.CYAN} ...{C.RESET}\n")

    # Step 1 - DNS
    step1_dns_resolution(in_scope_host)
    mark_done()

    # Step 2 - crt.sh
    root_domain = ".".join(in_scope_host.split(".")[-2:])
    discovered = step2_crtsh_enum(root_domain, timeout=max(timeout, 10))
    mark_done()

    # Step 3/4 - status check (falls back to just the target host if crt.sh
    # returned nothing, e.g. due to no internet access or a crt.sh outage)
    hosts_to_check = discovered if discovered else [in_scope_host]
    status_results = step34_status_check(hosts_to_check, scheme=scheme, timeout=timeout, delay=delay)
    mark_done()
    mark_done()  # steps 3 and 4 are combined here

    # Step 5 - directory fuzzing
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                paths = [line.strip() for line in f if line.strip()]
            print(f"  {C.GREEN}Loaded {len(paths)} paths from {wordlist_path}{C.RESET}")
        except OSError as e:
            print(f"  {C.RED}Could not read wordlist ({e}). Using built-in default list.{C.RESET}")
            paths = DEFAULT_WORDLIST
    else:
        paths = DEFAULT_WORDLIST

    if leftover_path and leftover_path not in paths:
        paths = paths + [leftover_path]

    fuzz_results = step5_dir_fuzz(in_scope_host, paths, scheme=scheme, timeout=timeout, delay=delay)
    mark_done()

    # ------------------------------------------------------------------
    # Summary (tables)
    # ------------------------------------------------------------------
    hr("=")
    print(f"{C.BOLD}{C.CYAN} SUMMARY {C.RESET}")
    hr("=")

    if status_results:
        print(f"\n{C.BOLD}Subdomain / Host Results:{C.RESET}")
        sorted_results = sorted(status_results, key=lambda r: r["host"])
        rows = [
            [str(i + 1), r["host"], r["ip"], fmt_status(r["status"]), status_note(r["status"])]
            for i, r in enumerate(sorted_results)
        ]
        print(make_table(["#", "Subdomain", "IP Address", "Status", "Notes"], rows))
    else:
        print(f"\n{C.YELLOW}No subdomain/status results (DNS or crt.sh may be "
              f"unreachable from this network — check internet/DNS connectivity).{C.RESET}")

    if fuzz_results:
        print(f"\n{C.BOLD}Directory Fuzzing Results ({in_scope_host}):{C.RESET}")
        rows = [
            [str(i + 1), r["path"], fmt_status(r["status"]), status_note(r["status"])]
            for i, r in enumerate(fuzz_results)
        ]
        print(make_table(["#", "Path", "Status", "Notes"], rows))

    # ------------------------------------------------------------------
    # Save everything under one target-named folder:
    #
    #   <target>/
    #     JSON/results.json
    #     Subdomain/<code>_result.txt
    #     Directories/<code>_result.txt
    #     HTML/<target>_report.html   (optional)
    # ------------------------------------------------------------------
    target_dir = in_scope_host
    os.makedirs(target_dir, exist_ok=True)

    json_dir = os.path.join(target_dir, "JSON")
    os.makedirs(json_dir, exist_ok=True)
    out_path = os.path.join(json_dir, "results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "target": in_scope_host,
                "discovered_subdomains": discovered,
                "status_results": status_results,
                "fuzz_results": fuzz_results,
            },
            f,
            indent=2,
        )
    print(f"\n{C.GREEN}Results auto-saved to {out_path}{C.RESET}")

    subdomain_dir, dirs_dir, codes = save_status_code_files(target_dir, status_results, fuzz_results)
    if codes:
        print(f"{C.GREEN}Sorted by status code under {target_dir}/{C.RESET}")
        if status_results:
            print(f"  {C.GREY}{subdomain_dir}/<code>_result.txt{C.RESET}")
        if fuzz_results:
            print(f"  {C.GREY}{dirs_dir}/<code>_result.txt{C.RESET}")
        print(f"  {C.GREY}Status codes found: {', '.join(str(c) for c in codes)}{C.RESET}")

    if ask_yes_no("Also save a modern HTML report?", "y"):
        html_dir = os.path.join(target_dir, "HTML")
        os.makedirs(html_dir, exist_ok=True)
        html_path = os.path.join(html_dir, f"{in_scope_host}_report.html")
        generate_html_report(in_scope_host, scheme, status_results, fuzz_results, html_path)
        print(f"{C.GREEN}HTML report saved to {html_path}{C.RESET} "
              f"{C.GREY}(open it in any browser){C.RESET}")

    hr("=")
    print(f"{C.GREEN}{C.BOLD}All done!{C.RESET} Everything saved under "
          f"{C.CYAN}{C.BOLD}{target_dir}/{C.RESET}. Thanks for using {C.CYAN}{C.BOLD}ShadowMap{C.RESET}.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}Interrupted by user (Ctrl+C).{C.RESET} "
              f"{C.GREY}Exiting ShadowMap — no partial state was left running.{C.RESET}")
        sys.exit(130)  # conventional exit code for SIGINT
    except Exception as e:
        print(f"\n{C.RED}Unexpected error: {e}{C.RESET}")
        print(f"{C.GREY}If this keeps happening, please share the exact command/target "
              f"used so it can be reproduced.{C.RESET}")
        sys.exit(1)
