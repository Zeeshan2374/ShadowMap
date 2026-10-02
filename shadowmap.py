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

def step2_crtsh_enum(root_domain, timeout=15):
    section(f"crt.sh subdomain enumeration for *.{root_domain}", 2)
    url = f"https://crt.sh/?q=%25.{root_domain}&output=json"
    print(f"  Querying {C.GREY}{url}{C.RESET} ...")
    status, _, body = http_get(url, timeout=timeout)

    if status != 200 or not body:
        print(f"  {C.RED}crt.sh query failed (status={status}). Skipping.{C.RESET}")
        return []

    try:
        data = json.loads(body.decode("utf-8", errors="ignore"))
    except json.JSONDecodeError:
        print(f"  {C.RED}Could not parse crt.sh JSON response.{C.RESET}")
        return []

    names = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.splitlines():
            line = line.strip().lower()
            if line.startswith("*."):
                line = line[2:]
            if line.endswith(root_domain):
                names.add(line)

    names.add(root_domain)
    print(f"  {C.GREEN}Found {len(names)} unique hostnames.{C.RESET}")
    return sorted(names)


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
    <div>
      <div class="logo">ShadowMap</div>
      <div class="subtitle">Passive / Unauthenticated External Recon Report</div>
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
# Status-code folder export (one folder per status code, .txt inside)
# --------------------------------------------------------------------------

def save_status_code_folders(base_dir, status_results, fuzz_results):
    """
    Organizes results into a folder tree like:

      <base_dir>/
        Subdomain/
          200/results.txt
          301/results.txt
          404/results.txt
          ...
        Directories/
          200/results.txt
          403/results.txt
          ...

    Each results.txt is plain text, one entry per line. For subdomains each
    line is "domain , ip"; for directory fuzzing each line is the bare path.
    Returns (subdomain_dir, directories_dir, list_of_status_codes_written).
    """
    subdomain_dir = os.path.join(base_dir, "Subdomain")
    dirs_dir = os.path.join(base_dir, "Directories")

    codes_written = set()

    if status_results:
        os.makedirs(subdomain_dir, exist_ok=True)
        grouped = defaultdict(list)
        for r in status_results:
            grouped[r["status"]].append(f"{r['host']} , {r['ip']}")
        for code, entries in grouped.items():
            folder = os.path.join(subdomain_dir, str(code))
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, "results.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(entries)) + "\n")
            codes_written.add(code)

    if fuzz_results:
        os.makedirs(dirs_dir, exist_ok=True)
        grouped = defaultdict(list)
        for r in fuzz_results:
            grouped[r["status"]].append(r["path"])
        for code, entries in grouped.items():
            folder = os.path.join(dirs_dir, str(code))
            os.makedirs(folder, exist_ok=True)
            with open(os.path.join(folder, "results.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(entries)) + "\n")
            codes_written.add(code)

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
    #     Subdomain/<code>/results.txt
    #     Directories/<code>/results.txt
    #     <target>_report.html   (optional)
    # ------------------------------------------------------------------
    target_dir = in_scope_host  # e.g. "coindcx.com"
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

    subdomain_dir, dirs_dir, codes = save_status_code_folders(target_dir, status_results, fuzz_results)
    if codes:
        print(f"{C.GREEN}Sorted into status-code folders under {target_dir}/{C.RESET}")
        if status_results:
            print(f"  {C.GREY}{subdomain_dir}/<code>/results.txt{C.RESET}")
        if fuzz_results:
            print(f"  {C.GREY}{dirs_dir}/<code>/results.txt{C.RESET}")
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
