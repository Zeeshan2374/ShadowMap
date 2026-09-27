# ShadowMap 🕶️

**Passive / unauthenticated external recon toolkit** — built for teaching the basics of
reconnaissance methodology (DNS resolution, certificate-transparency subdomain
enumeration, HTTP status enumeration, and directory/path fuzzing).

Paste in a URL or domain and ShadowMap runs the full passive recon workflow
automatically, showing progress live and producing clean table output plus
JSON and HTML reports.

![status](https://img.shields.io/badge/status-educational-blue)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

---

## ⚠️ Authorized Use Only

This tool performs **read-only, unauthenticated** requests only — no credential
bruteforce, no exploitation, no destructive actions. Even so:

> **Only run ShadowMap against domains/hosts you own or are explicitly
> authorized to test.** Unauthorized scanning of systems you don't have
> permission to test may be illegal in your jurisdiction, regardless of intent.

Safe targets to practice on:
- `example.com` (IANA-reserved, safe to resolve/probe)
- `testphp.vulnweb.com` (Acunetix's public vulnerable test site)
- `demo.testfire.net` (IBM's intentionally vulnerable demo bank)
- Your own domains/servers, or in-scope bug bounty targets you've verified

---

## What it does

ShadowMap replicates a 5-step manual recon methodology:

| Step | What happens |
|------|--------------|
| 1 | **DNS resolution** — resolves the target hostname to its IP address(es) |
| 2 | **Subdomain enumeration** — queries [crt.sh](https://crt.sh) certificate transparency logs for `*.domain` |
| 3 | **Consolidation** — dedupes and normalizes discovered hostnames |
| 4 | **Status enumeration** — checks HTTP status + resolves IP for every discovered host |
| 5 | **Directory fuzzing** — probes a wordlist of common paths (`.git`, `.env`, `/admin`, `/api`, etc.) against the in-scope host only |

## Features

- ✅ Accepts a **bare domain or a full URL** — no need to strip `https://` yourself
- ✅ **Fully automated** — one prompt for the target, then it runs end-to-end
- ✅ **Animated ASCII banner** and live progress bars with ETA
- ✅ **Color-coded terminal tables** for subdomain and fuzzing results
- ✅ **Modern HTML report** export (dark dashboard, self-contained single file)
- ✅ **JSON export** for programmatic use / grading pipelines
- ✅ Graceful `Ctrl+C` handling — no raw tracebacks, shows partial results
- ✅ **Zero external dependencies** — pure Python 3 standard library

## Requirements

- Python 3.8+
- Internet access (for DNS resolution, crt.sh queries, and HTTP requests)
- No `pip install` needed — everything uses the standard library

## Usage

```bash
git clone https://github.com/Zeeshan2374/ShadowMap.git
cd ShadowMap
python3 shadowmap.py
```

You'll be prompted for a target, e.g.:

```
? Enter a URL or domain to scan: testphp.vulnweb.com
? Customize scan settings? (timeouts, wordlist, etc.) (y/n) [n]:
```

Press Enter to accept defaults and let it run. At the end you'll be asked
whether to also save an HTML report.

### Custom wordlist

If you answer "y" to customize settings, you can point ShadowMap at your own
wordlist file (one path per line) instead of the small built-in default list.

## Output

- `shadowmap_<host>_results.json` — structured results (subdomains, IPs, status codes, fuzz results)
- `shadowmap_<host>_report.html` — a self-contained, modern dark-themed HTML report you can open in any browser or share with a teammate

## For instructors / classroom use

This project is designed as a teaching tool for an intro recon/pentesting
module. Suggested exercises:

1. Run it against `testphp.vulnweb.com` and interpret each status code
2. Explain why `rds-*` or `eks-*`-style hostnames showing up in crt.sh results
   don't necessarily mean an exposed database/cluster (see the original
   Alasco-style report methodology this tool is modeled on)
3. Extend the wordlist and discuss why some blocked paths (`.git`, `.env`)
   return `403` from a WAF rather than `404` from the origin
4. Add a new step (e.g. HTTP header/security-header analysis) as a homework extension

## Disclaimer

This project is provided for **educational purposes**. The author and
contributors are not responsible for misuse. By using this tool you agree to
only test systems you own or are explicitly authorized to assess.

## License

MIT — see [LICENSE](LICENSE).
