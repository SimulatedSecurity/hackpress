# Hackpress

Open-source WordPress security scanner with CVE matching and Nuclei-style templates.

## Install

```bash
git clone https://github.com/simulatedsecurity/hackpress.git
cd hackpress
cargo build --release
# binary: target/release/hackpress  (or hackpress.exe on Windows)
```

## Quick start

```bash
# Update local databases (plugins, themes, vulns)
hackpress update

# Full scan
hackpress scan https://example.com

# Stealth / WAF / force
hackpress scan https://example.com --stealth
hackpress scan https://example.com --waf-bypass
hackpress scan https://example.com --force

# Active plugin/theme enum from local DB lists (after `hackpress update`)
hackpress scan https://example.com --enumerate=plugins,themes      # top lists
hackpress scan https://example.com --enumerate-all=plugins,themes  # full lists

# Templates
hackpress vuln https://example.com --template templates/vulns/xss.json
hackpress vuln https://example.com --template-dir templates/vulns/ --threads 20
hackpress exploit https://example.com --template templates/exploits/exploit.json

# Auth attacks
hackpress bruteforce https://example.com --users users.txt --passwords passwords.txt
hackpress spray https://example.com --users users.txt --passwords passwords.txt --rate-limit 2

# Interactive console
hackpress interactive
```

## Commands

| Command | Purpose |
|---------|---------|
| `scan <url>` | Detect WP, plugins/themes, CVEs, config, users, file disclosures |
| `vuln <url>` | Run validation template(s) (safe checks) |
| `exploit <url>` | Run one exploit template (destructive — authorized targets only) |
| `bruteforce <url>` | Password bruteforce (`wp-login`, `xmlrpc`, `rest-api`) |
| `spray <url>` | Password spray (same endpoints) |
| `update` | Download `database/` files from GitHub |
| `interactive` | msfconsole-like session |

### Global flags

| Flag | Effect |
|------|--------|
| `--output json\|table\|markdown` | Output format (default: `table`) |
| `-v, --verbose` | Verbose logging |
| `--threads <n>` | Concurrency for mass `vuln` (default: 10) |
| `--waf-bypass` | Browser-like headers, throttling, cookie/referer chain |
| `--stealth` | Less traffic: skip aggressive file/user/dir enumeration |
| `--force` | Continue full scan even if WordPress is not detected |

`scan`-only:

| Flag | Effect |
|------|--------|
| `--enumerate=plugins,themes` | After passive detect, probe **top** DB lists |
| `--enumerate-all=plugins,themes` | Same with **full** DB lists (slower) |

Do not combine `--enumerate` and `--enumerate-all`. Both need local files from `hackpress update`.

### Flag notes (short)

- **`--waf-bypass`** — random browser UA, full browser headers, 1–3s delays, cookies + referer, gzip/brotli decode, warm-up `GET /`. Same checks, slower against WAFs.
- **`--stealth`** — skip backup/file bruteforce, author archives, directory listings; plugins/themes mostly passive. No throttling unless you also pass `--waf-bypass`.
- **`--force`** — run the rest of the pipeline when WP detection fails (hidden/custom installs).
- **Databases** — `vulns.json` auto-downloads on scan if missing; plugins/themes lists only via `hackpress update`.
- **WAF alerts** — high-confidence only (challenge pages, `cf-mitigated`, hard-block bodies). Plain `403` + `cf-ray` is not a hard block; scan no longer aborts on weak signals.
## Interactive mode

```text
hackpress interactive
hackpress [not set] > set target https://example.com
hackpress [https://example.com] > set waf-bypass
hackpress [https://example.com] > scan
hackpress [https://example.com] > help
```

Useful: `set` / `unset` / `show options`, `scan`, `vuln`, `exploit`, `bruteforce`, `spray`, `update`, `exit`.

## Project layout

```text
src/                 Rust CLI (scan, templates, bruteforce, …)
templates/exploits/  Exploit templates
templates/vulns/     Validation templates
database/            Local cache (plugins*.txt, themes*.txt, vulns.json)
docs/                Template guide
```

## Documentation

- [Templates](docs/TEMPLATES.md) — structure, matchers, extractors, raw HTTP, examples

Older doc filenames redirect there: `TEMPLATE_TUTORIAL.md`, `EXPLOIT_TEMPLATES.md`, `VULN_TEMPLATES.md`.

## License

MIT — see [LICENSE](LICENSE).
