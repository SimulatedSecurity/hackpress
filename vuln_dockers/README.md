# Vulnerability Docker labs

Docker Compose labs that spin up **vulnerable WordPress versions** so you can validate HackPress `vuln` / `exploit` templates locally.

**Authorized testing only.** Bind these stacks to localhost. Do not expose them to the internet.

## Labs

| Directory | CVE / issue | WordPress | Purpose |
|-----------|-------------|-----------|---------|
| [wp2shell-cve](wp2shell-cve/) | [CVE-2026-63030](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/) (wp2shell) | **7.0.1** (fixed in 7.0.2) | REST batch route-confusion → pre-auth SQLi |

## Quick start (example)

```bash
cd vuln_dockers/wp2shell-cve
docker compose up -d
docker compose logs -f wp-setup   # wait for "Lab ready"
```

Then from the repo root:

```bash
hackpress vuln http://localhost:8080 --template templates/vulns/wp2shell-cve-2026-63030.json -v
hackpress exploit http://localhost:8080 --template templates/exploits/wp2shell-cve-2026-63030-sqli-confirm.json -v
```

See each lab’s own `README.md` for ports, credentials, reset, and patched-version comparison.

## Adding a new lab

1. Create `vuln_dockers/<short-name>/` with `docker-compose.yml`, setup script if needed, `.env`, and a lab `README.md`.
2. Pin an affected WordPress (or plugin) image/version.
3. Document matching templates under `templates/vulns/` / `templates/exploits/`.
4. Add a row to the table above.
