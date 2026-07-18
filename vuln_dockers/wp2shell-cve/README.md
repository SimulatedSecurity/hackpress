# wp2shell lab (CVE-2026-63030)

Local Docker Compose stack for validating HackPress templates against **CVE-2026-63030 / wp2shell** (pre-auth REST batch route-confusion → SQLi).

| Component | Value |
|-----------|--------|
| WordPress | **7.0.1** (affected; fixed in 7.0.2) |
| URL | http://localhost:8080 |
| Admin | `admin` / `admin` |
| DB | MariaDB 11.4 |

**Authorized local testing only.** Do not expose this port to the internet.

## Start

```bash
cd vuln_dockers/wp2shell-cve
docker compose up -d
docker compose logs -f wp-setup
```

Wait until you see `Lab ready`. First start pulls images and can take a few minutes.

## Validate templates

From the **repo root** (with a built `hackpress` binary):

```bash
# Non-destructive marker probe (expect MATCH on 7.0.1)
hackpress vuln http://localhost:8080 --template templates/vulns/wp2shell-cve-2026-63030.json -v

# Active UNION SQLi data extraction (authorized labs only)
hackpress exploit http://localhost:8080 --template templates/exploits/wp2shell-cve-2026-63030-sqli-confirm.json -v
```

If pretty permalinks failed for some reason:

```bash
hackpress vuln http://localhost:8080 --template templates/vulns/wp2shell-cve-2026-63030-rest-route.json -v
```

## Stop / reset

```bash
cd vuln_dockers/wp2shell-cve
docker compose down          # keep volumes
docker compose down -v       # wipe DB + WP (clean reinstall next up)
```

## Config

Edit `.env` to change port, image pin, or credentials. Defaults:

- `WORDPRESS_IMAGE=wordpress:7.0.1-apache`
- `WP_PORT=8080`

## Notes

- `wp-setup` enables `/%postname%/` permalinks **and writes Apache rewrite rules** into `.htaccess` so `/wp-json/batch/v1` works.
- If `/wp-json/` still 404s, use the `wp2shell-cve-2026-63030-rest-route.json` template, or re-run setup: `docker compose run --rm wp-setup`.
- No security plugins / WAF — stock install so the batch probe can succeed.
- The published vuln templates use the **3-request** marker (`///` + posts + block-renderer). Some CDNs (e.g. Hostinger) block the older 4-request form that nests `/batch/v1` in the body; the 3-request form still yields the same three marker codes on affected cores.
- The UNION SQLi exploit template still needs the nested `/batch/v1` trailer (Icex0/Searchlight shape). Edge WAFs may block that while the marker still matches — treat “vuln MATCH + exploit fail” as possible WAF mitigation, not a false positive on the marker.
- To compare a **patched** build, change `WORDPRESS_IMAGE` to `wordpress:7.0.2-apache` (when published on Docker Hub), run `docker compose down -v && docker compose up -d`, and expect the marker template **not** to match.

## References

- [Searchlight Cyber — wp2shell](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core/)
- [WordPress 7.0.2 release](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
- [Icex0/wp2shell-poc](https://github.com/Icex0/wp2shell-poc)
