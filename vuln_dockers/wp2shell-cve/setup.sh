#!/bin/sh
# One-shot installer for the wp2shell lab (pretty permalinks + known admin).
set -eu

PATH_WP="/var/www/html"
WP_URL="${WP_URL:-http://localhost:8080}"
WP_ADMIN_USER="${WP_ADMIN_USER:-admin}"
WP_ADMIN_PASSWORD="${WP_ADMIN_PASSWORD:-admin}"
WP_ADMIN_EMAIL="${WP_ADMIN_EMAIL:-admin@lab.local}"
WP_TITLE="${WP_TITLE:-wp2shell-lab}"

echo "[*] Waiting for database..."
i=0
until wp db check --path="$PATH_WP" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "[-] Database not ready"
    exit 1
  fi
  sleep 2
done

echo "[*] Waiting for WordPress core files..."
i=0
until [ -f "$PATH_WP/wp-includes/version.php" ]; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "[-] WordPress files not ready"
    exit 1
  fi
  sleep 2
done

VER="$(wp core version --path="$PATH_WP")"
echo "[*] WordPress core version: $VER"

if ! wp core is-installed --path="$PATH_WP"; then
  echo "[*] Running wp core install..."
  wp core install \
    --path="$PATH_WP" \
    --url="$WP_URL" \
    --title="$WP_TITLE" \
    --admin_user="$WP_ADMIN_USER" \
    --admin_password="$WP_ADMIN_PASSWORD" \
    --admin_email="$WP_ADMIN_EMAIL" \
    --skip-email
else
  echo "[*] WordPress already installed; refreshing URLs / permalinks..."
  wp option update home "$WP_URL" --path="$PATH_WP"
  wp option update siteurl "$WP_URL" --path="$PATH_WP"
fi

# Pretty permalinks are required for /wp-json/batch/v1 (otherwise use rest_route template).
echo "[*] Enabling pretty permalinks..."
wp rewrite structure '/%postname%/' --path="$PATH_WP"
wp option update permalink_structure '/%postname%/' --path="$PATH_WP"

# WP-CLI --hard often skips writing .htaccess in this image; write rules ourselves.
HTACCESS="$PATH_WP/.htaccess"
echo "[*] Writing Apache rewrite rules to .htaccess..."
cat > "$HTACCESS" <<'EOF'
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
EOF

wp rewrite flush --path="$PATH_WP"

# Smoke-check REST discovery (best-effort; may fail until Apache finishes warming).
if wp rewrite structure --path="$PATH_WP" >/dev/null 2>&1; then
  echo "[*] Permalink structure OK"
fi

echo ""
echo "[+] Lab ready (authorized local testing only)"
echo "    URL:       $WP_URL"
echo "    Admin:     $WP_ADMIN_USER / $WP_ADMIN_PASSWORD"
echo "    Version:   $(wp core version --path="$PATH_WP")"
echo "    REST:      $WP_URL/wp-json/"
echo "    Batch:     $WP_URL/wp-json/batch/v1"
echo ""
echo "    Validate (from repo root):"
echo "      hackpress vuln $WP_URL --template templates/vulns/wp2shell-cve-2026-63030.json -v"
echo "      hackpress exploit $WP_URL --template templates/exploits/wp2shell-cve-2026-63030-sqli-confirm.json -v"
echo ""
