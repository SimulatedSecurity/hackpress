# Hackpress

Open-source WordPress security scanner with exploit templates and vulnerability validation.

## Features

- **WordPress Detection**: Multiple detection methods with version identification and outdated warnings
- **Plugin Enumeration**: Passive detection from web content, version from `readme.txt` or `?ver=` parameter, SVN latest version lookup, outdated plugin warnings
- **Theme Enumeration**: Passive detection from CSS/JS paths, version from `style.css`, SVN latest version lookup, outdated theme warnings
- **Vulnerability Enumeration**: Automatic CVE matching from multiple sources for WordPress core, plugins, and themes with detailed information (description, affected versions, references)
- **General Findings**: IP address, country, ASN, server, PHP version, CDN, security headers, relevant headers (x-powered-by, PleskLin, etc.)
- **WordPress Configuration**: XML-RPC status, comments, user signup, login path detection, path disclosure vulnerabilities
- **Username Enumeration**: REST API, RSS feed, author archive enumeration
- **File Disclosure Detection**: wp-config backups, database dumps, error logs, version control, directory listings, backup paths
- **Password Attacks**: Bruteforcing and spraying with multiple endpoints (wp-login, XML-RPC, REST API)
- **WAF Bypass**: Browser-like behavior with throttling, referer chain, and full headers
- **Stealth Mode**: Minimal footprint scanning with reduced traffic and no aggressive enumeration
- **Force Mode**: Continue scanning even when WordPress is not detected
- **Nuclei-style Templates**: Exploit and vulnerability validation templates
- **Multiple Output Formats**: Table (real-time), JSON, Markdown
- **Interactive Mode**: Console-based interface similar to msfconsole

## Installation

```bash
# Clone the repository
git clone https://github.com/simulatedsecurity/hackpress.git
cd hackpress

# Build the project
cargo build --release

# The binary will be in target/release/hackpress
```

## Usage

### Global Options

All commands support these global options:

- `--output <format>` - Output format: `json`, `table` (default), or `markdown`
- `-v, --verbose` - Enable verbose logging
- `--threads <num>` - Number of concurrent threads (default: 10)
- `--waf-bypass` - Enable WAF bypass with browser-like behavior and throttling
- `--force` - Force complete scan even if WordPress is not detected
- `--stealth` - Stealth mode: minimal footprint, reduced traffic, no aggressive enumeration
- `--version` - Display version information and exit

### Commands

#### Scan

Perform a comprehensive WordPress security scan:

```bash
# Basic scan
hackpress scan https://example.com

# With verbose output and WAF bypass
hackpress scan https://example.com --verbose --waf-bypass

# Force complete scan even if WordPress is not detected
hackpress scan https://example.com --force

# Stealth mode (reduced traffic, no bruteforcing, no archive enumeration)
hackpress scan https://example.com --stealth

# Enumerate plugins/themes from top database files (plugins-top.txt, themes-top.txt)
hackpress scan https://example.com --enumerate=plugins,themes
hackpress scan https://example.com --enumerate=plugins
hackpress scan https://example.com --enumerate=themes

# Enumerate plugins/themes from complete database files (plugins.txt, themes.txt)
hackpress scan https://example.com --enumerate-all=plugins,themes
hackpress scan https://example.com --enumerate-all=plugins

# Output in JSON format
hackpress scan https://example.com --output json

# Output in markdown format
hackpress scan https://example.com --output markdown > report.md

# Show version
hackpress --version
```

The scan command detects:
- **WordPress Detection**: Version detection, installation confirmation, outdated version warnings
- **Plugins**: Passive detection from web content, version detection from `readme.txt` or `?ver=` parameter, SVN latest version lookup, outdated plugin warnings
- **Themes**: Passive detection from CSS/JS paths, version from `style.css`, SVN latest version lookup, outdated theme warnings
- **Vulnerabilities**: Enumeration from multiple sources (`vulns.json` database) with automatic download if not present locally. Displays detailed information: description, affected versions, and clickable reference URLs. Results are sorted: Core → Themes → Plugins (by type), then by severity (critical → minimal)
- **General Findings**: IP address and country (with ASN), server identification, PHP version, CDN detection, security headers, relevant headers (x-powered-by, PleskLin, etc.)
- **WordPress Configuration**: XML-RPC status, comments allowed, user signup enabled, login path detection, path disclosure vulnerabilities
- **Usernames**: REST API enumeration, RSS feed enumeration, author archive enumeration (unless stealth mode)
- **File Disclosures**: wp-config backups, database dumps, error logs, version control files, directory listings, common backup paths (unless stealth mode)

### Advanced Options Explained

#### `--waf-bypass` - WAF Bypass Mode

**Purpose:** Bypass Web Application Firewalls (WAF) by mimicking real browser behavior and implementing request throttling.

**What it includes:**
- ✅ **Random User-Agent**: Uses a consistent random browser user agent (Chrome/Firefox/Safari/Edge) for the entire session
- ✅ **Full Browser Headers**: Adds complete browser-like headers including:
  - `Accept`, `Accept-Encoding`, `Accept-Language`
  - `Referer` (maintains referer chain across requests)
  - `DNT` (Do Not Track)
  - `Viewport-Width` (Chrome-specific)
  - `Sec-Fetch-*` headers (Site, Mode, Dest, User)
  - `Connection: keep-alive`
  - `Upgrade-Insecure-Requests: 1`
  - `Cache-Control` (for non-navigation requests)
- ✅ **Request Throttling**: 
  - First request: 2-3 seconds delay (simulates initial page load)
  - Subsequent requests: 1-3 seconds random delay (avoids rate limiting)
- ✅ **Cookie Persistence**: Maintains cookie jar across requests
- ✅ **Referer Chain**: Builds realistic referer chain (homepage → assets → sensitive paths)

**What it does NOT include:**
- ❌ Does not skip any scan checks (all enumeration still runs)
- ❌ Does not reduce traffic volume (same number of requests, just throttled)
- ❌ Does not skip file/backup checks

**When to use:**
- When encountering WAF blocks (HTTP 403, 406, 415)
- When requests are being rate-limited
- When you need to bypass Cloudflare, Imunify360, ModSecurity, or similar WAFs
- For penetration testing on protected sites

**Example:**
```bash
hackpress scan https://example.com --waf-bypass
```

---

#### `--stealth` - Stealth Mode

**Purpose:** Minimize scan footprint and avoid detection by security monitoring systems.

**What it includes:**
- ✅ **Random User-Agent**: Uses a consistent random browser user agent (instead of default "hackpress/0.1.0")
- ✅ **Minimal Headers**: Only sends User-Agent header (no browser-like headers)
- ✅ **No File/Backup Bruteforcing**: Completely skips:
  - wp-config.php backup checks
  - Database dump checks (`.sql`, `.sql.gz`)
  - Error log checks
  - Version control checks (`.git`, `.svn`, `.hg`)
  - Common backup path checks (`/backup.zip`, `/wp-content/updraft/`, etc.)
  - Directory listing checks
- ✅ **No Username Archive Enumeration**: Skips author archive page enumeration (`/?author=1` through `/?author=20`)
  - Still uses REST API (`/wp-json/wp/v2/users`) - more discrete
  - Still uses RSS feed enumeration - passive method
- ✅ **No Directory Enumeration**: Skips:
  - Plugin directory listing (`/wp-content/plugins/`)
  - Theme directory listing (`/wp-content/themes/`)
  - Upload directory listing (`/wp-content/uploads/`)
- ✅ **Reduced Plugin/Theme Traffic**: 
  - Plugins: Only detects from passive HTML/CSS/JS analysis (no directory listing)
  - Themes: Only detects from passive HTML/CSS/JS analysis (no directory listing)
  - Plugin versions: Only from `?ver=` parameter (no `readme.txt` checks, no SVN lookups)
  - Theme versions: Only from `style.css` (no SVN lookups)

**What it does NOT include:**
- ❌ No request throttling (requests are sent at normal speed)
- ❌ No browser-like headers (minimal headers only)
- ❌ No referer chain building

**When to use:**
- When you need to avoid detection by security monitoring
- When you want to minimize server logs
- When you need to reduce server load
- For reconnaissance with minimal footprint
- When testing on production systems where aggressive scanning is not allowed

**Example:**
```bash
hackpress scan https://example.com --stealth
```

---

#### `--force` - Force Scan Mode

**Purpose:** Continue scanning even when WordPress is not detected.

**What it includes:**
- ✅ **Full Scan Execution**: Performs all scan checks regardless of WordPress detection
- ✅ **Plugin Enumeration**: Still attempts to enumerate plugins
- ✅ **Theme Enumeration**: Still attempts to enumerate themes
- ✅ **Vulnerability Matching**: Still matches against vulnerability database
- ✅ **Username Enumeration**: Still attempts username enumeration
- ✅ **File Disclosure Checks**: Still checks for file disclosures
- ✅ **General Findings Analysis**: Still analyzes general findings (IP, country, server, etc.)

**What it does NOT include:**
- ❌ Does not change request behavior (no throttling, no special headers)
- ❌ Does not skip any checks (opposite of stealth mode)

**When to use:**
- When WordPress detection fails but you suspect WordPress is present
- When you want to check for plugins/themes even on non-WordPress sites
- For comprehensive security assessment regardless of CMS detection
- When WordPress is hidden or obfuscated

**Example:**
```bash
hackpress scan https://example.com --force
```

---

#### `--enumerate` - Enumerate from Top Database Files

**Purpose:** Enumerate plugins/themes from top database files after passive detection.

**What it includes:**
- ✅ **Top Database Files**: Uses `plugins-top.txt` and `themes-top.txt` from local `database/` directory
- ✅ **Post-Passive Enumeration**: Runs after passive detection, combining results
- ✅ **Duplicate Prevention**: Automatically skips plugins/themes already found passively
- ✅ **Version Detection**: Uses same methods as passive detection (readme.txt, ?ver= parameter, SVN lookup)
- ✅ **Progress Bar**: Displays real-time progress with status and current number (`Enumerating themes [X/Y] Z%`)
- ✅ **Order**: Enumerates themes first, then plugins (as specified)
- ✅ **Local Files Only**: Only works if database files exist locally (requires `hackpress update`)

**Format:**
- `--enumerate=plugins,themes` - Enumerate both plugins and themes
- `--enumerate=plugins` - Enumerate only plugins
- `--enumerate=themes` - Enumerate only themes

**What it does NOT include:**
- ❌ Does not work with `--enumerate-all` (cannot use both simultaneously)
- ❌ Does not download database files automatically (must run `hackpress update` first)
- ❌ Does not use complete database files (uses top files only)

**When to use:**
- When you want to check for popular plugins/themes from top database lists
- For faster enumeration using curated top lists instead of full databases
- When you've already run `hackpress update` and have top database files locally

**Example:**
```bash
# Enumerate both plugins and themes from top files
hackpress scan https://example.com --enumerate=plugins,themes

# Enumerate only plugins from top files
hackpress scan https://example.com --enumerate=plugins
```

---

#### `--enumerate-all` - Enumerate from Complete Database Files

**Purpose:** Enumerate plugins/themes from complete database files after passive detection.

**What it includes:**
- ✅ **Complete Database Files**: Uses `plugins.txt` and `themes.txt` from local `database/` directory
- ✅ **Post-Passive Enumeration**: Runs after passive detection, combining results
- ✅ **Duplicate Prevention**: Automatically skips plugins/themes already found passively
- ✅ **Version Detection**: Uses same methods as passive detection (readme.txt, ?ver= parameter, SVN lookup)
- ✅ **Progress Bar**: Displays real-time progress with status and current number (`Enumerating plugins [X/Y] Z%`)
- ✅ **Order**: Enumerates themes first, then plugins (as specified)
- ✅ **Comprehensive**: Checks all plugins/themes from complete database (can be slow for large databases)
- ✅ **Local Files Only**: Only works if database files exist locally (requires `hackpress update`)

**Format:**
- `--enumerate-all=plugins,themes` - Enumerate both plugins and themes
- `--enumerate-all=plugins` - Enumerate only plugins
- `--enumerate-all=themes` - Enumerate only themes

**What it does NOT include:**
- ❌ Does not work with `--enumerate` (cannot use both simultaneously)
- ❌ Does not download database files automatically (must run `hackpress update` first)
- ❌ Does not use top database files (uses complete files only)

**When to use:**
- When you want comprehensive enumeration from complete database lists
- For thorough security assessments requiring all possible plugins/themes
- When you've already run `hackpress update` and have complete database files locally
- When top lists are insufficient and you need full coverage

**Example:**
```bash
# Enumerate both plugins and themes from complete files
hackpress scan https://example.com --enumerate-all=plugins,themes

# Enumerate only themes from complete files
hackpress scan https://example.com --enumerate-all=themes
```

**Note:** Both `--enumerate` and `--enumerate-all` require local database files. Run `hackpress update` first to download the database files from GitHub.

---

### Combining Flags

You can combine flags for different scenarios:

```bash
# Stealth mode with WAF bypass (minimal footprint + browser-like behavior)
hackpress scan https://example.com --stealth --waf-bypass

# Force scan with verbose output (comprehensive scan with detailed logging)
hackpress scan https://example.com --force --verbose

# All flags combined (force scan, stealth mode, WAF bypass, verbose)
hackpress scan https://example.com --force --stealth --waf-bypass --verbose
```

**Note:** When `--stealth` and `--waf-bypass` are both enabled:
- User-Agent: Random browser (from `--waf-bypass`)
- Headers: Full browser headers (from `--waf-bypass`)
- Throttling: Enabled (from `--waf-bypass`)
- Scan checks: Reduced (from `--stealth`)

#### Vulnerability Validation

Run vulnerability validation templates (safe, read-only):

```bash
# Single template execution
hackpress vuln https://example.com --template templates/vulns/example-xss.json

# Mass execution of all templates in directory
hackpress vuln https://example.com --template-dir templates/vulns/

# Mass execution with custom thread count
hackpress vuln https://example.com --template-dir templates/vulns/ --threads 20

# Output results to JSON file
hackpress vuln https://example.com --template-dir templates/vulns/ --output json > vuln-results.json
```

#### Exploit Execution

Execute exploit templates (potentially destructive - use with caution):

```bash
# Execute a single exploit template
hackpress exploit https://example.com --template templates/exploits/example-rce.json

# With WAF bypass
hackpress exploit https://example.com --template templates/exploits/example-rce.json --waf-bypass
```

**Warning:** Exploits are potentially destructive. Only use on systems you own or have explicit permission to test.

#### Password Bruteforcing

Perform password bruteforcing attacks:

```bash
# Basic bruteforce attack
hackpress bruteforce https://example.com --users users.txt --passwords passwords.txt

# With rate limiting (requests per second)
hackpress bruteforce https://example.com --users users.txt --passwords passwords.txt --rate-limit 5

# Stop on first successful login
hackpress bruteforce https://example.com --users users.txt --passwords passwords.txt --stop-on-success

# Using XML-RPC endpoint
hackpress bruteforce https://example.com --users users.txt --passwords passwords.txt --bruteforce-type xmlrpc

# Using REST API endpoint
hackpress bruteforce https://example.com --users users.txt --passwords passwords.txt --bruteforce-type rest-api

# Using wp-login endpoint (default)
hackpress bruteforce https://example.com --users users.txt --passwords passwords.txt --bruteforce-type wp-login
```

Bruteforce types: `wp-login` (default), `xmlrpc`, `rest-api`, `custom`

#### Password Spraying

Perform password spraying attacks (one password across all users):

```bash
# Basic password spraying
hackpress spray https://example.com --users users.txt --passwords passwords.txt

# With custom rate limit (default: 2 requests/second)
hackpress spray https://example.com --users users.txt --passwords passwords.txt --rate-limit 3

# Using XML-RPC endpoint
hackpress spray https://example.com --users users.txt --passwords passwords.txt --bruteforce-type xmlrpc
```

#### Update Databases

Update plugin and vulnerability databases from GitHub:

```bash
hackpress update
```

**Note:** The vulnerability database (`vulns.json`) is automatically downloaded during scans if not found locally. Use `hackpress update` to manually update all databases from GitHub.

#### Interactive Mode

Start an interactive console session (similar to msfconsole):

```bash
hackpress interactive
```

Once in interactive mode, you can:
- **Set target URL**: `set target https://example.com`
- **Configure options**: 
  - `set waf-bypass` - Enable WAF bypass mode
  - `set stealth` - Enable stealth mode
  - `set force` - Enable force scan mode
  - `set verbose` - Enable verbose logging
  - `set threads 20` - Set thread count
  - `set output json` - Set output format (json/table/markdown)
- **Unset options**: `unset waf-bypass`, `unset stealth`, `unset force`, `unset verbose`
- **Run commands**: `scan`, `exploit <template>`, `vuln <template>`, `bruteforce <users> <passwords>`, `spray <users> <passwords>`, `update`
- **View current options**: `show options` or `show target`
- **Get help**: `help`
- **Clear screen**: `clear` or `cls`
- **Exit**: `exit`

Example interactive session:
```bash
hackpress interactive
hackpress [not set] > set target https://example.com
✓ Target set to: https://example.com
hackpress [https://example.com] > scan
→ Running scan on https://example.com...
[... scan results ...]
hackpress [https://example.com] > set waf-bypass
✓ WAF bypass enabled
hackpress [https://example.com] > bruteforce users.txt passwords.txt
→ Running bruteforce attack on https://example.com...
[... bruteforce results ...]
hackpress [https://example.com] > exit
```

## Examples

### Complete Security Assessment

```bash
hackpress scan https://target-site.com --output markdown > report.md
```

This performs a comprehensive scan including WordPress detection, plugin/theme enumeration with outdated warnings, vulnerability enumeration from multiple sources with detailed information (description, affected versions, references), file disclosure checks, username enumeration, and general findings (IP, country, server, etc.).

### Stealth Reconnaissance

```bash
hackpress scan https://target-site.com --stealth --verbose
```

Minimal footprint scan that avoids aggressive enumeration while still gathering essential information.

### WAF-Protected Site

```bash
hackpress scan https://target-site.com --waf-bypass --verbose
```

Bypass WAF protection using browser-like behavior and request throttling.

### Force Scan (False-negative cases)

```bash
hackpress scan https://target-site.com --force
```

Continue scanning even if WordPress is not detected - useful for checking plugins/themes on custom setups.

### Mass Vulnerability Validation

```bash
hackpress vuln https://target-site.com --template-dir templates/vulns/ --threads 20 --output json > vuln-results.json
```

This safely validates multiple CVEs concurrently without exploitation.

### Controlled Password Attack

```bash
hackpress bruteforce https://target-site.com \
  --users users.txt \
  --passwords passwords.txt \
  --bruteforce-type wp-login \
  --rate-limit 5 \
  --stop-on-success
```

This limits requests to 5 per second and stops on first successful login.


## Project Structure

- `src/` - Source code
  - `detection.rs` - WordPress, plugin, and theme detection
  - `enumeration.rs` - Username enumeration
  - `file_disclosure.rs` - File disclosure checks
  - `http_client.rs` - HTTP client with WAF bypass and stealth support
  - `scanner.rs` - Main scanning orchestration
  - `output.rs` - Output formatting (table, JSON, markdown)
  - `tech_stack.rs` - General findings analysis (IP, country, server, headers)
  - `vulnerability_matcher.rs` - CVE matching
  - `constants.rs` - Application constants (version, URLs, timeouts, etc.)
- `templates/exploits/` - Exploit templates
- `templates/vulns/` - Vulnerability validation templates
- `database/` - Local database cache (plugins, themes, vulnerabilities)
  - `vulns.json` - Vulnerability database from multiple sources (auto-downloaded if missing)
- `docs/` - Documentation

## Documentation

For detailed documentation, see:
- [Template Tutorial](docs/TEMPLATE_TUTORIAL.md) - How to create and use templates
- [Exploit Templates Guide](docs/EXPLOIT_TEMPLATES.md) - Exploit template documentation
- [Vulnerability Templates Guide](docs/VULN_TEMPLATES.md) - Vulnerability validation templates

## License


## Status

✅ **Active Development** - Core features implemented. Plugin/theme detection, vulnerability matching, WAF bypass, stealth mode, IP geolocation, and version management are fully functional.
