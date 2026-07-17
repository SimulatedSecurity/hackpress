# Hackpress templates

Nuclei-style JSON templates for `hackpress vuln` and `hackpress exploit`.

Both commands share the same engine (`template_engine`). Difference is intent and CLI:

| | `vuln` | `exploit` |
|---|--------|-----------|
| Intent | Safe validation | Potentially destructive PoC |
| Mass run | `--template-dir` + `--threads` | Single `--template` only |
| Examples | `templates/vulns/` | `templates/exploits/` |

**Only run exploits on systems you own or are authorized to test.**

## Run

```bash
hackpress vuln https://target.com --template templates/vulns/xss.json
hackpress vuln https://target.com --template-dir templates/vulns/ --threads 20
hackpress exploit https://target.com --template templates/exploits/exploit.json --waf-bypass
```

Useful globals: `--output json|table|markdown`, `--verbose`, `--waf-bypass`, `--threads` (vuln mass only).

## Minimal template

```json
{
  "id": "my-check",
  "info": {
    "name": "My Check",
    "author": ["you"],
    "severity": "medium",
    "description": "What this checks",
    "reference": [],
    "tags": ["wordpress"]
  },
  "variables": {
    "plugin_path": "/wp-content/plugins/example/"
  },
  "http": [
    {
      "method": "GET",
      "path": ["{{plugin_path}}readme.txt"],
      "matchers": [
        {
          "type": "status",
          "status": [200]
        }
      ]
    }
  ]
}
```

Built-in variable: `{{target}}` (base URL). Anything you put in `variables` (or extract later) is usable as `{{name}}`.

## HTTP requests

Each entry in `http` can use either **structured** fields or **raw**.

### Structured

| Field | Notes |
|-------|--------|
| `method` | `GET`, `POST`, `PUT`, `DELETE` (default GET) |
| `path` | Array; first element is used. Supports `{{vars}}` |
| `headers` | Map of header → value |
| `body` | Optional body string |
| `matchers` | Optional; if present and fail → template fails |
| `extractors` | Optional; fill variables for later requests |
| `cookie_reuse` | Default `true` (session cookies). `false` = no cookie jar |
| `max_redirects` | Optional redirect limit (uses a one-off client) |

### Raw

```json
{
  "raw": [
    "POST /wp-login.php HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nlog=admin&pwd=test"
  ],
  "matchers": [{ "type": "status", "status": [302] }]
}
```

`Host` in raw is ignored; the CLI target URL is used.

Requests run in order. Template-level `matchers` / `extractors` apply to the **last** response.

## Matchers

All listed matchers must pass (AND). Types:

| `type` | Fields | Meaning |
|--------|--------|---------|
| `status` | `status: [200, 302]` | HTTP status |
| `word` | `words`, `part`, `case_insensitive` | Substring (any word = OR inside one matcher) |
| `regex` | `regex`, `part` | Regex (any pattern = OR) |
| `size` | `size: [1024]` | Exact body length |

`part`: `body` (default), `header` / `headers`, `all`.

```json
{
  "type": "word",
  "words": ["error", "not found"],
  "part": "body",
  "negative": true,
  "case_insensitive": true
}
```

Empty matchers at template level → treated as success (prefer explicit matchers).

## Extractors

Pull data from a response into a variable for later steps.

```json
{
  "http": [
    {
      "method": "GET",
      "path": ["/wp-login.php"],
      "extractors": [
        {
          "type": "regex",
          "name": "nonce",
          "regex": ["name=\"_wpnonce\" value=\"([^\"]+)\""],
          "group": 1
        }
      ]
    },
    {
      "method": "POST",
      "path": ["/wp-login.php"],
      "headers": { "Content-Type": "application/x-www-form-urlencoded" },
      "body": "log=admin&pwd=x&_wpnonce={{nonce}}",
      "matchers": [{ "type": "status", "status": [302] }]
    }
  ]
}
```

| `type` | How |
|--------|-----|
| `regex` | First matching pattern; `group` = capture index (default `0`) |
| `json` | Paths like `token`, `data.token`, or pointer `/data/token` |

Variable name: `name` (or `group_name`). Without a name, the extractor is skipped.

## Examples

### Validation — reflected XSS

See `templates/vulns/xss.json`.

### Exploit — RCE-style check

See `templates/exploits/exploit.json`.

### Chained with JSON extractor

```json
{
  "id": "api-token-then-call",
  "info": {
    "name": "Fetch token then call API",
    "author": ["hackpress"],
    "severity": "high"
  },
  "http": [
    {
      "method": "GET",
      "path": ["/wp-json/myplugin/v1/session"],
      "extractors": [
        {
          "type": "json",
          "name": "token",
          "json": ["data.token"]
        }
      ],
      "matchers": [{ "type": "status", "status": [200] }]
    },
    {
      "method": "GET",
      "path": ["/wp-json/myplugin/v1/admin"],
      "headers": { "Authorization": "Bearer {{token}}" },
      "matchers": [
        { "type": "status", "status": [200] },
        { "type": "word", "words": ["\"role\":\"admin\""], "part": "body" }
      ]
    }
  ]
}
```

More samples under `docs/scripts-examples/`.

## Tips

1. Prefer unique `id` values and real `reference` / CVE links.
2. Keep `vuln` templates read-only (GET / harmless probes).
3. Test with `--verbose` and `--output json` on a lab target first.
4. For mass `vuln`, keep templates fast and independent.

## Troubleshooting

| Problem | Check |
|---------|--------|
| Template won't load | Valid JSON; path correct |
| Never matches | Inspect real response; `part`, case, `negative` |
| `{{var}}` empty | Define in `variables` or extract with `name` |
| Cookies missing between steps | Leave `cookie_reuse` true (default) |
| Redirect surprises | Set `max_redirects` (uses an isolated client) |
