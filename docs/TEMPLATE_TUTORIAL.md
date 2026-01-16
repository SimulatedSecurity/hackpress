# Template Tutorial

This guide provides step-by-step instructions for creating custom exploit and vulnerability validation templates for hackpress.

## Overview

hackpress supports two types of templates:

1. **Exploit Templates** (`templates/exploits/`) - Execute actual exploits (potentially destructive)
2. **Vulnerability Validation Templates** (`templates/vulns/`) - Validate vulnerabilities without exploitation (safe, read-only)

## Template Structure

Both template types follow the same Nuclei-style JSON structure:

```json
{
  "id": "unique-template-id",
  "info": {
    "name": "Template Name",
    "author": ["Author Name"],
    "severity": "critical|high|medium|low",
    "description": "Template description",
    "reference": ["https://..."],
    "tags": ["tag1", "tag2"]
  },
  "variables": {
    "target": "{{target}}",
    "custom_var": "value"
  },
  "http": [
    {
      "method": "GET|POST|PUT|DELETE",
      "path": ["/path/to/endpoint"],
      "headers": {
        "Header-Name": "value"
      },
      "body": "request body",
      "matchers": [...]
    }
  ],
  "matchers": [...],
  "extractors": [...]  // Note: Extractors are defined in the structure but not yet implemented
}
```

## Command Usage

All hackpress commands support global options that can be used with template execution:

- `--output <format>` - Output format: `json`, `table` (default), or `markdown`
- `--verbose` - Enable verbose logging for debugging
- `--threads <num>` - Number of concurrent threads (for mass execution, default: 10)
- `--waf-bypass` - Enable WAF bypass with random user agents

These options work with both `hackpress exploit` and `hackpress vuln` commands.

## Step-by-Step Template Creation

### Step 1: Basic Template Structure

Start with a minimal template:

```json
{
  "id": "my-template",
  "info": {
    "name": "My Template",
    "author": ["Your Name"],
    "severity": "medium",
    "description": "Template description"
  },
  "http": [
    {
      "method": "GET",
      "path": ["/endpoint"]
    }
  ]
}
```

### Step 2: Add Variables

Variables allow dynamic content substitution:

```json
{
  "variables": {
    "target": "{{target}}",
    "plugin_path": "/wp-content/plugins/my-plugin/"
  },
  "http": [
    {
      "method": "GET",
      "path": ["{{plugin_path}}vulnerable.php"]
    }
  ]
}
```

Available built-in variables:
- `{{target}}` - The target URL provided by the user

### Step 3: Configure HTTP Request

Specify method, path, headers, and body:

```json
{
  "http": [
    {
      "method": "POST",
      "path": ["/wp-admin/admin-ajax.php"],
      "headers": {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      "body": "action=test&data=payload"
    }
  ]
}
```

### Step 4: Add Matchers

Matchers validate the response to determine success:

```json
{
  "matchers": [
    {
      "type": "status",
      "status": [200, 201]
    },
    {
      "type": "word",
      "words": ["success", "executed"],
      "part": "body"
    }
  ]
}
```

Matcher types:
- `status` - Match HTTP status codes
- `word` - Match specific words in response
- `regex` - Match regular expressions
- `size` - Match response size

**Note:** Extractors are defined in the template structure but are not yet implemented in the current version of hackpress. Only matchers are currently used for template validation.

### Step 5: Test Your Template

Test your template:

**For exploit templates:**
```bash
# Basic execution
hackpress exploit https://target.com --template templates/exploits/my-template.json

# With WAF bypass
hackpress exploit https://target.com --template templates/exploits/my-template.json --waf-bypass

# With verbose output
hackpress exploit https://target.com --template templates/exploits/my-template.json --verbose
```

**For vulnerability validation templates:**
```bash
# Single template execution
hackpress vuln https://target.com --template templates/vulns/my-template.json

# Mass execution (all templates in directory)
hackpress vuln https://target.com --template-dir templates/vulns/

# Mass execution with custom thread count
hackpress vuln https://target.com --template-dir templates/vulns/ --threads 20

# Output to JSON
hackpress vuln https://target.com --template-dir templates/vulns/ --output json > results.json
```

## Common Patterns

### Pattern 1: Simple GET Request

```json
{
  "http": [
    {
      "method": "GET",
      "path": ["/vulnerable-endpoint"],
      "matchers": [
        {
          "type": "word",
          "words": ["vulnerable"],
          "part": "body"
        }
      ]
    }
  ]
}
```

### Pattern 2: POST with Form Data

```json
{
  "http": [
    {
      "method": "POST",
      "path": ["/wp-login.php"],
      "headers": {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      "body": "log=admin&pwd=password",
      "matchers": [
        {
          "type": "status",
          "status": [302]
        }
      ]
    }
  ]
}
```

### Pattern 3: Multiple Requests (Chained)

```json
{
  "http": [
    {
      "method": "GET",
      "path": ["/login.php"]
    },
    {
      "method": "POST",
      "path": ["/login.php"],
      "body": "user=admin&pass=test"
    }
  ]
}
```

## Best Practices

1. **Use descriptive IDs** - Make template IDs unique and descriptive
2. **Include references** - Add CVE numbers, advisory URLs, etc.
3. **Test thoroughly** - Test templates on safe environments first
4. **Use appropriate severity** - Match severity to actual impact
5. **Document complex payloads** - Add comments in description field
6. **Handle errors gracefully** - Use negative matchers to detect failures

## Differences: Exploit vs Validation Templates

### Exploit Templates
- Execute actual exploits
- Can be destructive
- Use for confirmed vulnerabilities
- Single execution only (`hackpress exploit <url> --template <path>`)
- **Warning**: Only use on systems you own or have explicit permission to test

### Vulnerability Validation Templates
- Read-only validation
- Safe to run
- Use for vulnerability detection
- Supports mass execution (`hackpress vuln <url> --template-dir <path>`)
- Can run hundreds of templates concurrently with `--threads` option

## Advanced Features

### Negative Matchers

Match when something should NOT be present:

```json
{
  "matchers": [
    {
      "type": "word",
      "words": ["error", "not found"],
      "part": "body",
      "negative": true
    }
  ]
}
```

### Case-Insensitive Matching

```json
{
  "matchers": [
    {
      "type": "word",
      "words": ["SUCCESS"],
      "part": "body",
      "case_insensitive": true
    }
  ]
}
```

### Regex Matchers

```json
{
  "matchers": [
    {
      "type": "regex",
      "regex": ["\\d{4}-\\d{2}-\\d{2}"],
      "part": "body"
    }
  ]
}
```

## Troubleshooting

### Template Not Executing
- Check JSON syntax validity
- Verify file path is correct
- Ensure required fields are present

### Matchers Not Matching
- Check response content manually
- Verify matcher type and part
- Test with case_insensitive if needed

### Variable Substitution Not Working
- Ensure variable names match exactly
- Check variable is defined in variables section
- Use `{{variable_name}}` syntax

## Resources

- See `EXPLOIT_TEMPLATES.md` for detailed exploit template guide
- See `VULN_TEMPLATES.md` for detailed validation template guide
- Check example templates in `templates/` directory
