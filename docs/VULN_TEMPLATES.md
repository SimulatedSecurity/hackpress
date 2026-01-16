# Vulnerability Validation Templates Guide

This guide provides detailed documentation for creating vulnerability validation templates in hackpress.

## What are Vulnerability Validation Templates?

Vulnerability validation templates are **safe, read-only** checks that validate the presence of vulnerabilities without exploitation. These templates:

- Are non-destructive
- Only validate vulnerability presence
- Can be run in mass execution mode
- Safe to run on production systems (with permission)

## Execution Modes

### Single Template

```bash
# Basic execution
hackpress vuln https://example.com --template templates/vulns/example-xss.json

# With verbose output
hackpress vuln https://example.com --template templates/vulns/example-xss.json --verbose

# With WAF bypass
hackpress vuln https://example.com --template templates/vulns/example-xss.json --waf-bypass

# Output to JSON
hackpress vuln https://example.com --template templates/vulns/example-xss.json --output json
```

### Mass Execution

```bash
# Basic mass execution (default: 10 threads)
hackpress vuln https://example.com --template-dir templates/vulns/

# With custom thread count
hackpress vuln https://example.com --template-dir templates/vulns/ --threads 20

# With output format
hackpress vuln https://example.com --template-dir templates/vulns/ --threads 20 --output json > results.json

# With WAF bypass
hackpress vuln https://example.com --template-dir templates/vulns/ --threads 20 --waf-bypass
```

Runs all `.json` templates in the specified directory concurrently. Each template is executed independently, making this safe for comprehensive vulnerability validation.

## Template Structure

Vulnerability validation templates use the same structure as exploit templates but are designed for validation only.

### Required Fields

```json
{
  "id": "unique-template-id",
  "info": {
    "name": "Template Name",
    "author": ["Author"],
    "severity": "critical|high|medium|low"
  },
  "http": [...]
}
```

### Complete Example

```json
{
  "id": "wordpress-plugin-xss-cve-2023",
  "info": {
    "name": "WordPress Plugin XSS Validation",
    "author": ["hackpress"],
    "severity": "medium",
    "description": "Validates presence of XSS vulnerability in plugin X",
    "reference": ["CVE-2023-XXXXX"],
    "tags": ["wordpress", "xss", "plugin", "validation"]
  },
  "variables": {
    "target": "{{target}}",
    "plugin_path": "/wp-content/plugins/vulnerable-plugin/"
  },
  "http": [
    {
      "method": "GET",
      "path": ["{{plugin_path}}vulnerable-endpoint.php?param=<script>alert('XSS')</script>"],
      "matchers": [
        {
          "type": "word",
          "words": ["<script>alert('XSS')</script>"],
          "part": "body"
        }
      ]
    }
  ]
}
```

## Validation vs Exploitation

### Validation Templates (This Guide)
- **Purpose**: Detect vulnerability presence
- **Safety**: Read-only, non-destructive
- **Use Case**: Security assessment, vulnerability scanning
- **Execution**: Can run multiple templates at once

### Exploit Templates
- **Purpose**: Execute actual exploits
- **Safety**: Potentially destructive
- **Use Case**: Confirmed exploitation, proof of concept
- **Execution**: Single template only

## Common Validation Patterns

### Pattern 1: Reflected XSS

```json
{
  "http": [
    {
      "method": "GET",
      "path": ["/endpoint.php?param=<script>alert(1)</script>"],
      "matchers": [
        {
          "type": "word",
          "words": ["<script>alert(1)</script>"],
          "part": "body"
        }
      ]
    }
  ]
}
```

### Pattern 2: SQL Injection

```json
{
  "http": [
    {
      "method": "GET",
      "path": ["/endpoint.php?id=1'"],
      "matchers": [
        {
          "type": "word",
          "words": ["SQL syntax", "mysql error", "database error"],
          "part": "body",
          "case_insensitive": true
        }
      ]
    }
  ]
}
```

### Pattern 3: Path Traversal

```json
{
  "http": [
    {
      "method": "GET",
      "path": ["/file.php?path=../../../../etc/passwd"],
      "matchers": [
        {
          "type": "word",
          "words": ["root:", "bin:"],
          "part": "body"
        }
      ]
    }
  ]
}
```

### Pattern 4: Information Disclosure

```json
{
  "http": [
    {
      "method": "GET",
      "path": ["/debug.php"],
      "matchers": [
        {
          "type": "word",
          "words": ["PHP Version", "Server API", "Loaded Configuration"],
          "part": "body"
        }
      ]
    }
  ]
}
```

### Pattern 5: Version Detection

```json
{
  "http": [
    {
      "method": "GET",
      "path": ["/readme.txt"],
      "matchers": [
        {
          "type": "regex",
          "regex": ["Version:\\s*([\\d.]+)"],
          "part": "body"
        }
      ]
    }
  ]
}
```

## Matchers for Validation

### Status Code Validation

```json
{
  "type": "status",
  "status": [200, 404]
}
```

### Content Validation

```json
{
  "type": "word",
  "words": ["vulnerable", "error"],
  "part": "body"
}
```

### Regex Validation

```json
{
  "type": "regex",
  "regex": ["error.*\\d{4}"],
  "part": "body"
}
```

### Negative Validation

Ensure vulnerability indicators are NOT present:

```json
{
  "type": "word",
  "words": ["not found", "404"],
  "part": "body",
  "negative": true
}
```

## Integration with Vulnerability Database

Validation templates can be linked to vulnerabilities in the database:

```json
{
  "id": "CVE-2023-XXXXX-validation",
  "info": {
    "name": "CVE-2023-XXXXX Validation",
    "description": "Validates CVE-2023-XXXXX in plugin X"
  }
}
```

## Mass Execution Best Practices

When creating templates for mass execution:

1. **Unique IDs** - Ensure template IDs are unique
2. **Fast Execution** - Keep requests simple and fast
3. **Clear Matchers** - Use specific, reliable matchers
4. **Error Handling** - Templates should handle errors gracefully
5. **No Side Effects** - Ensure templates are truly read-only

## Version-Specific Validation

Validate vulnerabilities in specific versions:

```json
{
  "variables": {
    "target": "{{target}}",
    "plugin_version": "{{plugin_version}}"
  },
  "http": [
    {
      "method": "GET",
      "path": ["/wp-content/plugins/plugin/readme.txt"],
      "matchers": [
        {
          "type": "word",
          "words": ["{{plugin_version}}"],
          "part": "body"
        }
      ]
    }
  ]
}
```

## Safe Testing Methodologies

1. **Read-Only Operations** - Use GET requests when possible
2. **Non-Destructive Payloads** - Use harmless test strings
3. **Error Detection** - Detect errors without causing them
4. **Version Checking** - Check versions before validation
5. **Graceful Failures** - Handle failures without side effects

## Common Validation Scenarios

### Scenario 1: Plugin Vulnerability

```json
{
  "id": "plugin-xss-v1.0",
  "http": [
    {
      "method": "GET",
      "path": ["/wp-content/plugins/plugin/endpoint.php?xss=<script>alert(1)</script>"],
      "matchers": [
        {
          "type": "word",
          "words": ["<script>alert(1)</script>"],
          "part": "body"
        }
      ]
    }
  ]
}
```

### Scenario 2: Theme Vulnerability

```json
{
  "id": "theme-sqli-v2.0",
  "http": [
    {
      "method": "GET",
      "path": ["/wp-content/themes/theme/file.php?id=1'"],
      "matchers": [
        {
          "type": "word",
          "words": ["SQL syntax", "mysql"],
          "part": "body",
          "case_insensitive": true
        }
      ]
    }
  ]
}
```

### Scenario 3: Core Vulnerability

```json
{
  "id": "wp-core-rce-v5.0",
  "http": [
    {
      "method": "POST",
      "path": ["/wp-admin/admin-ajax.php"],
      "body": "action=test&data=payload",
      "matchers": [
        {
          "type": "status",
          "status": [200]
        },
        {
          "type": "word",
          "words": ["executed"],
          "part": "body"
        }
      ]
    }
  ]
}
```

## Output and Results

Validation results include:

- `template_id` - Template identifier
- `name` - Template name
- `severity` - Vulnerability severity
- `matched` - Whether validation matched
- `details` - Additional details

## Best Practices

1. **Clear Naming** - Use descriptive template IDs and names
2. **Accurate Severity** - Match severity to vulnerability impact
3. **References** - Include CVE numbers and advisory links
4. **Documentation** - Explain what is being validated
5. **Testing** - Test templates on known vulnerable systems
6. **Maintenance** - Update templates as vulnerabilities are patched

## Troubleshooting

### Template Not Matching

- Verify vulnerability actually exists
- Check matcher patterns are correct
- Test with verbose output
- Inspect actual response content

### False Positives

- Refine matcher patterns
- Add negative matchers
- Check for version-specific behavior
- Validate with multiple indicators

### Mass Execution Issues

- Check template JSON validity
- Verify no conflicting template IDs
- Ensure templates are read-only
- Monitor resource usage

## Example Templates

See `templates/vulns/` directory for example validation templates.

## Related Documentation

- `TEMPLATE_TUTORIAL.md` - General template creation guide
- `EXPLOIT_TEMPLATES.md` - Exploit template guide
