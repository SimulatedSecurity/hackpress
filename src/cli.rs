use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "hackpress")]
#[command(version = crate::constants::VERSION)]
#[command(about = "Open-source WordPress security scanner")]
#[command(long_about = "Hackpress - Open-source WordPress security scanner with exploit templates and vulnerability validation.

Features:
  - WordPress detection and enumeration
  - Plugin and theme version detection
  - Vulnerability database matching
  - General findings (IP, country, server, PHP, CDN, headers)
  - Username enumeration
  - File disclosure detection
  - Password bruteforcing and spraying
  - WAF bypass capabilities
  - Nuclei-style exploit and vulnerability validation templates

Global Options:
  --output <format>    Output format: json, table (default), or markdown
  --verbose           Enable verbose logging
  --threads <num>     Number of concurrent threads (default: 10)
  --waf-bypass        Enable WAF bypass: browser-like headers, request throttling (2-3s delays), referer chain
  --force             Force complete scan even if WordPress is not detected
  --stealth           Stealth mode: minimal footprint, no bruteforcing, no directory enumeration, reduced traffic

Commands:
  scan         Perform comprehensive WordPress security scan
  exploit      Execute exploit template (potentially destructive)
  vuln         Run vulnerability validation template(s) (safe, read-only)
  bruteforce   Perform password bruteforcing attack
  spray        Perform password spraying attack
  update       Update plugin and vulnerability databases
  interactive  Start interactive console mode (similar to msfconsole)

Examples:
  # Basic scan
  hackpress scan https://example.com

  # Scan with verbose output and WAF bypass
  hackpress scan https://example.com --verbose --waf-bypass

  # Run single vulnerability validation template
  hackpress vuln https://example.com --template templates/vulns/example-xss.json

  # Mass vulnerability validation
  hackpress vuln https://example.com --template-dir templates/vulns/ --threads 20

  # Execute exploit template
  hackpress exploit https://example.com --template templates/exploits/example-rce.json

  # Password bruteforcing
  hackpress bruteforce https://example.com --users users.txt --passwords passwords.txt

  # Password spraying
  hackpress spray https://example.com --users users.txt --passwords passwords.txt --rate-limit 2

  # Update databases
  hackpress update

  # Start interactive mode
  hackpress interactive

For more information, visit: https://github.com/simulatedsecurity/hackpress

Version information:
  Use --version to display the current version.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Output format (json, table, markdown)
    #[arg(short, long, default_value = "table", global = true)]
    pub output: String,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Number of concurrent threads
    #[arg(short, long, default_value_t = 10, global = true)]
    pub threads: usize,

    /// Enable WAF bypass: browser-like headers, request throttling (2-3s delays), referer chain
    #[arg(long, global = true)]
    pub waf_bypass: bool,

    /// Force complete scan even if WordPress is not detected
    #[arg(long, global = true)]
    pub force: bool,

    /// Stealth mode: minimal footprint, no bruteforcing, no directory enumeration, reduced traffic
    #[arg(long, global = true)]
    pub stealth: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Main scanning command
    Scan {
        /// Target URL to scan
        url: String,
        /// Enumerate plugins/themes from top database files (plugins-top.txt, themes-top.txt)
        /// Format: --enumerate=plugins,themes or --enumerate=plugins or --enumerate=themes
        #[arg(long, value_delimiter = ',')]
        enumerate: Option<Vec<String>>,
        /// Enumerate plugins/themes from complete database files (plugins.txt, themes.txt)
        /// Format: --enumerate-all=plugins,themes or --enumerate-all=plugins or --enumerate-all=themes
        /// Cannot be used with --enumerate
        #[arg(long, value_delimiter = ',')]
        enumerate_all: Option<Vec<String>>,
    },
    /// Run specific exploit template
    Exploit {
        /// Target URL
        url: String,
        /// Path to exploit template (required)
        #[arg(short, long)]
        template: String,
    },
    /// Run vulnerability validation template(s)
    Vuln {
        /// Target URL
        url: String,
        /// Path to single vulnerability validation template file
        #[arg(short, long)]
        template: Option<String>,
        /// Directory containing vulnerability validation templates (mass execution)
        #[arg(long)]
        template_dir: Option<String>,
    },
    /// Password bruteforcing attack
    Bruteforce {
        /// Target URL
        url: String,
        /// Path to file containing usernames
        #[arg(short, long)]
        users: String,
        /// Path to file containing passwords
        #[arg(short, long)]
        passwords: String,
        /// Type of bruteforcing endpoint (wp-login, xmlrpc, rest-api, custom)
        #[arg(long, default_value = "wp-login")]
        bruteforce_type: String,
        /// Requests per second (default: 10)
        #[arg(long, default_value_t = 10)]
        rate_limit: u64,
        /// Stop on first successful login
        #[arg(long)]
        stop_on_success: bool,
    },
    /// Password spraying attack
    Spray {
        /// Target URL
        url: String,
        /// Path to file containing usernames
        #[arg(short, long)]
        users: String,
        /// Path to file containing passwords
        #[arg(short, long)]
        passwords: String,
        /// Type of bruteforcing endpoint (wp-login, xmlrpc, rest-api, custom)
        #[arg(long, default_value = "wp-login")]
        bruteforce_type: String,
        /// Requests per second (default: 2)
        #[arg(long, default_value_t = 2)]
        rate_limit: u64,
    },
    /// Update plugin/vulnerability databases from official source
    Update,
    /// Start interactive console mode
    Interactive,
}

