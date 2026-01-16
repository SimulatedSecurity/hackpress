use crate::models::{
    ScanResults, TechStackInfo, RobotsTxtInfo, WordPressInfo, WordPressConfig,
    DetectedPlugin, DetectedTheme, FoundVulnerability,
    EnumeratedUsername, FileDisclosure
};
use anyhow::Result;
use colored::*;
use std::io::Write;

pub struct OutputFormatter;

impl OutputFormatter {
    // Real-time output helpers - print directly to stdout
    pub fn print_header(target: &str) {
        println!("{}", "=".repeat(80).bright_white());
        println!("{} {}", "Target:".bright_cyan(), target.bright_yellow());
        println!("{}\n", "=".repeat(80).bright_white());
    }

    pub fn print_tech_stack_section(tech: &TechStackInfo) {
        println!("{}", "General Findings".bright_white().bold());
        
        // IP and location information
        if let Some(ref ip) = tech.ip {
            let mut ip_line = format!("  IP: {}", ip.bright_cyan());
            if let Some(ref country) = tech.country {
                ip_line.push_str(&format!(" , {}", country.bright_yellow()));
                if let Some(ref info) = tech.ip_info {
                    ip_line.push_str(&format!(" ({})", info.bright_blue()));
                }
            }
            println!("{}", ip_line);
        }
        
        if let Some(server) = &tech.server {
            println!("  Server: {}", server.bright_cyan());
        }
        if let Some(php) = &tech.php_version {
            println!("  PHP Version: {}", php.bright_cyan());
        }
        if let Some(cdn) = &tech.cdn {
            println!("  CDN: {}", cdn.bright_cyan());
        }
        if !tech.relevant_headers.is_empty() {
            for (name, value) in &tech.relevant_headers {
                println!("  {}: {}", name.bright_cyan(), value.bright_yellow());
            }
        }
        if !tech.security_headers.is_empty() {
            println!("  Security Headers: {}", tech.security_headers.len().to_string().bright_green());
        }
        println!();
    }

    pub fn print_robots_section(robots: &RobotsTxtInfo) {
        println!("{}", "Robots.txt Analysis".bright_white().bold());
        // Display robots.txt content if available
        if let Some(ref content) = robots.content {
            println!("  Content:");
            for line in content.lines() {
                println!("    {}", line);
            }
        }
        if !robots.disallowed.is_empty() {
            println!("  Disallowed paths: {}", robots.disallowed.len());
        }
        if !robots.sitemap.is_empty() {
            println!("  Sitemaps: {}", robots.sitemap.len());
        }
        if !robots.findings.is_empty() {
            for finding in &robots.findings {
                println!("  - {}", finding.bright_yellow());
            }
        }
        println!();
    }

    pub fn print_wordpress_section(wp: &WordPressInfo) {
        println!("{}", "WordPress Detection".bright_white().bold());
        println!("  Detected: {}", if wp.detected { "Yes".bright_green() } else { "No".bright_red() });
        if let Some(version) = &wp.version {
            print!("  Version: {}", version);
            // Check against latest WordPress version
            if let Ok(latest_version) = Self::get_latest_wordpress_version() {
                if Self::compare_wordpress_versions(version, &latest_version) < 0 {
                    println!(" {} (Latest: {})", "OUTDATED".bright_red().bold(), latest_version.bright_green());
                } else {
                    println!(" {} (Latest version)", "UP TO DATE".bright_green());
                }
            } else {
                println!();
            }
        } else {
            println!();
        }
        println!();
    }

    pub fn print_wordpress_config_section(config: &WordPressConfig) {
        println!("{}", "WordPress Configuration".bright_white().bold());
        println!("  XML-RPC: {}", if config.xmlrpc_enabled { "Enabled".bright_yellow() } else { "Disabled".bright_green() });
        println!("  Comments: {}", if config.comments_allowed { "Allowed".bright_yellow() } else { "Not Allowed".bright_green() });
        println!("  User Signup: {}", if config.signup_enabled { "Enabled".bright_yellow() } else { "Disabled".bright_green() });
        if config.login_path_validated {
            if let Some(ref path) = config.login_path {
                println!("  Login Path: {} (non-standard)", path.bright_yellow());
            } else {
                println!("  Login Path: {} (standard)", "/wp-login.php".bright_green());
            }
        } else {
            println!("  Login Path: {} (not validated)", "Unknown".bright_yellow());
        }
        if let Some(ref disclosed_path) = config.path_disclosure {
            println!("  Path Disclosure: {} {}", "VULNERABLE".bright_red().bold(), disclosed_path.bright_red());
        }
        println!();
    }

    fn get_latest_wordpress_version() -> Result<String> {
        use reqwest::blocking;
        use serde_json::Value;
        use crate::constants;
        
        let client = blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(constants::WORDPRESS_API_TIMEOUT))
            .build()?;
        
        let response = client.get(constants::WORDPRESS_VERSION_API_URL)
            .send()?;
        
        let json: Value = response.json()?;
        
        // Get first offer which should be the latest version
        if let Some(offers) = json.get("offers").and_then(|v| v.as_array()) {
            if let Some(first_offer) = offers.first() {
                if let Some(version) = first_offer.get("version").and_then(|v| v.as_str()) {
                    return Ok(version.to_string());
                }
            }
        }
        
        anyhow::bail!("Could not extract latest version from API response")
    }

    fn compare_wordpress_versions(v1: &str, v2: &str) -> i32 {
        // Parse versions like "6.9", "6.9.1", "6.8.3" into comparable parts
        let v1_parts: Vec<u32> = v1.split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let v2_parts: Vec<u32> = v2.split('.')
            .filter_map(|s| s.parse().ok())
            .collect();

        // Compare each part
        let max_len = v1_parts.len().max(v2_parts.len());
        for i in 0..max_len {
            let v1_part = v1_parts.get(i).copied().unwrap_or(0);
            let v2_part = v2_parts.get(i).copied().unwrap_or(0);
            
            if v1_part < v2_part {
                return -1;
            } else if v1_part > v2_part {
                return 1;
            }
        }
        
        0 // Equal
    }

    pub fn print_plugins_section_header() {
        println!("{}", "Plugins".bright_white().bold());
    }

    pub fn print_plugin_item(plugin: &DetectedPlugin, verbose: bool) {
        let mut plugin_line = format!("  - {} (v{})", plugin.name.bright_cyan(), plugin.version);
        
        // Check against latest WordPress plugin version from SVN
        if plugin.version != "unknown" {
            if verbose {
                eprintln!("     [verbose] Checking plugin version for slug: {}", plugin.slug);
            }
            if let Some(latest_version) = crate::detection::WordPressDetector::get_latest_plugin_version_from_svn(&plugin.slug, verbose) {
                if verbose {
                    eprintln!("     [verbose] Comparing detected version {} with latest SVN version {}", plugin.version, latest_version);
                }
                let comparison = crate::detection::WordPressDetector::compare_wordpress_versions(&plugin.version, &latest_version);
                if verbose {
                    eprintln!("     [verbose] Version comparison result: {} (< 0 means outdated)", comparison);
                }
                if comparison < 0 {
                    plugin_line.push_str(&format!(" - {} (Latest: {})", "OUTDATED".bright_red().bold(), latest_version.bright_green()));
                } else {
                    plugin_line.push_str(&format!(" - {}", "UP TO DATE".bright_green()));
                }
            } else if verbose {
                eprintln!("     [verbose] Could not retrieve latest version from SVN for plugin slug: {}", plugin.slug);
            }
        }
        println!("{}", plugin_line);
    }

    pub fn print_themes_section_header() {
        println!("{}", "Themes".bright_white().bold());
    }

    pub fn print_theme_item(theme: &DetectedTheme, verbose: bool) {
        let mut theme_line = format!("  - {}", theme.name.bright_cyan());
        if theme.active {
            theme_line.push_str(&format!(" {}", "[ACTIVE]".bright_green().bold()));
            if verbose {
                eprintln!("     [verbose] Processing ACTIVE theme: {} (slug: {})", theme.name, theme.slug);
            }
        }
        if theme.version != "unknown" {
            theme_line.push_str(&format!(" (v{})", theme.version));
            if verbose {
                eprintln!("     [verbose] Theme version detected: {}", theme.version);
            }
        }
        if let Some(ref author) = theme.author {
            theme_line.push_str(&format!(" by {}", author.bright_blue()));
        }
        // Check against latest WordPress theme version from SVN (using slug from /themes/<slug>)
        if theme.version != "unknown" {
            // Use the slug directly from /themes/<slug> path
            if verbose {
                eprintln!("     [verbose] Checking theme version for slug: {}", theme.slug);
            }
            if let Some(latest_version) = crate::detection::WordPressDetector::get_latest_theme_version_from_svn(&theme.slug, verbose) {
                if verbose {
                    eprintln!("     [verbose] Comparing detected version {} with latest SVN version {}", theme.version, latest_version);
                }
                let comparison = crate::detection::WordPressDetector::compare_wordpress_versions(&theme.version, &latest_version);
                if verbose {
                    eprintln!("     [verbose] Version comparison result: {} (< 0 means outdated)", comparison);
                }
                if comparison < 0 {
                    theme_line.push_str(&format!(" - {} (Latest: {})", "OUTDATED".bright_red().bold(), latest_version.bright_green()));
                } else {
                    theme_line.push_str(&format!(" - {}", "UP TO DATE".bright_green()));
                }
            } else if verbose {
                eprintln!("     [verbose] Could not retrieve latest version from SVN for theme slug: {}", theme.slug);
            }
        }
        println!("{}", theme_line);
    }

    pub fn print_vulnerability_item(vuln: &FoundVulnerability, index: usize) {
        let severity_color = match vuln.severity.as_str() {
            "critical" => vuln.severity.bright_red().bold(),
            "high" => vuln.severity.bright_red(),
            "medium" => vuln.severity.bright_yellow(),
            "low" => vuln.severity.bright_blue(),
            _ => vuln.severity.white(),
        };
        
        // Format: 1. <slug> [severity]
        let component_display = if vuln.affected_component == "wordpress-core" {
            "wordpress-core"
        } else {
            &vuln.affected_component
        };
        println!("  {}. {} [{}]", index + 1, component_display.bright_cyan(), severity_color);
        
        // Indented details
        println!("    - description: {}", vuln.description);
        if !vuln.affected_versions.is_empty() {
            println!("    - affected versions: {}", vuln.affected_versions.join(", "));
        }
        if !vuln.references.is_empty() {
            println!("    - references:");
            for ref_url in &vuln.references {
                println!("      {}", ref_url.bright_blue().underline());
            }
        }
    }

    pub fn print_vulnerabilities_section_header() {
        println!("{}", "Vulnerabilities".bright_white().bold());
    }

    pub fn print_usernames_section_header() {
        println!("{}", "Enumerated Usernames".bright_white().bold());
    }

    pub fn print_username_item(username: &EnumeratedUsername) {
        println!("  - {} ({})", username.username.bright_yellow(), username.source.bright_cyan());
    }

    pub fn print_file_disclosures_section_header() {
        println!("{}", "File Disclosures".bright_white().bold());
    }

    pub fn print_file_disclosure_item(disclosure: &FileDisclosure) {
        let status = if disclosure.accessible {
            "ACCESSIBLE".bright_red().bold()
        } else {
            "FOUND".bright_yellow()
        };
        println!("  [{}] {} ({})", status, disclosure.path.bright_cyan(), disclosure.file_type);
    }

    // Helper method to print plugin item - header is printed by caller when first plugin is found
    pub fn print_plugin_item_real_time(plugin: &DetectedPlugin, is_first: bool, verbose: bool) {
        if is_first {
            Self::print_plugins_section_header();
        }
        Self::print_plugin_item(plugin, verbose);
    }

    // Helper method to print theme item - header is printed by caller when first theme is found
    pub fn print_theme_item_real_time(theme: &DetectedTheme, is_first: bool, verbose: bool) {
        if is_first {
            Self::print_themes_section_header();
        }
        Self::print_theme_item(theme, verbose);
    }

    // Helper method to print vulnerability item - header is printed by caller when first vuln is found
    pub fn print_vulnerability_item_real_time(vuln: &FoundVulnerability, index: usize, is_first: bool) {
        if is_first {
            Self::print_vulnerabilities_section_header();
            println!();
        }
        Self::print_vulnerability_item(vuln, index);
    }

    // Helper method to print username item - header is printed by caller when first username is found
    pub fn print_username_item_real_time(username: &EnumeratedUsername, is_first: bool) {
        if is_first {
            Self::print_usernames_section_header();
        }
        Self::print_username_item(username);
    }

    // Helper method to print file disclosure item - header is printed by caller when first disclosure is found
    pub fn print_file_disclosure_item_real_time(disclosure: &FileDisclosure, is_first: bool) {
        if is_first {
            Self::print_section_end(); // Padding before File Disclosures section (same as other sections)
            Self::print_file_disclosures_section_header();
        }
        Self::print_file_disclosure_item(disclosure);
    }

    pub fn print_section_end() {
        println!();
    }

    /// Print progress bar with status and current number
    pub fn print_progress_bar(current: usize, total: usize, label: &str) {
        let percentage = if total > 0 {
            (current as f64 / total as f64 * 100.0) as usize
        } else {
            0
        };
        // Use \r to overwrite the same line
        print!("\r  {} [{}/{}] {}%", label.bright_cyan(), current.to_string().bright_yellow(), total.to_string().bright_yellow(), percentage.to_string().bright_green());
        std::io::stdout().flush().ok();
    }

    /// Print newline after progress bar is complete
    pub fn print_progress_complete() {
        println!();
    }

    pub fn format(results: &ScanResults, format: &str, verbose: bool) -> String {
        match format {
            "json" => Self::format_json(results),
            "markdown" => Self::format_markdown(results, verbose),
            _ => Self::format_table(results, verbose),
        }
    }

    fn format_json(results: &ScanResults) -> String {
        serde_json::to_string_pretty(results).unwrap_or_else(|_| "{}".to_string())
    }

    fn format_table(results: &ScanResults, verbose: bool) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("{}\n", "=".repeat(80).bright_white()));
        output.push_str(&format!("{} {}\n", "Target:".bright_cyan(), results.target.bright_yellow()));
        output.push_str(&format!("{}\n\n", "=".repeat(80).bright_white()));

        // General Findings
        if let Some(tech) = &results.tech_stack {
            output.push_str(&format!("{}\n", "General Findings".bright_white().bold()));
            
            // IP and location information
            if let Some(ref ip) = tech.ip {
                let mut ip_line = format!("  IP: {}", ip.bright_cyan());
                if let Some(ref country) = tech.country {
                    ip_line.push_str(&format!(" , {}", country.bright_yellow()));
                    if let Some(ref info) = tech.ip_info {
                        ip_line.push_str(&format!(" ({})", info.bright_blue()));
                    }
                }
                output.push_str(&format!("{}\n", ip_line));
            }
            
            if let Some(server) = &tech.server {
                output.push_str(&format!("  Server: {}\n", server.bright_cyan()));
            }
            if let Some(php) = &tech.php_version {
                output.push_str(&format!("  PHP Version: {}\n", php.bright_cyan()));
            }
            if let Some(cdn) = &tech.cdn {
                output.push_str(&format!("  CDN: {}\n", cdn.bright_cyan()));
            }
            if !tech.relevant_headers.is_empty() {
                for (name, value) in &tech.relevant_headers {
                    output.push_str(&format!("  {}: {}\n", name.bright_cyan(), value.bright_yellow()));
                }
            }
            if !tech.security_headers.is_empty() {
                output.push_str(&format!("  Security Headers: {}\n", tech.security_headers.len().to_string().bright_green()));
            }
            output.push('\n');
        }

        // Robots.txt
        if let Some(robots) = &results.robots_txt {
            output.push_str(&format!("{}\n", "Robots.txt Analysis".bright_white().bold()));
            if !robots.disallowed.is_empty() {
                output.push_str(&format!("  Disallowed paths: {}\n", robots.disallowed.len()));
            }
            if !robots.sitemap.is_empty() {
                output.push_str(&format!("  Sitemaps: {}\n", robots.sitemap.len()));
            }
            if !robots.findings.is_empty() {
                for finding in &robots.findings {
                    output.push_str(&format!("  - {}\n", finding.bright_yellow()));
                }
            }
            if let Some(ref content) = robots.content {
                output.push_str("  Content:\n");
                for line in content.lines() {
                    output.push_str(&format!("    {}\n", line));
                }
            }
            output.push('\n');
        }

        // WordPress Info
        if let Some(wp) = &results.wordpress {
            output.push_str(&format!("{}\n", "WordPress Detection".bright_white().bold()));
            output.push_str(&format!("  Detected: {}\n", if wp.detected { "Yes".bright_green() } else { "No".bright_red() }));
            if let Some(version) = &wp.version {
                let mut version_line = format!("  Version: {}", version);
                // Check against latest WordPress version
                if let Ok(latest_version) = Self::get_latest_wordpress_version() {
                    if Self::compare_wordpress_versions(version, &latest_version) < 0 {
                        version_line.push_str(&format!(" {} (Latest: {})", "OUTDATED".bright_red().bold(), latest_version.bright_green()));
                    } else {
                        version_line.push_str(&format!(" {} (Latest version)", "UP TO DATE".bright_green()));
                    }
                }
                output.push_str(&format!("{}\n", version_line));
            }
            output.push('\n');
        }

        // WordPress Configuration
        if let Some(config) = &results.wordpress_config {
            output.push_str(&format!("{}\n", "WordPress Configuration".bright_white().bold()));
            output.push_str(&format!("  XML-RPC: {}\n", if config.xmlrpc_enabled { "Enabled".bright_yellow() } else { "Disabled".bright_green() }));
            output.push_str(&format!("  Comments: {}\n", if config.comments_allowed { "Allowed".bright_yellow() } else { "Not Allowed".bright_green() }));
            output.push_str(&format!("  User Signup: {}\n", if config.signup_enabled { "Enabled".bright_yellow() } else { "Disabled".bright_green() }));
            if config.login_path_validated {
                if let Some(ref path) = config.login_path {
                    output.push_str(&format!("  Login Path: {} (non-standard)\n", path.bright_yellow()));
                } else {
                    output.push_str(&format!("  Login Path: {} (standard)\n", "/wp-login.php".bright_green()));
                }
            } else {
                output.push_str(&format!("  Login Path: {} (not validated)\n", "Unknown".bright_yellow()));
            }
            if let Some(ref disclosed_path) = config.path_disclosure {
                output.push_str(&format!("  Path Disclosure: {} {}\n", "VULNERABLE".bright_red().bold(), disclosed_path.bright_red()));
            }
            output.push('\n');
        }

        // Plugins
        if !results.plugins.is_empty() {
            output.push_str(&format!("{}\n", "Plugins".bright_white().bold()));
            for plugin in &results.plugins {
                let mut plugin_line = format!("  - {} (v{})", plugin.name.bright_cyan(), plugin.version);
                // Check against latest WordPress plugin version from SVN
                if plugin.version != "unknown" {
                    if let Some(latest_version) = crate::detection::WordPressDetector::get_latest_plugin_version_from_svn(&plugin.slug, verbose) {
                        let comparison = crate::detection::WordPressDetector::compare_wordpress_versions(&plugin.version, &latest_version);
                        if comparison < 0 {
                            plugin_line.push_str(&format!(" - {} (Latest: {})", "OUTDATED".bright_red().bold(), latest_version.bright_green()));
                        } else {
                            plugin_line.push_str(&format!(" - {}", "UP TO DATE".bright_green()));
                        }
                    }
                }
                output.push_str(&format!("{}\n", plugin_line));
            }
            output.push('\n');
        }

        // Themes
        if !results.themes.is_empty() {
            output.push_str(&format!("{}\n", "Themes".bright_white().bold()));
            for theme in &results.themes {
                let mut theme_line = format!("  - {}", theme.name.bright_cyan());
                if theme.active {
                    theme_line.push_str(&format!(" {}", "[ACTIVE]".bright_green().bold()));
                }
                if theme.version != "unknown" {
                    theme_line.push_str(&format!(" (v{})", theme.version));
                }
                if let Some(ref author) = theme.author {
                    theme_line.push_str(&format!(" by {}", author.bright_blue()));
                }
                // Check against latest WordPress theme version from SVN (using slug from /themes/<slug>)
                if theme.version != "unknown" {
                    // Use the slug directly from /themes/<slug> path
                    if let Some(latest_version) = crate::detection::WordPressDetector::get_latest_theme_version_from_svn(&theme.slug, verbose) {
                        if crate::detection::WordPressDetector::compare_wordpress_versions(&theme.version, &latest_version) < 0 {
                            theme_line.push_str(&format!(" - {} (Latest: {})", "OUTDATED".bright_red().bold(), latest_version.bright_green()));
                        } else {
                            theme_line.push_str(&format!(" - {}", "UP TO DATE".bright_green()));
                        }
                    }
                }
                output.push_str(&format!("{}\n", theme_line));
            }
            output.push('\n');
        }

        // Vulnerabilities
        if !results.vulnerabilities.is_empty() {
            output.push_str(&format!("{}\n", "Vulnerabilities".bright_white().bold()));
            for (idx, vuln) in results.vulnerabilities.iter().enumerate() {
                let severity_color = match vuln.severity.as_str() {
                    "critical" => vuln.severity.bright_red().bold(),
                    "high" => vuln.severity.bright_red(),
                    "medium" => vuln.severity.bright_yellow(),
                    "low" => vuln.severity.bright_blue(),
                    _ => vuln.severity.white(),
                };
                
                let component_display = if vuln.affected_component == "wordpress-core" {
                    "wordpress-core"
                } else {
                    &vuln.affected_component
                };
                output.push_str(&format!("  {}. {} [{}]\n", idx + 1, component_display.bright_cyan(), severity_color));
                
                // Indented details
                output.push_str(&format!("    - description: {}\n", vuln.description));
                if !vuln.affected_versions.is_empty() {
                    output.push_str(&format!("    - affected versions: {}\n", vuln.affected_versions.join(", ")));
                }
                if !vuln.references.is_empty() {
                    output.push_str("    - references:\n");
                    for ref_url in &vuln.references {
                        output.push_str(&format!("      {}\n", ref_url.bright_blue().underline()));
                    }
                }
            }
            output.push('\n');
        }

        // Vulnerability Validations
        if !results.vuln_validations.is_empty() {
            output.push_str(&format!("{}\n", "Vulnerability Validations".bright_white().bold()));
            for validation in &results.vuln_validations {
                let status = if validation.matched {
                    "MATCHED".bright_green().bold()
                } else {
                    "NOT MATCHED".bright_red()
                };
                output.push_str(&format!("  [{}] {} - {}\n", status, validation.template_id.bright_cyan(), validation.name));
                if let Some(details) = &validation.details {
                    output.push_str(&format!("    {}\n", details));
                }
            }
            output.push('\n');
        }

        // Exploit Results
        if !results.exploit_results.is_empty() {
            output.push_str(&format!("{}\n", "Exploit Results".bright_white().bold()));
            for exploit in &results.exploit_results {
                let status = if exploit.success {
                    "SUCCESS".bright_green().bold()
                } else {
                    "FAILED".bright_red()
                };
                output.push_str(&format!("  [{}] {} - {}\n", status, exploit.template_id.bright_cyan(), exploit.name));
                if let Some(details) = &exploit.details {
                    output.push_str(&format!("    {}\n", details));
                }
            }
            output.push('\n');
        }

        // Usernames
        if !results.usernames.is_empty() {
            output.push_str(&format!("{}\n", "Enumerated Usernames".bright_white().bold()));
            for username_info in &results.usernames {
                output.push_str(&format!("  - {} ({})\n", username_info.username.bright_yellow(), username_info.source.bright_cyan()));
            }
            output.push('\n');
        }

        // File Disclosures
        if !results.file_disclosures.is_empty() {
            output.push_str(&format!("{}\n", "File Disclosures".bright_white().bold()));
            for disclosure in &results.file_disclosures {
                let status = if disclosure.accessible {
                    "ACCESSIBLE".bright_red().bold()
                } else {
                    "FOUND".bright_yellow()
                };
                output.push_str(&format!("  [{}] {} ({})\n", status, disclosure.path.bright_cyan(), disclosure.file_type));
            }
            output.push('\n');
        }

        // Bruteforce Results
        if let Some(bf) = &results.bruteforce_results {
            output.push_str(&format!("{}\n", "Bruteforce Results".bright_white().bold()));
            output.push_str(&format!("  Total Attempts: {}\n", bf.total_attempts));
            output.push_str(&format!("  Failed: {}\n", bf.failed_count));
            if !bf.successful.is_empty() {
                output.push_str(&format!("  {} Successful Logins:\n", bf.successful.len().to_string().bright_green().bold()));
                for cred in &bf.successful {
                    output.push_str(&format!("    {} / {} ({})\n", cred.username.bright_green(), cred.password.bright_green(), cred.endpoint));
                }
            }
            if bf.captcha_detected {
                output.push_str(&format!("  {} CAPTCHA detected\n", "WARNING:".bright_yellow().bold()));
            }
            if bf.account_lockouts > 0 {
                output.push_str(&format!("  {} Account lockouts detected\n", bf.account_lockouts.to_string().bright_yellow()));
            }
            output.push('\n');
        }

        output
    }

    fn format_markdown(results: &ScanResults, verbose: bool) -> String {
        let mut output = String::new();
        
        output.push_str(&format!("# Scan Results\n\n"));
        output.push_str(&format!("**Target:** {}\n\n", results.target));

        // General Findings
        if let Some(tech) = &results.tech_stack {
            output.push_str(&format!("## General Findings\n\n"));
            
            // IP and location information
            if let Some(ref ip) = tech.ip {
                let mut ip_line = format!("- **IP:** {}", ip);
                if let Some(ref country) = tech.country {
                    ip_line.push_str(&format!(" , {}", country));
                    if let Some(ref info) = tech.ip_info {
                        ip_line.push_str(&format!(" ({})", info));
                    }
                }
                output.push_str(&format!("{}\n", ip_line));
            }
            
            if let Some(server) = &tech.server {
                output.push_str(&format!("- **Server:** {}\n", server));
            }
            if let Some(php) = &tech.php_version {
                output.push_str(&format!("- **PHP Version:** {}\n", php));
            }
            if let Some(cdn) = &tech.cdn {
                output.push_str(&format!("- **CDN:** {}\n", cdn));
            }
            if !tech.relevant_headers.is_empty() {
                for (name, value) in &tech.relevant_headers {
                    output.push_str(&format!("- **{}:** {}\n", name, value));
                }
            }
            output.push('\n');
        }

        // WordPress Info
        if let Some(wp) = &results.wordpress {
            output.push_str(&format!("## WordPress\n\n"));
            output.push_str(&format!("- **Detected:** {}\n", wp.detected));
            if let Some(version) = &wp.version {
                let mut version_line = format!("- **Version:** {}", version);
                // Check against latest WordPress version
                if let Ok(latest_version) = Self::get_latest_wordpress_version() {
                    if Self::compare_wordpress_versions(version, &latest_version) < 0 {
                        version_line.push_str(&format!(" ⚠️ OUTDATED (Latest: {})", latest_version));
                    } else {
                        version_line.push_str(" ✓ UP TO DATE");
                    }
                }
                output.push_str(&format!("{}\n", version_line));
            }
            output.push('\n');
        }

        // WordPress Configuration
        if let Some(config) = &results.wordpress_config {
            output.push_str(&format!("## WordPress Configuration\n\n"));
            output.push_str(&format!("- **XML-RPC:** {}\n", if config.xmlrpc_enabled { "Enabled" } else { "Disabled" }));
            output.push_str(&format!("- **Comments:** {}\n", if config.comments_allowed { "Allowed" } else { "Not Allowed" }));
            output.push_str(&format!("- **User Signup:** {}\n", if config.signup_enabled { "Enabled" } else { "Disabled" }));
            if config.login_path_validated {
                if let Some(ref path) = config.login_path {
                    output.push_str(&format!("- **Login Path:** {} (non-standard)\n", path));
                } else {
                    output.push_str(&format!("- **Login Path:** {} (standard)\n", "/wp-login.php"));
                }
            } else {
                output.push_str(&format!("- **Login Path:** Unknown (not validated)\n"));
            }
            if let Some(ref disclosed_path) = config.path_disclosure {
                output.push_str(&format!("- **Path Disclosure:** ⚠️ VULNERABLE - {}\n", disclosed_path));
            }
            output.push('\n');
        }

        // Plugins
        if !results.plugins.is_empty() {
            output.push_str(&format!("## Plugins\n\n"));
            for plugin in &results.plugins {
                let mut plugin_line = format!("- **{}** (v{})", plugin.name, plugin.version);
                // Check against latest WordPress plugin version from SVN
                if plugin.version != "unknown" {
                    if let Some(latest_version) = crate::detection::WordPressDetector::get_latest_plugin_version_from_svn(&plugin.slug, verbose) {
                        if crate::detection::WordPressDetector::compare_wordpress_versions(&plugin.version, &latest_version) < 0 {
                            plugin_line.push_str(&format!(" - ⚠️ OUTDATED (Latest: {})", latest_version));
                        } else {
                            plugin_line.push_str(" - ✓ UP TO DATE");
                        }
                    }
                }
                output.push_str(&format!("{}\n", plugin_line));
            }
            output.push('\n');
        }

        // Themes
        if !results.themes.is_empty() {
            output.push_str(&format!("## Themes\n\n"));
            for theme in &results.themes {
                let mut theme_line = format!("- **{}**", theme.name);
                if theme.active {
                    theme_line.push_str(" **[ACTIVE]**");
                }
                if theme.version != "unknown" {
                    theme_line.push_str(&format!(" (v{})", theme.version));
                }
                if let Some(ref author) = theme.author {
                    theme_line.push_str(&format!(" by {}", author));
                }
                // Check against latest WordPress theme version from SVN (using slug from /themes/<slug>)
                if theme.version != "unknown" {
                    // Use the slug directly from /themes/<slug> path
                    if let Some(latest_version) = crate::detection::WordPressDetector::get_latest_theme_version_from_svn(&theme.slug, verbose) {
                        if crate::detection::WordPressDetector::compare_wordpress_versions(&theme.version, &latest_version) < 0 {
                            theme_line.push_str(&format!(" - ⚠️ OUTDATED (Latest: {})", latest_version));
                        } else {
                            theme_line.push_str(" - ✓ UP TO DATE");
                        }
                    }
                }
                output.push_str(&format!("{}\n", theme_line));
            }
            output.push('\n');
        }

        // Vulnerabilities
        if !results.vulnerabilities.is_empty() {
            output.push_str(&format!("## Vulnerabilities\n\n"));
            for (idx, vuln) in results.vulnerabilities.iter().enumerate() {
                let component_display = if vuln.affected_component == "wordpress-core" {
                    "wordpress-core"
                } else {
                    &vuln.affected_component
                };
                output.push_str(&format!("{}. **{}** [{}]\n\n", idx + 1, component_display, vuln.severity));
                
                // Indented details
                output.push_str(&format!("   - **description:** {}\n", vuln.description));
                if !vuln.affected_versions.is_empty() {
                    output.push_str(&format!("   - **affected versions:** {}\n", vuln.affected_versions.join(", ")));
                }
                if !vuln.references.is_empty() {
                    output.push_str("   - **references:**\n");
                    for ref_url in &vuln.references {
                        output.push_str(&format!("     - [{}]({})\n", ref_url, ref_url));
                    }
                }
                output.push('\n');
            }
        }

        // Usernames
        if !results.usernames.is_empty() {
            output.push_str(&format!("## Enumerated Usernames\n\n"));
            for username_info in &results.usernames {
                output.push_str(&format!("- **{}** ({})\n", username_info.username, username_info.source));
            }
            output.push('\n');
        }

        // File Disclosures
        if !results.file_disclosures.is_empty() {
            output.push_str(&format!("## File Disclosures ({})\n\n", results.file_disclosures.len()));
            for disclosure in &results.file_disclosures {
                output.push_str(&format!("- **{}** ({}) - {}\n", disclosure.path, disclosure.file_type, if disclosure.accessible { "ACCESSIBLE" } else { "Found" }));
            }
            output.push('\n');
        }

        output
    }
}
