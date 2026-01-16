use anyhow::{Context, Result};
use crate::http_client::HttpClient;
use crate::models::{DetectedPlugin, DetectedTheme, WordPressInfo, WordPressConfig};
use crate::constants;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub struct WordPressDetector;

struct ThemeInfo {
    name: Option<String>,
    version: Option<String>,
    author: Option<String>,
    text_domain: Option<String>, // Used as slug for SVN lookup
}

impl Default for ThemeInfo {
    fn default() -> Self {
        ThemeInfo {
            name: None,
            version: None,
            author: None,
            text_domain: None,
        }
    }
}

impl WordPressDetector {
    pub fn detect_wordpress(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Option<WordPressInfo>> {
        let mut detected = false;
        let mut version: Option<String> = None;

        // Method 1: Check wp-links-opml.php (VERY RELIABLE - contains version in XML comment)
        if verbose {
            eprintln!("     [verbose] Trying wp-links-opml.php...");
        }
        if let Ok(response) = client.get("/wp-links-opml.php", None) {
            let status = response.status().as_u16();
            let headers = Self::extract_response_headers(&response);
            let text = response.text().context("Failed to read wp-links-opml.php")?;
            
            // Check for errors after reading body
            if status >= 400 {
                if let Some(error_info) = crate::error_detection::ErrorDetector::detect_response_error_with_status(status, &headers, &text) {
                    crate::error_detection::ErrorDetector::alert_error(&error_info, verbose);
                }
                if verbose {
                    eprintln!("     [verbose] wp-links-opml.php returned status {}", status);
                }
            }
            
            if status < 400 {
                // Look for XML comment with generator: <!-- generator="WordPress/6.9" -->
                let generator_re = Regex::new(r#"(?i)<!--\s*generator\s*=\s*["']WordPress/([\d]+\.[\d]+(?:\.[\d]+)?)["']\s*-->"#).unwrap();
                if let Some(caps) = generator_re.captures(&text) {
                    if let Some(v) = caps.get(1) {
                        let ver_str = v.as_str().to_string();
                        // Validate it's a proper version (at least X.Y format)
                        if ver_str.contains('.') && ver_str.matches('.').count() <= 2 {
                            version = Some(ver_str.clone());
                            if verbose {
                                eprintln!("     [verbose] Found WordPress version {} from wp-links-opml.php", &ver_str);
                            }
                            let wp_info = WordPressInfo { version: version.clone(), detected: true };
                            // Display as found (real-time output)
                            if use_realtime_output {
                                crate::output::OutputFormatter::print_wordpress_section(&wp_info);
                            }
                            return Ok(Some(wp_info));
                        }
                    }
                }
                // Also check if file exists and contains WordPress-specific content
                // Only set detected if we find clear WordPress indicators
                if text.contains("opml") && (text.contains("WordPress") || text.contains("generator")) {
                    detected = true;
                    if verbose {
                        eprintln!("     [verbose] wp-links-opml.php accessible (WordPress detected, but version not found in comment)");
                    }
                }
            }
        } else if verbose {
            eprintln!("     [verbose] wp-links-opml.php not accessible");
        }

        // Method 2: Check wp-includes/version.php (MOST RELIABLE - direct source)
        if verbose {
            eprintln!("     [verbose] Trying wp-includes/version.php...");
        }
        if let Ok(response) = client.get("/wp-includes/version.php", None) {
            let status = response.status().as_u16();
            let headers = Self::extract_response_headers(&response);
            let text = response.text().context("Failed to read version.php")?;
            
            // Check for errors after reading body
            if status >= 400 {
                if let Some(error_info) = crate::error_detection::ErrorDetector::detect_response_error_with_status(status, &headers, &text) {
                    crate::error_detection::ErrorDetector::alert_error(&error_info, verbose);
                }
                if verbose {
                    eprintln!("     [verbose] wp-includes/version.php returned status {}", status);
                }
            }
            
            if status < 400 {
                // Look for $wp_version = 'X.X' or 'X.X.X';
                // Pattern must have at least one dot (X.Y format) to avoid matching single digits
                let version_re = Regex::new(r#"(?i)\$wp_version\s*=\s*['"]([\d]+\.[\d]+(?:\.[\d]+)?)['"]"#).unwrap();
                if let Some(caps) = version_re.captures(&text) {
                    if let Some(v) = caps.get(1) {
                        let ver_str = v.as_str().to_string();
                        // Validate it's a proper version (at least X.Y format)
                        if ver_str.contains('.') && ver_str.matches('.').count() <= 2 {
                            version = Some(ver_str.clone());
                            if verbose {
                                eprintln!("     [verbose] Found WordPress version {} from version.php", &ver_str);
                            }
                            let wp_info = WordPressInfo { version: version.clone(), detected: true };
                            // Display as found (real-time output)
                            if use_realtime_output {
                                crate::output::OutputFormatter::print_wordpress_section(&wp_info);
                            }
                            return Ok(Some(wp_info));
                        }
                    }
                }
                // Only set detected if we find clear WordPress indicators in the file
                if text.contains("$wp_version") || text.contains("wp_version") || text.contains("WORDPRESS") {
                    detected = true;
                    if verbose {
                        eprintln!("     [verbose] wp-includes/version.php accessible and contains WordPress indicators (but version not found or invalid format)");
                    }
                } else if verbose {
                    eprintln!("     [verbose] wp-includes/version.php accessible but doesn't contain WordPress indicators");
                }
            }
        } else if verbose {
            eprintln!("     [verbose] wp-includes/version.php not accessible");
        }

        // Method 3: Check for WordPress generator meta tag (VERY RELIABLE)
        if version.is_none() {
            if verbose {
                eprintln!("     [verbose] Trying homepage meta generator tag...");
            }
            if let Ok(response) = client.get("", None) {
                let status = response.status().as_u16();
                let headers = Self::extract_response_headers(&response);
                let text = response.text().context("Failed to read response")?;
                
                // Check for errors
                if status >= 400 {
                    if let Some(error_info) = crate::error_detection::ErrorDetector::detect_response_error_with_status(status, &headers, &text) {
                        crate::error_detection::ErrorDetector::alert_error(&error_info, verbose);
                    }
                }
                
                if status < 500 {  // Continue even with 4xx as homepage might redirect
                    // Try standard meta tag format: <meta name="generator" content="WordPress 6.9" />
                    let generator_re = Regex::new(r#"(?i)<meta\s+name=["']generator["']\s+content=["']([^"']+)["']"#).unwrap();
                    if let Some(caps) = generator_re.captures(&text) {
                        if let Some(content) = caps.get(1) {
                            let content = content.as_str();
                            if content.to_lowercase().contains("wordpress") {
                                detected = true;  // Only set detected if we actually find WordPress in generator
                                version = Self::extract_wp_version(content);
                                if let Some(ref v) = version {
                                    if verbose {
                                        eprintln!("     [verbose] Found WordPress version {} from meta generator", v);
                                    }
                                    let wp_info = WordPressInfo { version: version.clone(), detected: true };
                                    if use_realtime_output {
                                        crate::output::OutputFormatter::print_wordpress_section(&wp_info);
                                    }
                                    return Ok(Some(wp_info));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Method 4: Check readme.html (RELIABLE)
        if version.is_none() {
            if verbose {
                eprintln!("     [verbose] Trying readme.html...");
            }
            if let Ok(response) = client.get("/readme.html", None) {
                if response.status().is_success() {
                    let text = response.text().context("Failed to read readme.html")?;
                    // Only set detected if we find WordPress-specific content
                    if text.to_lowercase().contains("wordpress") {
                        detected = true;
                        // Look for version pattern in readme - must have at least X.Y format
                        let version_re = Regex::new(r"(?i)version\s+([\d]+\.[\d]+(?:\.[\d]+)?)").unwrap();
                        if let Some(caps) = version_re.captures(&text) {
                            if let Some(v) = caps.get(1) {
                                let ver_str = v.as_str().to_string();
                                // Validate it's a proper version format
                                if ver_str.contains('.') && ver_str.matches('.').count() <= 2 {
                                    version = Some(ver_str.clone());
                                    if verbose {
                                        eprintln!("     [verbose] Found WordPress version {} from readme.html", &ver_str);
                                    }
                                    // Will be printed at end if use_realtime_output
                                }
                            }
                        }
                    } else if verbose {
                        eprintln!("     [verbose] readme.html accessible but doesn't contain WordPress indicators");
                    }
                }
            }
        }

        // Method 5: Check RSS feed (RELIABLE)
        if version.is_none() {
            if verbose {
                eprintln!("     [verbose] Trying RSS feed...");
            }
            if let Ok(response) = client.get("/feed/", None) {
                if response.status().is_success() {
                    let text = response.text().context("Failed to read RSS feed")?;
                    let generator_re = Regex::new(r#"(?i)<generator[^>]*>([^<]+)</generator>"#).unwrap();
                    if let Some(caps) = generator_re.captures(&text) {
                        if let Some(content) = caps.get(1) {
                            let content = content.as_str();
                            if content.to_lowercase().contains("wordpress") {
                                detected = true;  // Only set detected if we actually find WordPress in generator
                                version = Self::extract_wp_version(content);
                                if let Some(ref v) = version {
                                    if verbose {
                                        eprintln!("     [verbose] Found WordPress version {} from RSS feed", v);
                                    }
                                    // Will be printed at end if use_realtime_output
                                }
                            }
                        }
                    } else if verbose {
                        eprintln!("     [verbose] RSS feed accessible but doesn't contain WordPress generator tag");
                    }
                }
            }
        }

        // Fallback: Check for wp-content directory (detection only, no version)
        // Only set detected if we can confirm it's actually a WordPress wp-content directory
        if !detected {
            if let Ok(response) = client.get("/wp-content/", None) {
                let status = response.status().as_u16();
                if status != 404 && status < 500 {
                    // Check if response contains WordPress-specific indicators
                    if let Ok(text) = response.text() {
                        let text_lower = text.to_lowercase();
                        // Look for WordPress-specific content in directory listing or response
                        if text_lower.contains("wp-content") || 
                           text_lower.contains("themes") || 
                           text_lower.contains("plugins") ||
                           text_lower.contains("wordpress") {
                            detected = true;
                            if verbose {
                                eprintln!("     [verbose] wp-content/ directory accessible and contains WordPress indicators");
                            }
                        } else if verbose {
                            eprintln!("     [verbose] wp-content/ directory accessible but doesn't contain WordPress indicators");
                        }
                    } else if verbose {
                        eprintln!("     [verbose] wp-content/ directory accessible but couldn't read response body");
                    }
                }
            }
        }

        // Print WordPress section if using real-time output (always show, even if not detected)
        if use_realtime_output {
            crate::output::OutputFormatter::print_wordpress_section(&WordPressInfo {
                version: version.clone(),
                detected,
            });
        }

        if detected {
            Ok(Some(WordPressInfo { version, detected: true }))
        } else {
            Ok(None)
        }
    }

    pub fn enumerate_plugins(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Vec<DetectedPlugin>> {
        Self::enumerate_plugins_internal(client, verbose, use_realtime_output, false)
    }
    
    pub fn enumerate_plugins_stealth(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Vec<DetectedPlugin>> {
        Self::enumerate_plugins_internal(client, verbose, use_realtime_output, true)
    }
    
    fn enumerate_plugins_internal(client: &HttpClient, verbose: bool, use_realtime_output: bool, stealth: bool) -> Result<Vec<DetectedPlugin>> {
        let mut plugins = vec![];
        let mut found_plugins = HashSet::new();
        let mut plugin_versions_from_urls: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        // Method 1: Detect plugins passively from web content (HTML/CSS/JS) - MOST RELIABLE
        if verbose {
            eprintln!("     [verbose] Trying to detect plugins from CSS/JS file paths in HTML...");
        }
        if let Ok(response) = client.get("", None) {
            if response.status().is_success() {
                let text = response.text().context("Failed to read homepage")?;
                
                // Look for plugin paths in CSS/JS links: /wp-content/plugins/{plugin-name}/
                // First, try to match URLs with ?ver= parameter (most reliable for version)
                let plugin_with_ver_re = Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"']*)/wp-content/plugins/([^/"']+)/[^"']*\?ver=([\d.]+)"#).unwrap();
                for caps in plugin_with_ver_re.captures_iter(&text) {
                    if let Some(plugin_slug_match) = caps.get(2) {
                        let plugin_slug = plugin_slug_match.as_str().to_string();
                        if let Some(version_match) = caps.get(3) {
                            let version = version_match.as_str().to_string();
                            found_plugins.insert(plugin_slug.clone());
                            plugin_versions_from_urls.insert(plugin_slug.clone(), version);
                        }
                    }
                }
                
                // Then, match plugin paths without ?ver= (for slug detection)
                let plugin_path_re = Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"']*)/wp-content/plugins/([^/"']+)/"#).unwrap();
                for caps in plugin_path_re.captures_iter(&text) {
                    if let Some(plugin_slug_match) = caps.get(2) {
                        let plugin_slug = plugin_slug_match.as_str().to_string();
                        if !found_plugins.contains(&plugin_slug) {
                            found_plugins.insert(plugin_slug.clone());
                            
                            // Check if the full URL (including query string) contains ?ver= parameter
                            if let Some(full_url_match) = caps.get(0) {
                                let full_url = full_url_match.as_str();
                                if let Some(version) = Self::extract_version_from_url(full_url) {
                                    plugin_versions_from_urls.insert(plugin_slug.clone(), version);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try directory listing (skip in stealth mode to reduce traffic)
        if !stealth {
            if let Ok(response) = client.get("/wp-content/plugins/", None) {
                if response.status().is_success() {
                    let text = response.text().context("Failed to read plugins directory")?;
                    let link_re = Regex::new(r#"<a\s+href=['"]([^'"]+)['"]"#).unwrap();
                    
                    for caps in link_re.captures_iter(&text) {
                        if let Some(href) = caps.get(1) {
                            let href = href.as_str();
                            if let Some(plugin_slug) = Self::extract_plugin_slug(href) {
                                found_plugins.insert(plugin_slug);
                            }
                        }
                    }
                }
            }
        } else if verbose {
            eprintln!("     [verbose] Stealth mode: skipping plugin directory listing");
        }

        // Now process all found plugins and get their versions
        for plugin_slug in &found_plugins {
            let mut version: Option<String> = None;
            
            if stealth {
                // In stealth mode: only use version from ?ver= parameter
                if let Some(ver) = plugin_versions_from_urls.get(plugin_slug) {
                    version = Some(ver.clone());
                }
            } else {
                // In normal mode: first try readme.txt, then fall back to ?ver= parameter
                if let Ok(readme_version) = Self::get_plugin_version_from_readme(client, plugin_slug) {
                    if let Some(v) = readme_version {
                        version = Some(v);
                    }
                }
                
                // Fall back to ?ver= parameter if readme.txt didn't work
                if version.is_none() {
                    if let Some(ver) = plugin_versions_from_urls.get(plugin_slug) {
                        version = Some(ver.clone());
                    }
                }
            }
            
            let version_value = version.unwrap_or_else(|| "unknown".to_string());
            let plugin = DetectedPlugin {
                slug: plugin_slug.clone(),
                name: plugin_slug.clone(),
                version: version_value.clone(),
            };
            plugins.push(plugin.clone());
            
            // Display as found (real-time output)
            if use_realtime_output {
                crate::output::OutputFormatter::print_plugin_item_real_time(&plugin, plugins.len() == 1, verbose);
            }
        }

        // If not stealth mode, get latest versions from SVN for plugins with known versions
        if !stealth {
            for plugin in &mut plugins {
                if plugin.version != "unknown" {
                    if let Some(latest_version) = Self::get_latest_plugin_version_from_svn(&plugin.slug, verbose) {
                        // Store latest version info (could be used for vulnerability checking)
                        if verbose {
                            eprintln!("     [verbose] Latest SVN version for {}: {}", plugin.slug, latest_version);
                        }
                    }
                }
            }
        }

        if use_realtime_output && !plugins.is_empty() {
            crate::output::OutputFormatter::print_section_end();
        }

        Ok(plugins)
    }

    pub fn enumerate_themes(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Vec<DetectedTheme>> {
        Self::enumerate_themes_internal(client, verbose, use_realtime_output, false)
    }
    
    pub fn enumerate_themes_stealth(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Vec<DetectedTheme>> {
        Self::enumerate_themes_internal(client, verbose, use_realtime_output, true)
    }
    
    fn enumerate_themes_internal(client: &HttpClient, verbose: bool, use_realtime_output: bool, stealth: bool) -> Result<Vec<DetectedTheme>> {
        let mut themes = vec![];
        let mut found_themes = HashSet::new();
        let mut active_theme_slug: Option<String> = None;

        // Method 1: Detect from CSS/JS file paths in HTML source (MOST RELIABLE)
        if verbose {
            eprintln!("     [verbose] Trying to detect themes from CSS/JS file paths in HTML...");
        }
        if let Ok(response) = client.get("", None) {
            if response.status().is_success() {
                let text = response.text().context("Failed to read homepage")?;
                
                // Look for theme paths in CSS/JS links: /wp-content/themes/{theme-name}/
                let theme_path_re = Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"']*)/wp-content/themes/([^/"']+)/"#).unwrap();
                
                for caps in theme_path_re.captures_iter(&text) {
                    if let Some(theme_slug_match) = caps.get(2) {
                        let theme_slug = theme_slug_match.as_str().to_string();
                        if !found_themes.contains(&theme_slug) {
                            found_themes.insert(theme_slug.clone());
                            // First theme found is likely the active one
                            if active_theme_slug.is_none() {
                                active_theme_slug = Some(theme_slug.clone());
                            }
                            
                            // Get detailed theme info from style.css
                            let theme_info = Self::get_theme_info(client, &theme_slug).ok().unwrap_or_default();
                            let theme = DetectedTheme {
                                slug: theme_slug.clone(),
                                name: theme_info.name.unwrap_or(theme_slug.clone()),
                                version: theme_info.version.unwrap_or_else(|| "unknown".to_string()),
                                active: active_theme_slug.as_ref().map_or(false, |s| s == &theme_slug),
                                author: theme_info.author.clone(),
                                text_domain: theme_info.text_domain.clone(),
                            };
                            themes.push(theme.clone());
                            // Display as found (real-time output)
                            if use_realtime_output {
                                crate::output::OutputFormatter::print_theme_item_real_time(&theme, themes.len() == 1, verbose);
                            }
                        }
                    }
                }
            }
        }

        // Method 2: Try directory listing (fallback) - skip in stealth mode
        if !stealth {
            if let Ok(response) = client.get("/wp-content/themes/", None) {
            if response.status().is_success() {
                let text = response.text().context("Failed to read themes directory")?;
                let link_re = Regex::new(r#"<a\s+href=['"]([^'"]+)['"]"#).unwrap();
                
                for caps in link_re.captures_iter(&text) {
                    if let Some(href) = caps.get(1) {
                        let href = href.as_str();
                        if let Some(theme_slug) = Self::extract_theme_slug(href) {
                            if !found_themes.contains(&theme_slug) {
                                found_themes.insert(theme_slug.clone());
                                
                                // Get detailed theme info from style.css
                                let theme_info = Self::get_theme_info(client, &theme_slug).ok().unwrap_or_default();
                                let theme = DetectedTheme {
                                    slug: theme_slug.clone(),
                                    name: theme_info.name.unwrap_or(theme_slug.clone()),
                                    version: theme_info.version.unwrap_or_else(|| "unknown".to_string()),
                                    active: active_theme_slug.as_ref().map_or(false, |s| s == &theme_slug),
                                    author: theme_info.author.clone(),
                                    text_domain: theme_info.text_domain.clone(),
                                };
                                themes.push(theme.clone());
                                // Display as found (real-time output)
                                if use_realtime_output {
                                    crate::output::OutputFormatter::print_theme_item_real_time(&theme, themes.len() == 1, verbose);
                                }
                            }
                        }
                    }
                }
            }
            }
        } else if verbose {
            eprintln!("     [verbose] Stealth mode: skipping theme directory listing");
        }

        if use_realtime_output && !themes.is_empty() {
            crate::output::OutputFormatter::print_section_end();
        }

        Ok(themes)
    }

    fn extract_wp_version(generator: &str) -> Option<String> {
        // Extract version from strings like "WordPress 6.9" or "WordPress 6.9.1"
        // This regex properly captures the version number after "wordpress"
        let re = Regex::new(r"(?i)wordpress\s+([\d]+\.[\d]+(?:\.[\d]+)?)").unwrap();
        if let Some(caps) = re.captures(generator) {
            if let Some(version_match) = caps.get(1) {
                return Some(version_match.as_str().to_string());
            }
        }
        None
    }

    fn extract_plugin_slug(href: &str) -> Option<String> {
        // Extract plugin slug from href like "/wp-content/plugins/plugin-name/"
        let re = Regex::new(r"/wp-content/plugins/([^/]+)/?").unwrap();
        re.captures(href)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }

    fn extract_theme_slug(href: &str) -> Option<String> {
        // Extract theme slug from href like "/wp-content/themes/theme-name/"
        let re = Regex::new(r"/wp-content/themes/([^/]+)/?").unwrap();
        re.captures(href)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }

    fn get_plugin_version_from_readme(client: &HttpClient, plugin_slug: &str) -> Result<Option<String>> {
        let path = format!("/wp-content/plugins/{}/readme.txt", plugin_slug);
        let response = client.get(&path, None)?;
        
        if !response.status().is_success() {
            return Ok(None);
        }

        let text = response.text().context("Failed to read readme.txt")?;
        let version_re = Regex::new(r"(?i)^\s*stable\s+tag:\s*([\d.]+)").unwrap();
        
        for line in text.lines() {
            if let Some(caps) = version_re.captures(line) {
                if let Some(version) = caps.get(1) {
                    return Ok(Some(version.as_str().to_string()));
                }
            }
        }

        Ok(None)
    }
    
    fn extract_version_from_url(url: &str) -> Option<String> {
        // Extract version from ?ver=X.X.X parameter in URLs
        // Example: /wp-content/plugins/woocommerce-gateway-authorize-net-cim/assets/css/blocks/wc-authorize-net-cim-checkout-block.css?ver=3.10.14
        let ver_re = Regex::new(r#"(?i)\?ver=([\d]+\.[\d]+(?:\.[\d]+)?)"#).unwrap();
        if let Some(caps) = ver_re.captures(url) {
            if let Some(version_match) = caps.get(1) {
                let ver_str = version_match.as_str().to_string();
                // Validate version format
                if ver_str.contains('.') && ver_str.matches('.').count() <= 2 {
                    if ver_str.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        return Some(ver_str);
                    }
                }
            }
        }
        None
    }
    
    pub fn get_latest_plugin_version_from_svn(plugin_slug: &str, verbose: bool) -> Option<String> {
        use crate::constants;
        // Fetch WordPress plugin SVN listing using slug
        let url = format!("{}/{}/tags/", constants::WORDPRESS_PLUGINS_SVN_BASE, plugin_slug);
        
        if verbose {
            eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
            eprintln!("     [verbose] [SVN] Checking plugin version for slug: {}", plugin_slug);
            eprintln!("     [verbose] [SVN] Making request to: {}", url);
        }
        
        // Create a client with a valid User-Agent specifically for SVN requests to avoid 403 Forbidden
        let client = match reqwest::blocking::Client::builder()
            .user_agent(constants::SVN_USER_AGENT)
            .timeout(std::time::Duration::from_secs(constants::DEFAULT_HTTP_TIMEOUT))
            .build() {
            Ok(client) => client,
            Err(e) => {
                if verbose {
                    eprintln!("     [verbose] [SVN] ✗ Failed to create HTTP client: {}", e);
                    eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                }
                return None;
            }
        };
        
        if let Ok(response) = client.get(&url).send() {
            let status = response.status();
            if verbose {
                eprintln!("     [verbose] SVN response status: {}", status);
            }
            
            if status.is_success() {
                if let Ok(text) = response.text() {
                    if verbose {
                        eprintln!("     [verbose] SVN response received ({} bytes)", text.len());
                    }
                    // Parse SVN directory listing for version numbers
                    // SVN directory listings show directories like "1.0.0/", "1.1.0/", etc.
                    let version_patterns = vec![
                        // Pattern 1: href="X.Y.Z/" or href='X.Y.Z/'
                        r#"href=["']([\d]+\.[\d]+(?:\.[\d]+)?)/["']"#,
                        // Pattern 2: <a href="X.Y.Z/"> or <a href='X.Y.Z/'>
                        r#"<a[^>]+href=["']([\d]+\.[\d]+(?:\.[\d]+)?)/["']"#,
                        // Pattern 3: Directory entry format in SVN listing
                        r#"([\d]+\.[\d]+(?:\.[\d]+)?)/\s*$"#,  // X.Y.Z/ at end of line
                    ];
                    
                    let mut versions = Vec::new();
                    
                    for pattern in version_patterns {
                        let version_re = Regex::new(pattern).unwrap();
                        for caps in version_re.captures_iter(&text) {
                            if let Some(ver_match) = caps.get(1) {
                                let ver_str = ver_match.as_str().to_string();
                                // Validate version format: must have at least one dot and max two dots
                                if ver_str.contains('.') && ver_str.matches('.').count() <= 2 {
                                    // Make sure it's a valid version number (only digits and dots)
                                    if ver_str.chars().all(|c| c.is_ascii_digit() || c == '.') {
                                        // Ensure it starts and ends with a digit
                                        if ver_str.chars().next().map_or(false, |c| c.is_ascii_digit()) &&
                                           ver_str.chars().last().map_or(false, |c| c.is_ascii_digit()) {
                                            versions.push(ver_str);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Remove duplicates
                    versions.sort();
                    versions.dedup();
                    
                    // Sort versions and return the latest
                    if !versions.is_empty() {
                        versions.sort_by(|a, b| {
                            // Version comparison (X.Y.Z format)
                            let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
                            let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();
                            
                            // Compare each part
                            for (a_part, b_part) in a_parts.iter().zip(b_parts.iter()) {
                                match a_part.cmp(b_part) {
                                    std::cmp::Ordering::Equal => continue,
                                    other => return other,
                                }
                            }
                            // If all parts compared are equal, longer version is newer
                            a_parts.len().cmp(&b_parts.len())
                        });
                        
                        let latest = versions.last().cloned();
                        if verbose {
                            if let Some(ref latest_ver) = latest {
                                eprintln!("     [verbose] [SVN] ✓ Latest version found: {}", latest_ver);
                                eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                            } else {
                                eprintln!("     [verbose] [SVN] ✗ No latest version determined");
                                eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                            }
                        }
                        return latest;
                    } else if verbose {
                        eprintln!("     [verbose] [SVN] ✗ No valid versions found in SVN listing");
                        eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                    }
                } else if verbose {
                    eprintln!("     [verbose] [SVN] ✗ Failed to read SVN response text");
                    eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                }
            } else if verbose {
                eprintln!("     [verbose] [SVN] ✗ Request failed with status: {}", status);
                eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
            }
        } else if verbose {
            eprintln!("     [verbose] [SVN] ✗ Failed to make request to SVN URL");
            eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
        }
        
        None
    }


    fn get_theme_info(client: &HttpClient, theme_slug: &str) -> Result<ThemeInfo> {
        let path = format!("/wp-content/themes/{}/style.css", theme_slug);
        let response = client.get(&path, None)?;
        
        if !response.status().is_success() {
            return Ok(ThemeInfo::default());
        }

        let text = response.text().context("Failed to read style.css")?;
        let mut theme_info = ThemeInfo::default();
        
        // Parse WordPress theme header (first ~20 lines)
        for line in text.lines().take(30) {
            let line_lower = line.to_lowercase();
            
            // Theme Name
            if line_lower.contains("theme name:") {
                let name_re = Regex::new(r"(?i)^\s*theme\s+name:\s*(.+)$").unwrap();
                if let Some(caps) = name_re.captures(line) {
                    if let Some(name_match) = caps.get(1) {
                        theme_info.name = Some(name_match.as_str().trim().to_string());
                    }
                }
            }
            
            // Version
            if line_lower.contains("version:") && theme_info.version.is_none() {
                let version_re = Regex::new(r"(?i)^\s*version:\s*([\d.]+)").unwrap();
                if let Some(caps) = version_re.captures(line) {
                    if let Some(version_match) = caps.get(1) {
                        theme_info.version = Some(version_match.as_str().to_string());
                    }
                }
            }
            
            // Author
            if line_lower.contains("author:") {
                let author_re = Regex::new(r"(?i)^\s*author:\s*(.+)$").unwrap();
                if let Some(caps) = author_re.captures(line) {
                    if let Some(author_match) = caps.get(1) {
                        theme_info.author = Some(author_match.as_str().trim().to_string());
                    }
                }
            }
            
            // Text Domain (used as slug for SVN)
            if line_lower.contains("text domain:") {
                let text_domain_re = Regex::new(r"(?i)^\s*text\s+domain:\s*(.+)$").unwrap();
                if let Some(caps) = text_domain_re.captures(line) {
                    if let Some(text_domain_match) = caps.get(1) {
                        theme_info.text_domain = Some(text_domain_match.as_str().trim().to_string());
                    }
                }
            }
        }

        Ok(theme_info)
    }

    pub fn compare_wordpress_versions(v1: &str, v2: &str) -> i32 {
        let v1_parts: Vec<u32> = v1.split('.').filter_map(|s| s.parse().ok()).collect();
        let v2_parts: Vec<u32> = v2.split('.').filter_map(|s| s.parse().ok()).collect();
        
        for (v1_part, v2_part) in v1_parts.iter().zip(v2_parts.iter()) {
            match v1_part.cmp(v2_part) {
                std::cmp::Ordering::Less => return -1,
                std::cmp::Ordering::Greater => return 1,
                std::cmp::Ordering::Equal => continue,
            }
        }
        
        // If all parts compared are equal, compare lengths
        match v1_parts.len().cmp(&v2_parts.len()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Equal => 0,
        }
    }

    pub fn get_latest_theme_version_from_svn(theme_slug: &str, verbose: bool) -> Option<String> {
        use crate::constants;
        // Fetch WordPress theme SVN listing using slug from /themes/<slug>
        let url = format!("{}/{}/", constants::WORDPRESS_THEMES_SVN_BASE, theme_slug);
        
        if verbose {
            eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
            eprintln!("     [verbose] [SVN] Checking theme version for slug: {}", theme_slug);
            eprintln!("     [verbose] [SVN] Making request to: {}", url);
        }
        
        // Create a client with a valid User-Agent specifically for SVN requests to avoid 403 Forbidden
        let client = match reqwest::blocking::Client::builder()
            .user_agent(constants::SVN_USER_AGENT)
            .timeout(std::time::Duration::from_secs(constants::DEFAULT_HTTP_TIMEOUT))
            .build() {
            Ok(client) => client,
            Err(e) => {
                if verbose {
                    eprintln!("     [verbose] [SVN] ✗ Failed to create HTTP client: {}", e);
                    eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                }
                return None;
            }
        };
        
        if let Ok(response) = client.get(&url).send() {
            let status = response.status();
            if verbose {
                eprintln!("     [verbose] SVN response status: {}", status);
            }
            
            if status.is_success() {
                if let Ok(text) = response.text() {
                    if verbose {
                        eprintln!("     [verbose] SVN response received ({} bytes)", text.len());
                    }
                    // Parse SVN directory listing for version numbers
                    // SVN directory listings show directories like "1.0.0/", "1.1.0/", etc.
                    // Look for directory entries that match version format X.Y or X.Y.Z
                    let version_patterns = vec![
                        // Pattern 1: href="X.Y.Z/" or href='X.Y.Z/'
                        r#"href=["']([\d]+\.[\d]+(?:\.[\d]+)?)/["']"#,
                        // Pattern 2: <a href="X.Y.Z/"> or <a href='X.Y.Z/'>
                        r#"<a[^>]+href=["']([\d]+\.[\d]+(?:\.[\d]+)?)/["']"#,
                        // Pattern 3: Directory entry format in SVN listing
                        r#"([\d]+\.[\d]+(?:\.[\d]+)?)/\s*$"#,  // X.Y.Z/ at end of line
                    ];
                    
                    let mut versions = Vec::new();
                    
                    for pattern in version_patterns {
                        let version_re = Regex::new(pattern).unwrap();
                        for caps in version_re.captures_iter(&text) {
                            if let Some(ver_match) = caps.get(1) {
                                let ver_str = ver_match.as_str().to_string();
                                // Validate version format: must have at least one dot and max two dots
                                if ver_str.contains('.') && ver_str.matches('.').count() <= 2 {
                                    // Make sure it's a valid version number (only digits and dots)
                                    if ver_str.chars().all(|c| c.is_ascii_digit() || c == '.') {
                                        // Ensure it starts and ends with a digit
                                        if ver_str.chars().next().map_or(false, |c| c.is_ascii_digit()) &&
                                           ver_str.chars().last().map_or(false, |c| c.is_ascii_digit()) {
                                            versions.push(ver_str);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Remove duplicates
                    versions.sort();
                    versions.dedup();
                    
                    // Sort versions and return the latest
                    if !versions.is_empty() {
                        versions.sort_by(|a, b| {
                            // Version comparison (X.Y.Z format)
                            let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
                            let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();
                            
                            // Compare each part
                            for (a_part, b_part) in a_parts.iter().zip(b_parts.iter()) {
                                match a_part.cmp(b_part) {
                                    std::cmp::Ordering::Equal => continue,
                                    other => return other,
                                }
                            }
                            // If all parts compared are equal, longer version is newer
                            a_parts.len().cmp(&b_parts.len())
                        });
                        
                        let latest = versions.last().cloned();
                        if verbose {
                            if let Some(ref latest_ver) = latest {
                                eprintln!("     [verbose] [SVN] ✓ Latest version found: {}", latest_ver);
                                eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                            } else {
                                eprintln!("     [verbose] [SVN] ✗ No latest version determined");
                                eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                            }
                        }
                        return latest;
                    } else if verbose {
                        eprintln!("     [verbose] [SVN] ✗ No valid versions found in SVN listing");
                        eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                    }
                } else if verbose {
                    eprintln!("     [verbose] [SVN] ✗ Failed to read SVN response text");
                    eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
                }
            } else if verbose {
                eprintln!("     [verbose] [SVN] ✗ Request failed with status: {}", status);
                eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
            }
        } else if verbose {
            eprintln!("     [verbose] [SVN] ✗ Failed to make request to SVN URL");
            eprintln!("     [verbose] ════════════════════════════════════════════════════════════");
        }
        
        None
    }
    
    pub fn check_wordpress_config(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<(Option<WordPressConfig>, bool)> {
        let mut xmlrpc_enabled = false;
        let mut comments_allowed = false;
        let mut signup_enabled = false;
        let login_path: Option<String>;
        
        // Check XML-RPC
        if verbose {
            eprintln!("     [verbose] Checking XML-RPC...");
        }
        if let Ok(response) = client.get("/xmlrpc.php", None) {
            let status = response.status().as_u16();
            if status == 200 {
                if let Ok(text) = response.text() {
                    // XML-RPC typically responds with "XML-RPC server accepts POST requests only" or similar
                    if text.contains("XML-RPC") || text.contains("xmlrpc") || text.contains("Fault") {
                        xmlrpc_enabled = true;
                        if verbose {
                            eprintln!("     [verbose] ✓ XML-RPC is enabled");
                        }
                    }
                }
            } else if verbose {
                eprintln!("     [verbose] XML-RPC check returned status: {}", status);
            }
        } else if verbose {
            eprintln!("     [verbose] XML-RPC endpoint not accessible");
        }
        
        // Check comments (try to post a comment or check comment form)
        if verbose {
            eprintln!("     [verbose] Checking if comments are allowed...");
        }
        // Try to access a post/page and check for comment form
        if let Ok(response) = client.get("", None) {
            if response.status().is_success() {
                if let Ok(text) = response.text() {
                    // Look for comment form indicators
                    if text.contains("comment-form") || 
                       text.contains("comment_form") ||
                       text.contains("post-comment") ||
                       (text.contains("comment") && text.contains("textarea")) {
                        comments_allowed = true;
                        if verbose {
                            eprintln!("     [verbose] ✓ Comments appear to be allowed");
                        }
                    } else if verbose {
                        eprintln!("     [verbose] Comments form not found on homepage");
                    }
                }
            }
        }
        
        // Check signup (try /wp-signup.php or check registration link)
        if verbose {
            eprintln!("     [verbose] Checking if user signup is enabled...");
        }
        if let Ok(response) = client.get("/wp-signup.php", None) {
            let status = response.status().as_u16();
            if status == 200 {
                if let Ok(text) = response.text() {
                    // Check if signup page is accessible (not just a redirect to login)
                    if text.contains("signup") || text.contains("register") || text.contains("Create") {
                        signup_enabled = true;
                        if verbose {
                            eprintln!("     [verbose] ✓ User signup appears to be enabled");
                        }
                    }
                }
            } else if verbose {
                eprintln!("     [verbose] Signup check returned status: {}", status);
            }
        } else if verbose {
            eprintln!("     [verbose] Signup endpoint not accessible");
        }
        
        // Also check homepage for registration link
        if !signup_enabled {
            if let Ok(response) = client.get("", None) {
                if response.status().is_success() {
                    if let Ok(text) = response.text() {
                        if text.contains("wp-register.php") || 
                           text.contains("wp-signup.php") ||
                           (text.contains("register") && text.contains("href")) {
                            signup_enabled = true;
                            if verbose {
                                eprintln!("     [verbose] ✓ User signup link found on homepage");
                            }
                        }
                    }
                }
            }
        }
        
        // Check login path
        if verbose {
            eprintln!("     [verbose] Checking login path...");
        }
        let login_paths = vec![
            "/wp-login.php",
            "/wp-login/",
            "/wp-admin/",
            "/wp-admin.php",
            "/login/",
            "/admin/",
            "/secret/",
            "/administration/",
            "/login",
        ];
        
        let standard_path = "/wp-login.php".to_string();
        let mut found_path: Option<String> = None;
        let mut standard_path_valid = false;
        
        // Helper function to check if content is actually a WordPress login page
        fn is_wordpress_login_page(text: &str) -> bool {
            let text_lower = text.to_lowercase();
            
            // Must have multiple indicators to avoid false positives
            let mut indicators = 0;
            
            // WordPress-specific login indicators
            if text_lower.contains("wp-login") || text_lower.contains("wp_login") {
                indicators += 2; // Strong indicator
            }
            if text_lower.contains("user_login") || text_lower.contains("user-login") {
                indicators += 2; // Strong indicator
            }
            if text_lower.contains("log in") || text_lower.contains("login") {
                indicators += 1;
            }
            if text_lower.contains("password") && text_lower.contains("username") {
                indicators += 1;
            }
            if text_lower.contains("name=\"log\"") || text_lower.contains("id=\"user_login\"") {
                indicators += 2; // Strong indicator - form field names
            }
            if text_lower.contains("name=\"pwd\"") || text_lower.contains("id=\"user_pass\"") {
                indicators += 2; // Strong indicator - password field
            }
            if text_lower.contains("wp-submit") || text_lower.contains("wp-submit") {
                indicators += 2; // Strong indicator - submit button
            }
            if text_lower.contains("action=\"") && (text_lower.contains("wp-login") || text_lower.contains("login")) {
                indicators += 2; // Strong indicator - form action
            }
            
            // Check for false positives - exclude common non-login pages
            if text_lower.contains("404") && text_lower.contains("not found") {
                return false; // 404 page
            }
            if text_lower.contains("403") && text_lower.contains("forbidden") {
                return false; // 403 page
            }
            if text_lower.contains("index of") || text_lower.contains("directory listing") {
                return false; // Directory listing
            }
            
            // Need at least 3 indicators to be confident it's a login page
            indicators >= 3
        }
        
        // Track WAF blocking responses (403/406/415) for WAF detection
        let mut waf_block_count = 0;
        let mut total_checked = 0;
        
        // First check standard path
        if let Ok(response) = client.get(&standard_path, None) {
            let status = response.status().as_u16();
            total_checked += 1;
            
            // Track WAF blocking responses (403, 406, 415)
            if status == 403 || status == 406 || status == 415 {
                waf_block_count += 1;
            }
            
            if status == 200 {
                if let Ok(text) = response.text() {
                    // Check if it's actually a login page by content, not just status code
                    if is_wordpress_login_page(&text) {
                        standard_path_valid = true;
                        if verbose {
                            eprintln!("     [verbose] Standard login path {} is accessible and contains login form", standard_path);
                        }
                    } else if verbose {
                        eprintln!("     [verbose] Standard login path {} returned 200 but content doesn't match login page", standard_path);
                    }
                }
            } else if verbose {
                eprintln!("     [verbose] Standard login path {} returned status: {}", standard_path, status);
            }
        } else if verbose {
            eprintln!("     [verbose] Standard login path {} not accessible", standard_path);
        }
        
        // Check alternative paths only if standard path is not valid
        
        if !standard_path_valid {
            for path in &login_paths {
                if path == &standard_path {
                    continue; // Already checked
                }
                
                if let Ok(response) = client.get(path, None) {
                    let status = response.status().as_u16();
                    total_checked += 1;
                    
                    // Track WAF blocking responses (403, 406, 415)
                    if status == 403 || status == 406 || status == 415 {
                        waf_block_count += 1;
                    }
                    
                    // Check both status code AND content
                    if status == 200 {
                        if let Ok(text) = response.text() {
                            // Verify content is actually a login page
                            if is_wordpress_login_page(&text) {
                                found_path = Some(path.to_string());
                                if verbose {
                                    eprintln!("     [verbose] ✓ Found login page at: {} (verified by content)", path);
                                }
                                break;
                            } else if verbose {
                                eprintln!("     [verbose] Path {} returned 200 but content doesn't match login page", path);
                            }
                        }
                    } else if verbose {
                        eprintln!("     [verbose] Path {} returned status: {}", path, status);
                    }
                } else if verbose {
                    eprintln!("     [verbose] Path {} not accessible", path);
                }
            }
        }
        
        // Check if we're being blocked by WAF (multiple 403/406/415 responses)
        // If at least 3 paths return WAF blocking status, it's likely WAF blocking
        let waf_detected = waf_block_count >= 3 && total_checked >= 3;
        
        if waf_detected {
            use colored::*;
            eprintln!("{} WAF detected (Imunify/ModSecurity suspected): {} out of {} login path checks returned HTTP 403/406/415", 
                "⚠".bright_red().bold(),
                waf_block_count,
                total_checked);
            eprintln!("   Uniform blocking behavior detected - stopping scan early to avoid further blocks.");
            eprintln!("   WAF is actively blocking requests. Consider using --waf-bypass flag for browser-like behavior.");
        }
        
        // Set login_path based on what we found
        let login_path_validated = standard_path_valid || found_path.is_some();
        
        if standard_path_valid {
            // Standard path is valid, login_path stays None (will be reported as standard)
            login_path = None;
        } else {
            // Use found_path if available, otherwise None
            login_path = found_path;
        }
        
        // Check for path disclosure in /wp-includes/rss.php
        let mut path_disclosure: Option<String> = None;
        if verbose {
            eprintln!("     [verbose] Checking for path disclosure...");
        }
        if let Ok(response) = client.get("/wp-includes/rss.php", None) {
            let status = response.status().as_u16();
            // Path disclosure often appears in error responses (400, 500, etc.)
            if status >= 400 {
                if let Ok(text) = response.text() {
                    // Look for common path disclosure patterns
                    // PHP errors often show full paths like: /var/www/html/wp-includes/rss.php
                    // or Windows paths like: C:\xampp\htdocs\wp-includes\rss.php
                    let path_patterns = vec![
                        (r"(?i)(?:warning|error|fatal|notice).*?in\s+(/[\w/\\-]+\.php)", "Unix path"),
                        (r"(?i)(?:warning|error|fatal|notice).*?in\s+([A-Z]:\\[^\s]+\.php)", "Windows path"),
                        (r"(?i)(?:file|path):\s*(/[\w/\\-]+\.php)", "File path"),
                        (r"(?i)(?:file|path):\s+([A-Z]:\\[^\s]+\.php)", "Windows file path"),
                        (r"(/var/www[^\s]+\.php)", "Common web path"),
                        (r"(/home/[^\s]+\.php)", "Home directory path"),
                        (r"(C:\\xampp[^\s]+\.php)", "XAMPP path"),
                    ];
                    
                    for (pattern, _desc) in path_patterns {
                        if let Ok(re) = Regex::new(pattern) {
                            if let Some(captures) = re.captures(&text) {
                                if let Some(matched_path) = captures.get(1) {
                                    let disclosed_path = matched_path.as_str().to_string();
                                    path_disclosure = Some(disclosed_path);
                                    if verbose {
                                        eprintln!("     [verbose] ✓ Path disclosure detected: {}", path_disclosure.as_ref().unwrap());
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            } else if verbose {
                eprintln!("     [verbose] Path disclosure check returned status: {}", status);
            }
        } else if verbose {
            eprintln!("     [verbose] Path disclosure endpoint not accessible");
        }
        
        let config = WordPressConfig {
            xmlrpc_enabled,
            comments_allowed,
            signup_enabled,
            login_path,
            login_path_validated,
            path_disclosure,
        };
        
        // Display as found (real-time output)
        if use_realtime_output {
            crate::output::OutputFormatter::print_wordpress_config_section(&config);
        }
        
        Ok((Some(config), waf_detected))
    }
    
    fn extract_response_headers(response: &reqwest::blocking::Response) -> std::collections::HashMap<String, String> {
        let mut headers = std::collections::HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(key.to_string(), value_str.to_string());
            }
        }
        headers
    }

    /// Enumerate plugins from database file (top or complete)
    pub fn enumerate_plugins_from_file(
        client: &HttpClient,
        verbose: bool,
        use_realtime_output: bool,
        use_top: bool,
        existing_slugs: &HashSet<String>, // Slug-urile deja detectate pasiv
        update_progress: impl Fn(usize, usize), // (current, total) callback
    ) -> Result<Vec<DetectedPlugin>> {
        let file_path = if use_top {
            format!("{}/plugins-top.txt", constants::DATABASE_DIR)
        } else {
            format!("{}/plugins.txt", constants::DATABASE_DIR)
        };

        if !Path::new(&file_path).exists() {
            if verbose {
                eprintln!("     [verbose] Database file not found: {}", file_path);
            }
            return Ok(vec![]);
        }

        let content = fs::read_to_string(&file_path)
            .context("Failed to read plugins database file")?;
        
        let slugs: Vec<String> = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        let total = slugs.len();
        let mut plugins = vec![];

        if use_realtime_output && total > 0 {
            crate::output::OutputFormatter::print_section_end();
        }

        for (idx, slug) in slugs.iter().enumerate() {
            update_progress(idx + 1, total);

            // Skip if already detected passively
            if existing_slugs.contains(slug) {
                continue;
            }

            // Check if plugin exists by trying to access a common plugin file
            let plugin_check_path = format!("/wp-content/plugins/{}/", slug);
            if let Ok(response) = client.get(&plugin_check_path, None) {
                let status = response.status().as_u16();
                if status == 200 || status == 403 || status == 301 || status == 302 {
                    // 200 = exists, 403 = exists but denied, 301/302 = redirect (exists)
                    // Get version using same methods as passive detection
                    let mut version: Option<String> = None;
                    
                    // Try readme.txt first (normal mode)
                    if let Ok(readme_version) = Self::get_plugin_version_from_readme(client, slug) {
                        if let Some(v) = readme_version {
                            version = Some(v);
                        }
                    }
                    
                    // Fall back to ?ver= parameter by checking homepage
                    if version.is_none() {
                        if let Ok(homepage_response) = client.get("", None) {
                            if homepage_response.status().is_success() {
                                if let Ok(text) = homepage_response.text() {
                                    // Look for this plugin's URLs with ?ver= parameter
                                    let escaped_slug = regex::escape(slug);
                                    let plugin_ver_re = Regex::new(&format!(r#"(?i)/wp-content/plugins/{}/[^"']*\?ver=([\d.]+)"#, escaped_slug)).unwrap();
                                    for caps in plugin_ver_re.captures_iter(&text) {
                                        if let Some(ver_match) = caps.get(1) {
                                            version = Some(ver_match.as_str().to_string());
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let version_value = version.unwrap_or_else(|| "unknown".to_string());
                    let plugin = DetectedPlugin {
                        slug: slug.clone(),
                        name: slug.clone(),
                        version: version_value.clone(),
                    };
                    plugins.push(plugin.clone());

                    // Display as found (real-time output)
                    if use_realtime_output {
                        crate::output::OutputFormatter::print_plugin_item_real_time(&plugin, false, verbose);
                    }

                    // Get latest version from SVN if version is known
                    if plugin.version != "unknown" {
                        if let Some(latest_version) = Self::get_latest_plugin_version_from_svn(slug, verbose) {
                            if verbose {
                                eprintln!("     [verbose] Latest SVN version for {}: {}", slug, latest_version);
                            }
                        }
                    }
                }
            }
        }

        if use_realtime_output && !plugins.is_empty() {
            crate::output::OutputFormatter::print_section_end();
        }

        Ok(plugins)
    }

    /// Enumerate themes from database file (top or complete)
    pub fn enumerate_themes_from_file(
        client: &HttpClient,
        verbose: bool,
        use_realtime_output: bool,
        use_top: bool,
        existing_slugs: &HashSet<String>, // Slug-urile deja detectate pasiv
        update_progress: impl Fn(usize, usize), // (current, total) callback
    ) -> Result<Vec<DetectedTheme>> {
        let file_path = if use_top {
            format!("{}/themes-top.txt", constants::DATABASE_DIR)
        } else {
            format!("{}/themes.txt", constants::DATABASE_DIR)
        };

        if !Path::new(&file_path).exists() {
            if verbose {
                eprintln!("     [verbose] Database file not found: {}", file_path);
            }
            return Ok(vec![]);
        }

        let content = fs::read_to_string(&file_path)
            .context("Failed to read themes database file")?;
        
        let slugs: Vec<String> = content
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect();

        let total = slugs.len();
        let mut themes = vec![];

        if use_realtime_output && total > 0 {
            crate::output::OutputFormatter::print_section_end();
        }

        for (idx, slug) in slugs.iter().enumerate() {
            update_progress(idx + 1, total);

            // Skip if already detected passively
            if existing_slugs.contains(slug) {
                continue;
            }

            // Check if theme exists by trying to access style.css
            let theme_check_path = format!("/wp-content/themes/{}/style.css", slug);
            if let Ok(response) = client.get(&theme_check_path, None) {
                let status = response.status().as_u16();
                if status == 200 || status == 403 || status == 301 || status == 302 {
                    // 200 = exists, 403 = exists but denied, 301/302 = redirect (exists)
                    // Get theme info from style.css (same method as passive detection)
                    let theme_info = Self::get_theme_info(client, slug).ok().unwrap_or_default();
                    let theme = DetectedTheme {
                        slug: slug.clone(),
                        name: theme_info.name.unwrap_or(slug.clone()),
                        version: theme_info.version.unwrap_or_else(|| "unknown".to_string()),
                        active: false, // Cannot determine active status from file enumeration
                        author: theme_info.author.clone(),
                        text_domain: theme_info.text_domain.clone(),
                    };
                    themes.push(theme.clone());

                    // Display as found (real-time output)
                    if use_realtime_output {
                        crate::output::OutputFormatter::print_theme_item_real_time(&theme, false, verbose);
                    }

                    // Get latest version from SVN if version is known
                    if theme.version != "unknown" {
                        if let Some(latest_version) = Self::get_latest_theme_version_from_svn(slug, verbose) {
                            if verbose {
                                eprintln!("     [verbose] Latest SVN version for {}: {}", slug, latest_version);
                            }
                        }
                    }
                }
            }
        }

        if use_realtime_output && !themes.is_empty() {
            crate::output::OutputFormatter::print_section_end();
        }

        Ok(themes)
    }
}
