use anyhow::{Context, Result};
use crate::http_client::HttpClient;
use crate::models::{RobotsTxtInfo, TechStackInfo};
use regex::Regex;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use url::Url;

pub struct TechStackAnalyzer;

impl TechStackAnalyzer {
    pub fn analyze_headers(client: &HttpClient) -> Result<TechStackInfo> {
        let response = client.get("", None)
            .context("Failed to fetch headers")?;
        
        let mut headers_map = HashMap::new();
        let mut server = None;
        let mut php_version = None;
        let mut cdn = None;
        let mut security_headers = vec![];
        let mut relevant_headers = vec![];
        
        // Resolve IP address and get geolocation
        let (ip, country, ip_info) = Self::resolve_ip_and_location(&client.base_url);

        // Extract all headers
        for (name, value) in response.headers() {
            let name_str = name.as_str().to_lowercase();
            let value_str = value.to_str().unwrap_or("").to_string();
            
            // For headers that can have multiple values, collect all of them
            // Otherwise, just store the last one in the map
            if name_str == "x-powered-by" || name_str == "vary" {
                // These headers can have multiple values, so we'll handle them specially
                // Don't insert into headers_map to avoid overwriting
            } else {
                headers_map.insert(name_str.clone(), value_str.clone());
            }

            // Identify server
            if name_str == "server" {
                server = Some(value_str.clone());
            }

            // Identify PHP version from x-powered-by
            if name_str == "x-powered-by" {
                if let Some(version) = Self::extract_php_version(&value_str) {
                    php_version = Some(version);
                }
                // Always add x-powered-by to relevant headers (can have multiple values)
                relevant_headers.push((name.as_str().to_string(), value_str.clone()));
            }

            // Identify CDN
            if let Some(detected_cdn) = Self::detect_cdn(&name_str, &value_str) {
                cdn = Some(detected_cdn);
            }

            // Check for security headers
            if Self::is_security_header(&name_str) {
                security_headers.push(format!("{}: {}", name_str, value_str));
            }
            
            // Check for other relevant headers (PleskLin, etc.)
            // Note: x-powered-by is already handled above, so we skip it here to avoid duplicates
            // But we still check the value for PleskLin in case it's in a different header
            if name_str != "x-powered-by" {
                if Self::is_relevant_header(&name_str, &value_str) {
                    relevant_headers.push((name.as_str().to_string(), value_str.clone()));
                }
            } else {
                // For x-powered-by, also check if value contains PleskLin or other relevant info
                // (already added above, but this ensures we catch all cases)
                let value_lower = value_str.to_lowercase();
                if value_lower.contains("plesklin") || value_lower.contains("plesk") {
                    // Already added above, but ensure it's there
                }
            }
        }

        Ok(TechStackInfo {
            ip,
            country,
            ip_info,
            server,
            php_version,
            cdn,
            security_headers,
            headers: headers_map,
            relevant_headers,
        })
    }
    
    fn resolve_ip_and_location(url_str: &str) -> (Option<String>, Option<String>, Option<String>) {
        // Parse URL and extract hostname
        let hostname = match Url::parse(url_str) {
            Ok(url) => {
                url.host_str().map(|h| h.to_string())
            }
            Err(_) => {
                // If URL parsing fails, try to extract hostname manually
                url_str
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .split('/')
                    .next()
                    .map(|s| s.to_string())
            }
        };
        
        let hostname = match hostname {
            Some(h) => h,
            None => return (None, None, None),
        };
        
        // Resolve IP address
        let ip = match Self::resolve_hostname_to_ip(&hostname) {
            Some(ip) => ip,
            None => return (None, None, None),
        };
        
        // Get IP geolocation
        match Self::get_ip_geolocation(&ip) {
            Some((country, info)) => (Some(ip), Some(country), Some(info)),
            None => (Some(ip), None, None),
        }
    }
    
    fn resolve_hostname_to_ip(hostname: &str) -> Option<String> {
        // Skip if hostname is already an IP address
        if hostname.parse::<std::net::IpAddr>().is_ok() {
            return Some(hostname.to_string());
        }
        
        // Try to resolve hostname to IP
        let socket_addr = format!("{}:80", hostname);
        match socket_addr.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    return Some(addr.ip().to_string());
                }
            }
            Err(_) => {}
        }
        
        // Fallback: try with port 443
        let socket_addr = format!("{}:443", hostname);
        match socket_addr.to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    return Some(addr.ip().to_string());
                }
            }
            Err(_) => {}
        }
        
        None
    }
    
    fn get_ip_geolocation(ip: &str) -> Option<(String, String)> {
        use crate::constants;
        // Use ip-api.com free API (no API key required, rate limit: 45 requests/minute)
        // Format: http://ip-api.com/json/{ip}?fields=status,message,country,as,org
        // The "as" field returns format like "AS12345 Example ISP" or just "AS12345"
        let api_url = format!("{}/{}?fields=status,message,country,as,org", constants::IP_API_BASE_URL, ip);
        
        match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(constants::IP_API_TIMEOUT))
            .build()
        {
            Ok(client) => {
                match client.get(&api_url).send() {
                    Ok(response) => {
                        if response.status().is_success() {
                            if let Ok(json) = response.json::<serde_json::Value>() {
                                // Check if request was successful
                                if json.get("status").and_then(|s| s.as_str()) == Some("success") {
                                    let country = json.get("country")
                                        .and_then(|c| c.as_str())
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| "Unknown".to_string());
                                    
                                    // Build info string with ASN and org
                                    // The "as" field from ip-api.com returns format like "AS12345 Example ISP" or "AS12345"
                                    // The "org" field returns the organization name
                                    let mut info_parts = vec![];
                                    
                                    // Get ASN field (contains AS number and sometimes org)
                                    if let Some(asn_str) = json.get("as").and_then(|a| a.as_str()) {
                                        if !asn_str.is_empty() && asn_str != "Unknown" && asn_str.starts_with("AS") {
                                            // Extract just the AS number part (AS12345) if it contains more
                                            let asn_clean = asn_str.split_whitespace().next().unwrap_or(asn_str);
                                            info_parts.push(asn_clean.to_string());
                                        }
                                    }
                                    
                                    // Get org field (organization name)
                                    if let Some(org) = json.get("org").and_then(|o| o.as_str()) {
                                        if !org.is_empty() && org != "Unknown" {
                                            // Only add org if it's not already in the ASN string
                                            if let Some(asn_str) = json.get("as").and_then(|a| a.as_str()) {
                                                // Check if org is different from what's in ASN
                                                let org_in_asn = asn_str.contains(org);
                                                if !org_in_asn {
                                                    info_parts.push(org.to_string());
                                                }
                                            } else {
                                                info_parts.push(org.to_string());
                                            }
                                        }
                                    }
                                    
                                    let info = if info_parts.is_empty() {
                                        "Unknown".to_string()
                                    } else {
                                        info_parts.join(", ")
                                    };
                                    
                                    return Some((country, info));
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }
        
        None
    }

    pub fn analyze_robots_txt(client: &HttpClient) -> Result<Option<RobotsTxtInfo>> {
        let response = match client.get("/robots.txt", None) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };

        if !response.status().is_success() {
            return Ok(None);
        }

        let text = response.text().context("Failed to read robots.txt")?;
        let mut disallowed = vec![];
        let mut sitemap = vec![];
        let mut findings = vec![];

        let disallow_re = Regex::new(r"(?i)^disallow:\s*(.+)$").unwrap();
        let allow_re = Regex::new(r"(?i)^allow:\s*(.+)$").unwrap();
        let sitemap_re = Regex::new(r"(?i)^sitemap:\s*(.+)$").unwrap();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(caps) = disallow_re.captures(line) {
                if let Some(path) = caps.get(1) {
                    let path = path.as_str().trim();
                    disallowed.push(path.to_string());
                    
                    // Check for interesting patterns
                    if path.contains("wp-admin") || path.contains("wp-includes") {
                        findings.push(format!("WordPress paths disallowed: {}", path));
                    }
                    if path.contains("config") || path.contains("backup") {
                        findings.push(format!("Sensitive path disallowed: {}", path));
                    }
                }
            } else if let Some(caps) = allow_re.captures(line) {
                if let Some(path) = caps.get(1) {
                    let path = path.as_str().trim();
                    findings.push(format!("Interesting allowed path: {}", path));
                }
            } else if let Some(caps) = sitemap_re.captures(line) {
                if let Some(url) = caps.get(1) {
                    sitemap.push(url.as_str().trim().to_string());
                }
            }
        }

        if disallowed.is_empty() && sitemap.is_empty() && findings.is_empty() {
            return Ok(None);
        }

        Ok(Some(RobotsTxtInfo {
            disallowed,
            sitemap,
            findings,
            content: Some(text),
        }))
    }

    fn extract_php_version(header: &str) -> Option<String> {
        let re = Regex::new(r"PHP/([\d.]+)").unwrap();
        re.captures(header)
            .and_then(|caps| caps.get(1))
            .map(|m| m.as_str().to_string())
    }

    fn detect_cdn(header_name: &str, header_value: &str) -> Option<String> {
        let value_lower = header_value.to_lowercase();
        
        if header_name == "cf-ray" || value_lower.contains("cloudflare") {
            return Some("Cloudflare".to_string());
        }
        if header_name == "server" && value_lower.contains("cloudfront") {
            return Some("CloudFront".to_string());
        }
        if value_lower.contains("fastly") {
            return Some("Fastly".to_string());
        }
        if value_lower.contains("akamai") {
            return Some("Akamai".to_string());
        }
        if header_name == "x-cache" || header_name == "x-cache-status" {
            return Some("CDN (Unknown)".to_string());
        }
        None
    }

    fn is_security_header(header_name: &str) -> bool {
        matches!(
            header_name,
            "x-frame-options"
                | "x-content-type-options"
                | "x-xss-protection"
                | "strict-transport-security"
                | "content-security-policy"
                | "referrer-policy"
                | "permissions-policy"
        )
    }
    
    fn is_relevant_header(header_name: &str, header_value: &str) -> bool {
        let name_lower = header_name.to_lowercase();
        let value_lower = header_value.to_lowercase();
        
        // x-powered-by is already handled separately above, so skip it here
        if name_lower == "x-powered-by" {
            return false;
        }
        
        // Check for PleskLin in any header value (case-insensitive)
        if value_lower.contains("plesklin") {
            return true;
        }
        
        // Check for other relevant technologies
        if value_lower.contains("plesk") || value_lower.contains("cpanel") || 
           value_lower.contains("directadmin") || value_lower.contains("vestacp") {
            return true;
        }
        
        // Check for framework indicators
        if name_lower.contains("x-") && (
            value_lower.contains("asp.net") || 
            value_lower.contains("express") || 
            value_lower.contains("django") ||
            value_lower.contains("rails")
        ) {
            return true;
        }
        
        false
    }
}
