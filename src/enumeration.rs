use anyhow::{Context, Result};
use crate::http_client::HttpClient;
use crate::models::EnumeratedUsername;
use regex::Regex;
use std::collections::HashMap;

pub struct UsernameEnumerator;

impl UsernameEnumerator {
    pub fn enumerate(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Vec<EnumeratedUsername>> {
        Self::enumerate_internal(client, verbose, use_realtime_output, false)
    }
    
    pub fn enumerate_stealth(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Vec<EnumeratedUsername>> {
        Self::enumerate_internal(client, verbose, use_realtime_output, true)
    }
    
    fn enumerate_internal(client: &HttpClient, verbose: bool, use_realtime_output: bool, stealth: bool) -> Result<Vec<EnumeratedUsername>> {
        let mut usernames: HashMap<String, String> = HashMap::new();

        // Method 1: REST API (MOST RELIABLE)
        let rest_endpoints = vec![
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/users?per_page=100",
            "/?rest_route=/wp/v2/users",
        ];
        
        if verbose {
            eprintln!("     [verbose] Trying REST API endpoints for username enumeration...");
        }
        for endpoint in rest_endpoints {
            if verbose {
                eprintln!("     [verbose] Checking {}", endpoint);
            }
            if let Ok(response) = client.get(endpoint, None) {
                let status = response.status().as_u16();
                let headers = Self::extract_response_headers(&response);
                let text = response.text().unwrap_or_default();
                
                // Check for errors
                if status >= 400 {
                    if let Some(error_info) = crate::error_detection::ErrorDetector::detect_response_error_with_status(status, &headers, &text) {
                        crate::error_detection::ErrorDetector::alert_error(&error_info, verbose);
                    }
                }
                
                if status < 400 {
                    let json: Result<serde_json::Value, _> = serde_json::from_str(&text);
                    if let Ok(json) = json {
                        if let Some(array) = json.as_array() {
                            if verbose {
                                eprintln!("     [verbose] REST API returned {} users", array.len());
                            }
                            for user in array {
                                // Prefer username/slug over name as it's the actual login
                                if let Some(slug) = user.get("slug").and_then(|s| s.as_str()) {
                                    if Self::is_valid_username(slug) {
                                        if verbose {
                                            eprintln!("     [verbose] Found username via REST API: {}", slug);
                                        }
                                        // Only add if not already found (preserve first source)
                                        if !usernames.contains_key(slug) {
                                            usernames.insert(slug.to_string(), "REST API".to_string());
                                            // Display as found (real-time output)
                                            if use_realtime_output {
                                                let username_info = EnumeratedUsername {
                                                    username: slug.to_string(),
                                                    source: "REST API".to_string(),
                                                };
                                                crate::output::OutputFormatter::print_username_item_real_time(&username_info, usernames.len() == 1);
                                            }
                                        }
                                    }
                                }
                                if let Some(login) = user.get("username").or_else(|| user.get("user_login")).and_then(|s| s.as_str()) {
                                    if Self::is_valid_username(login) {
                                        if verbose {
                                            eprintln!("     [verbose] Found username via REST API: {}", login);
                                        }
                                        if !usernames.contains_key(login) {
                                            usernames.insert(login.to_string(), "REST API".to_string());
                                            // Display as found (real-time output)
                                            if use_realtime_output {
                                                let username_info = EnumeratedUsername {
                                                    username: login.to_string(),
                                                    source: "REST API".to_string(),
                                                };
                                                crate::output::OutputFormatter::print_username_item_real_time(&username_info, usernames.len() == 1);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Method 2: Author archive pages via redirects (RELIABLE)
        // Skip in stealth mode (no archive enumeration)
        if !stealth {
            // Try first 20 author IDs (more efficient than 100)
            if verbose {
                eprintln!("     [verbose] Trying author archive pages (IDs 1-20)...");
            }
            for author_id in 1..=20 {
                if let Ok(response) = client.get(&format!("/?author={}", author_id), None) {
                let location_header = response.headers().get("location").cloned();
                let status = response.status().as_u16();
                let _text = response.text().unwrap_or_default();
                
                // Check redirect location (most reliable)
                if let Some(location) = location_header {
                    if let Ok(location_str) = location.to_str() {
                        if let Some(username) = Self::extract_username_from_url(location_str) {
                            if Self::is_valid_username(&username) {
                                if verbose {
                                    eprintln!("     [verbose] Found username via author archive (ID {}): {}", author_id, username);
                                }
                                if !usernames.contains_key(&username) {
                                    usernames.insert(username.clone(), "Author Archive".to_string());
                                    // Display as found (real-time output)
                                    if use_realtime_output {
                                        let username_info = EnumeratedUsername {
                                            username: username.clone(),
                                            source: "Author Archive".to_string(),
                                        };
                                        crate::output::OutputFormatter::print_username_item_real_time(&username_info, usernames.len() == 1);
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Also check response body if it's a 200 (less reliable)
                if status == 200 {
                    let username_re = Regex::new(r#"(?i)/author/([^/"]+)"#).unwrap();
                    for caps in username_re.captures_iter(&_text) {
                        if let Some(username) = caps.get(1) {
                            let uname = username.as_str();
                            if Self::is_valid_username(uname) {
                                if !usernames.contains_key(uname) {
                                    usernames.insert(uname.to_string(), "Author Archive".to_string());
                                    // Display as found (real-time output)
                                    if use_realtime_output {
                                        let username_info = EnumeratedUsername {
                                            username: uname.to_string(),
                                            source: "Author Archive".to_string(),
                                        };
                                        crate::output::OutputFormatter::print_username_item_real_time(&username_info, usernames.len() == 1);
                                    }
                                }
                            }
                        }
                    }
                }
                }
            }
        } else if verbose {
            eprintln!("     [verbose] Stealth mode: skipping author archive enumeration");
        }

        // Method 3: RSS Feed author enumeration (RELIABLE)
        if let Ok(response) = client.get("/feed/", None) {
            if response.status().is_success() {
                let text = response.text().context("Failed to read RSS feed")?;
                // Look for author/creator tags
                let author_re = Regex::new(r#"(?i)<(?:dc:)?creator>([^<]+)</(?:dc:)?creator>"#).unwrap();
                for caps in author_re.captures_iter(&text) {
                    if let Some(author) = caps.get(1) {
                        let uname = author.as_str().trim();
                        if Self::is_valid_username(uname) {
                            if !usernames.contains_key(uname) {
                                usernames.insert(uname.to_string(), "RSS Feed".to_string());
                                // Display as found (real-time output)
                                if use_realtime_output {
                                    let username_info = EnumeratedUsername {
                                        username: uname.to_string(),
                                        source: "RSS Feed".to_string(),
                                    };
                                    crate::output::OutputFormatter::print_username_item_real_time(&username_info, usernames.len() == 1);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(usernames.into_iter()
            .map(|(username, source)| EnumeratedUsername { username, source })
            .collect())
    }

    fn is_valid_username(username: &str) -> bool {
        // Validate username: not empty, reasonable length, only valid characters
        !username.is_empty()
            && username.len() < 100
            && username.len() >= 1
            && !username.contains(" ")
            && username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    }

    fn extract_username_from_url(url: &str) -> Option<String> {
        // Try multiple patterns for author URLs
        let patterns = vec![
            r"/author/([^/?#]+)",
            r"author=([^&]+)",
            r"author/([^/?#]+)",
        ];
        
        for pattern in patterns {
            let re = Regex::new(pattern).unwrap();
            if let Some(caps) = re.captures(url) {
                if let Some(username) = caps.get(1) {
                    let uname = username.as_str().trim();
                    // Filter out invalid usernames
                    if !uname.is_empty() 
                        && uname.len() < 100 
                        && !uname.contains(" ") 
                        && uname.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                        return Some(uname.to_string());
                    }
                }
            }
        }
        
        None
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
}
