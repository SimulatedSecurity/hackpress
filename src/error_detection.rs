use colored::*;
use regex::Regex;
use reqwest::blocking::Response;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum ErrorType {
    WafBlocked,
    WebsiteDown,
    ConnectionTimeout,
    DnsError,
    SslError,
    RateLimited,
    NotFound,
    PermissionDenied,
    #[allow(dead_code)]
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ErrorInfo {
    pub error_type: ErrorType,
    pub message: String,
    pub status_code: Option<u16>,
    pub headers: HashMap<String, String>,
    pub body_snippet: Option<String>,
}

pub struct ErrorDetector;

impl ErrorDetector {
    /// Check response for WAF blocking indicators
    #[allow(dead_code)]
    pub fn detect_waf(response: &Response, body: &str) -> Option<ErrorInfo> {
        let status = response.status().as_u16();
        let headers = Self::extract_headers(response);
        
        // Common WAF indicators
        let waf_status_codes = vec![403, 406, 418, 429, 503];
        let waf_headers = vec![
            "cf-ray",           // Cloudflare
            "x-sucuri-id",      // Sucuri
            "x-sucuri-cache",   // Sucuri
            "server",           // Check for WAF servers
            "x-waf",            // Generic WAF header
            "x-protected-by",   // Generic protection header
            "x-blocked-by",     // Generic blocking header
        ];
        
        let waf_body_patterns = vec![
            r"(?i)cloudflare",
            r"(?i)sucuri",
            r"(?i)incapsula",
            r"(?i)akamai",
            r"(?i)mod_security",
            r"(?i)blocked",
            r"(?i)forbidden.*waf",
            r"(?i)access.*denied.*waf",
            r"(?i)your request has been blocked",
            r"(?i)security.*by.*cloudflare",
            r"(?i)challenge.*required",
        ];

        // Check status code
        if waf_status_codes.contains(&status) {
            // Check headers for WAF indicators
            for waf_header in &waf_headers {
                if headers.keys().any(|k| k.to_lowercase().contains(waf_header)) {
                    return Some(ErrorInfo {
                        error_type: ErrorType::WafBlocked,
                        message: format!("WAF detected ({} header present)", waf_header),
                        status_code: Some(status),
                        headers,
                        body_snippet: Self::extract_body_snippet(body),
                    });
                }
            }

            // Check body for WAF patterns
            for pattern in &waf_body_patterns {
                let re = Regex::new(pattern).unwrap();
                if re.is_match(body) {
                    return Some(ErrorInfo {
                        error_type: ErrorType::WafBlocked,
                        message: format!("WAF detected (pattern: {})", pattern),
                        status_code: Some(status),
                        headers,
                        body_snippet: Self::extract_body_snippet(body),
                    });
                }
            }

            // If 403 with no other indicators, might still be WAF
            if status == 403 {
                return Some(ErrorInfo {
                    error_type: ErrorType::WafBlocked,
                    message: "Possible WAF blocking (403 Forbidden)".to_string(),
                    status_code: Some(status),
                    headers,
                    body_snippet: Self::extract_body_snippet(body),
                });
            }
        }

        None
    }

    /// Check request error for website down or connection issues
    pub fn detect_request_error(error: &anyhow::Error) -> Option<ErrorInfo> {
        let error_msg = error.to_string().to_lowercase();

        // Connection timeout
        if error_msg.contains("timeout") || error_msg.contains("timed out") {
            return Some(ErrorInfo {
                error_type: ErrorType::ConnectionTimeout,
                message: "Connection timeout - website may be slow or unresponsive".to_string(),
                status_code: None,
                headers: HashMap::new(),
                body_snippet: None,
            });
        }

        // DNS errors
        if error_msg.contains("dns") || error_msg.contains("resolve") || error_msg.contains("name resolution") {
            return Some(ErrorInfo {
                error_type: ErrorType::DnsError,
                message: "DNS resolution failed - website may be down or domain invalid".to_string(),
                status_code: None,
                headers: HashMap::new(),
                body_snippet: None,
            });
        }

        // SSL/TLS errors
        if error_msg.contains("ssl") || error_msg.contains("tls") || error_msg.contains("certificate") {
            return Some(ErrorInfo {
                error_type: ErrorType::SslError,
                message: "SSL/TLS error - certificate issue or connection problem".to_string(),
                status_code: None,
                headers: HashMap::new(),
                body_snippet: None,
            });
        }

        // Connection refused / website down
        if error_msg.contains("connection refused") 
            || error_msg.contains("connection reset")
            || error_msg.contains("failed to connect")
            || error_msg.contains("network unreachable") {
            return Some(ErrorInfo {
                error_type: ErrorType::WebsiteDown,
                message: "Connection failed - website may be down or unreachable".to_string(),
                status_code: None,
                headers: HashMap::new(),
                body_snippet: None,
            });
        }

        // Rate limiting
        if error_msg.contains("rate limit") || error_msg.contains("too many requests") {
            return Some(ErrorInfo {
                error_type: ErrorType::RateLimited,
                message: "Rate limited - too many requests".to_string(),
                status_code: Some(429),
                headers: HashMap::new(),
                body_snippet: None,
            });
        }

        None
    }

    /// Check response status for common error conditions (without Response object)
    pub fn detect_response_error_with_status(status: u16, headers: &HashMap<String, String>, body: &str) -> Option<ErrorInfo> {
        // Create a mock response-like structure for WAF detection
        // Check WAF first
        if let Some(waf_error) = Self::detect_waf_from_status(status, headers, body) {
            return Some(waf_error);
        }
        
        // Other error types
        match status {
            404 => Some(ErrorInfo {
                error_type: ErrorType::NotFound,
                message: "Resource not found (404)".to_string(),
                status_code: Some(status),
                headers: headers.clone(),
                body_snippet: None,
            }),
            403 => Some(ErrorInfo {
                error_type: ErrorType::PermissionDenied,
                message: "Permission denied (403) - access forbidden".to_string(),
                status_code: Some(status),
                headers: headers.clone(),
                body_snippet: Self::extract_body_snippet(body),
            }),
            429 => Some(ErrorInfo {
                error_type: ErrorType::RateLimited,
                message: "Rate limited (429) - too many requests".to_string(),
                status_code: Some(status),
                headers: headers.clone(),
                body_snippet: Self::extract_body_snippet(body),
            }),
            s if s >= 500 => Some(ErrorInfo {
                error_type: ErrorType::WebsiteDown,
                message: format!("Server error ({}) - website may be experiencing issues", s),
                status_code: Some(s),
                headers: headers.clone(),
                body_snippet: Self::extract_body_snippet(body),
            }),
            _ => None,
        }
    }
    
    fn detect_waf_from_status(status: u16, headers: &HashMap<String, String>, body: &str) -> Option<ErrorInfo> {
        // Common WAF indicators
        let waf_status_codes = vec![403, 406, 418, 429, 503];
        let waf_headers = vec![
            "cf-ray",           // Cloudflare
            "x-sucuri-id",      // Sucuri
            "x-sucuri-cache",   // Sucuri
            "x-waf",            // Generic WAF header
            "x-protected-by",   // Generic protection header
            "x-blocked-by",     // Generic blocking header
        ];
        
        let waf_body_patterns = vec![
            r"(?i)cloudflare",
            r"(?i)sucuri",
            r"(?i)incapsula",
            r"(?i)akamai",
            r"(?i)mod_security",
            r"(?i)blocked",
            r"(?i)forbidden.*waf",
            r"(?i)your request has been blocked",
            r"(?i)security.*by.*cloudflare",
        ];

        if waf_status_codes.contains(&status) {
            // Check headers
            for (key, value) in headers {
                let key_lower = key.to_lowercase();
                for waf_header in &waf_headers {
                    if key_lower.contains(waf_header) {
                        return Some(ErrorInfo {
                            error_type: ErrorType::WafBlocked,
                            message: format!("WAF detected ({}: {})", key, value),
                            status_code: Some(status),
                            headers: headers.clone(),
                            body_snippet: Self::extract_body_snippet(body),
                        });
                    }
                }
            }

            // Check body
            for pattern in &waf_body_patterns {
                let re = Regex::new(pattern).unwrap();
                if re.is_match(body) {
                    return Some(ErrorInfo {
                        error_type: ErrorType::WafBlocked,
                        message: format!("WAF detected in response body"),
                        status_code: Some(status),
                        headers: headers.clone(),
                        body_snippet: Self::extract_body_snippet(body),
                    });
                }
            }

            // If 403 with suspicious indicators
            if status == 403 && !body.is_empty() {
                return Some(ErrorInfo {
                    error_type: ErrorType::WafBlocked,
                    message: "Possible WAF blocking (403 Forbidden)".to_string(),
                    status_code: Some(status),
                    headers: headers.clone(),
                    body_snippet: Self::extract_body_snippet(body),
                });
            }
        }

        None
    }

    /// Check response status for common error conditions
    #[allow(dead_code)]
    pub fn detect_response_error(response: &Response, body: &str) -> Option<ErrorInfo> {
        let status = response.status().as_u16();
        let headers = Self::extract_headers(response);
        Self::detect_response_error_with_status(status, &headers, body)
    }

    /// Print error alert to user
    pub fn alert_error(error_info: &ErrorInfo, verbose: bool) {
        let (icon, color) = match error_info.error_type {
            ErrorType::WafBlocked => ("⚠", "yellow"),
            ErrorType::WebsiteDown => ("✗", "red"),
            ErrorType::ConnectionTimeout => ("⏱", "yellow"),
            ErrorType::DnsError => ("✗", "red"),
            ErrorType::SslError => ("🔒", "yellow"),
            ErrorType::RateLimited => ("⏸", "yellow"),
            ErrorType::NotFound => ("?", "blue"),
            ErrorType::PermissionDenied => ("🚫", "red"),
            ErrorType::Unknown => ("?", "white"),
        };

        let icon_colored = match color {
            "yellow" => icon.bright_yellow(),
            "red" => icon.bright_red(),
            "blue" => icon.bright_blue(),
            _ => icon.bright_white(),
        };

        // For WAF detection, show simplified message with status code
        if matches!(error_info.error_type, ErrorType::WafBlocked) {
            if let Some(status) = error_info.status_code {
                eprintln!(
                    "\n{} {} WAF detected (HTTP {})",
                    icon_colored,
                    "[ALERT]".bright_red().bold(),
                    status.to_string().bright_cyan()
                );
            } else {
                eprintln!(
                    "\n{} {} {}",
                    icon_colored,
                    "[ALERT]".bright_red().bold(),
                    error_info.message.bright_yellow()
                );
            }
        } else {
            eprintln!(
                "\n{} {} {}",
                icon_colored,
                "[ALERT]".bright_red().bold(),
                error_info.message.bright_yellow()
            );

            if verbose {
                if let Some(status) = error_info.status_code {
                    eprintln!("   Status Code: {}", status.to_string().bright_cyan());
                }

                if !error_info.headers.is_empty() {
                    eprintln!("   Headers:");
                    for (key, value) in &error_info.headers {
                        if key.to_lowercase().contains("waf")
                            || key.to_lowercase().contains("cf-")
                            || key.to_lowercase().contains("sucuri")
                            || key.to_lowercase().contains("x-blocked")
                        {
                            eprintln!("     {}: {}", key.bright_red(), value.bright_red());
                        } else {
                            eprintln!("     {}: {}", key, value);
                        }
                    }
                }

                if let Some(snippet) = &error_info.body_snippet {
                    eprintln!("   Response snippet: {}", snippet.bright_black());
                }
            }
        }

        // Provide recommendations
        match error_info.error_type {
            ErrorType::WafBlocked => {
                eprintln!(
                    "   {} Try using --waf-bypass flag to enable bypass techniques",
                    "→".bright_blue()
                );
            }
            ErrorType::RateLimited => {
                eprintln!(
                    "   {} Reduce request rate or wait before retrying",
                    "→".bright_blue()
                );
            }
            ErrorType::WebsiteDown | ErrorType::ConnectionTimeout => {
                eprintln!(
                    "   {} Verify the website is accessible and try again",
                    "→".bright_blue()
                );
            }
            _ => {}
        }
        eprintln!();
        eprintln!();
    }

    #[allow(dead_code)]
    fn extract_headers(response: &Response) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(key.to_string(), value_str.to_string());
            }
        }
        headers
    }

    fn extract_body_snippet(body: &str) -> Option<String> {
        let snippet = body.chars().take(200).collect::<String>();
        if snippet.is_empty() {
            None
        } else {
            Some(snippet)
        }
    }
}
