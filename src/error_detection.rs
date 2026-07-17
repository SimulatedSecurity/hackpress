use colored::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

static WAF_ALERT_SHOWN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorType {
    WafBlocked,
    WafChallenge,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafConfidence {
    /// Soft signal — log only in verbose, do not abort scan
    Low,
    /// Clear block/challenge page — warn once
    High,
}

#[derive(Debug, Clone)]
pub struct ErrorInfo {
    pub error_type: ErrorType,
    pub message: String,
    pub status_code: Option<u16>,
    #[allow(dead_code)]
    pub headers: HashMap<String, String>,
    pub body_snippet: Option<String>,
    pub confidence: WafConfidence,
    pub vendor: Option<String>,
}

pub struct ErrorDetector;

impl ErrorDetector {
    /// Reset once-per-process alert latch (useful for tests / new scan sessions).
    pub fn reset_alert_latch() {
        WAF_ALERT_SHOWN.store(false, Ordering::Relaxed);
    }

    /// High-confidence WAF block or JS challenge?
    pub fn is_waf_block(error: &ErrorInfo) -> bool {
        matches!(
            error.error_type,
            ErrorType::WafBlocked | ErrorType::WafChallenge
        ) && error.confidence == WafConfidence::High
    }

    /// Analyze a response for WAF / challenge / rate-limit. Returns None if not a WAF event.
    ///
    /// CDN headers alone (e.g. `cf-ray` on a normal Cloudflare site) are NOT treated as a block.
    pub fn detect_waf(
        status: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> Option<ErrorInfo> {
        let headers_l: HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();
        let body_l = body.to_lowercase();
        let vendor = Self::guess_vendor(&headers_l, &body_l);

        // Explicit Cloudflare mitigation header
        if let Some(mitigated) = headers_l.get("cf-mitigated") {
            let m = mitigated.to_lowercase();
            if m.contains("challenge") {
                return Some(Self::waf_info(
                    ErrorType::WafChallenge,
                    WafConfidence::High,
                    format!("Cloudflare challenge ({})", mitigated),
                    status,
                    headers,
                    body,
                    vendor.or(Some("cloudflare".into())),
                ));
            }
            return Some(Self::waf_info(
                ErrorType::WafBlocked,
                WafConfidence::High,
                format!("Cloudflare mitigation ({})", mitigated),
                status,
                headers,
                body,
                vendor.or(Some("cloudflare".into())),
            ));
        }

        // Strong body signatures (work on 200 challenge pages too)
        if let Some((kind, label)) = Self::match_block_body(&body_l) {
            return Some(Self::waf_info(
                kind,
                WafConfidence::High,
                label,
                status,
                headers,
                body,
                vendor,
            ));
        }

        // Rate limit
        if status == 429
            || (headers_l.contains_key("retry-after") && body_l.contains("rate"))
        {
            return Some(Self::waf_info(
                ErrorType::RateLimited,
                WafConfidence::High,
                "Rate limited (429 / Retry-After)".into(),
                status,
                headers,
                body,
                vendor,
            ));
        }

        // Hard block statuses need a supporting signal — never "any 403"
        if matches!(status, 403 | 406 | 418 | 503) {
            if Self::has_block_header(&headers_l) {
                return Some(Self::waf_info(
                    ErrorType::WafBlocked,
                    WafConfidence::High,
                    format!("WAF block headers with HTTP {}", status),
                    status,
                    headers,
                    body,
                    vendor,
                ));
            }

            // Soft: blocking status behind a known CDN, no clear page signature
            if vendor.is_some() && status == 403 {
                return Some(Self::waf_info(
                    ErrorType::WafBlocked,
                    WafConfidence::Low,
                    format!(
                        "HTTP {} behind {} (may be WAF or normal forbid)",
                        status,
                        vendor.as_deref().unwrap_or("CDN")
                    ),
                    status,
                    headers,
                    body,
                    vendor,
                ));
            }
        }

        None
    }

    pub fn detect_request_error(error: &anyhow::Error) -> Option<ErrorInfo> {
        let error_msg = error.to_string().to_lowercase();

        if error_msg.contains("timeout") || error_msg.contains("timed out") {
            return Some(ErrorInfo {
                error_type: ErrorType::ConnectionTimeout,
                message: "Connection timeout - website may be slow or unresponsive".into(),
                status_code: None,
                headers: HashMap::new(),
                body_snippet: None,
                confidence: WafConfidence::High,
                vendor: None,
            });
        }

        if error_msg.contains("dns")
            || error_msg.contains("resolve")
            || error_msg.contains("name resolution")
        {
            return Some(ErrorInfo {
                error_type: ErrorType::DnsError,
                message: "DNS resolution failed - website may be down or domain invalid".into(),
                status_code: None,
                headers: HashMap::new(),
                body_snippet: None,
                confidence: WafConfidence::High,
                vendor: None,
            });
        }

        if error_msg.contains("ssl")
            || error_msg.contains("tls")
            || error_msg.contains("certificate")
        {
            return Some(ErrorInfo {
                error_type: ErrorType::SslError,
                message: "SSL/TLS error - certificate issue or connection problem".into(),
                status_code: None,
                headers: HashMap::new(),
                body_snippet: None,
                confidence: WafConfidence::High,
                vendor: None,
            });
        }

        if error_msg.contains("connection refused")
            || error_msg.contains("connection reset")
            || error_msg.contains("failed to connect")
            || error_msg.contains("network unreachable")
        {
            return Some(ErrorInfo {
                error_type: ErrorType::WebsiteDown,
                message: "Connection failed - website may be down or unreachable".into(),
                status_code: None,
                headers: HashMap::new(),
                body_snippet: None,
                confidence: WafConfidence::High,
                vendor: None,
            });
        }

        if error_msg.contains("rate limit") || error_msg.contains("too many requests") {
            return Some(ErrorInfo {
                error_type: ErrorType::RateLimited,
                message: "Rate limited - too many requests".into(),
                status_code: Some(429),
                headers: HashMap::new(),
                body_snippet: None,
                confidence: WafConfidence::High,
                vendor: None,
            });
        }

        None
    }

    /// Classify response errors. WAF only when `detect_waf` agrees — plain 403/404 are not WAF.
    pub fn detect_response_error_with_status(
        status: u16,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> Option<ErrorInfo> {
        if let Some(waf) = Self::detect_waf(status, headers, body) {
            // Only surface high-confidence WAF / rate-limit as alerts by default
            if waf.confidence == WafConfidence::High
                || matches!(waf.error_type, ErrorType::RateLimited)
            {
                return Some(waf);
            }
            // Low confidence: fall through to generic status handling (e.g. PermissionDenied)
        }

        match status {
            404 => Some(ErrorInfo {
                error_type: ErrorType::NotFound,
                message: "Resource not found (404)".into(),
                status_code: Some(status),
                headers: headers.clone(),
                body_snippet: None,
                confidence: WafConfidence::High,
                vendor: None,
            }),
            403 => Some(ErrorInfo {
                error_type: ErrorType::PermissionDenied,
                message: "Permission denied (403)".into(),
                status_code: Some(status),
                headers: headers.clone(),
                body_snippet: Self::extract_body_snippet(body),
                confidence: WafConfidence::High,
                vendor: None,
            }),
            429 => Some(ErrorInfo {
                error_type: ErrorType::RateLimited,
                message: "Rate limited (429)".into(),
                status_code: Some(status),
                headers: headers.clone(),
                body_snippet: Self::extract_body_snippet(body),
                confidence: WafConfidence::High,
                vendor: None,
            }),
            s if s >= 500 => Some(ErrorInfo {
                error_type: ErrorType::WebsiteDown,
                message: format!("Server error ({})", s),
                status_code: Some(s),
                headers: headers.clone(),
                body_snippet: Self::extract_body_snippet(body),
                confidence: WafConfidence::High,
                vendor: None,
            }),
            _ => None,
        }
    }

    /// Print alert. WAF/challenge alerts are shown at most once per process unless `verbose`.
    pub fn alert_error(error_info: &ErrorInfo, verbose: bool) {
        // Skip noisy expected errors unless verbose
        if !verbose
            && matches!(
                error_info.error_type,
                ErrorType::NotFound | ErrorType::PermissionDenied
            )
        {
            return;
        }

        let is_waf = matches!(
            error_info.error_type,
            ErrorType::WafBlocked | ErrorType::WafChallenge
        );

        if is_waf && !verbose {
            if WAF_ALERT_SHOWN.swap(true, Ordering::Relaxed) {
                return;
            }
        }

        let (icon, color) = match error_info.error_type {
            ErrorType::WafBlocked | ErrorType::WafChallenge => ("⚠", "yellow"),
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

        if is_waf {
            let kind = if error_info.error_type == ErrorType::WafChallenge {
                "WAF challenge"
            } else {
                "WAF block"
            };
            let vendor = error_info
                .vendor
                .as_deref()
                .map(|v| format!(" [{}]", v))
                .unwrap_or_default();
            let status = error_info
                .status_code
                .map(|s| format!(" HTTP {}", s))
                .unwrap_or_default();

            eprintln!(
                "\n{} {} {}{}{}",
                icon_colored,
                "[ALERT]".bright_red().bold(),
                kind.bright_yellow(),
                vendor.bright_cyan(),
                status.bright_cyan()
            );
            if verbose {
                eprintln!("   {}", error_info.message.bright_black());
            }
            eprintln!(
                "   {} Retry with --waf-bypass (browser headers + throttling), or --force to continue anyway",
                "→".bright_blue()
            );
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
                if let Some(snippet) = &error_info.body_snippet {
                    eprintln!("   Response snippet: {}", snippet.bright_black());
                }
            }
            match error_info.error_type {
                ErrorType::RateLimited => {
                    eprintln!(
                        "   {} Reduce rate or use --waf-bypass throttling",
                        "→".bright_blue()
                    );
                }
                ErrorType::WebsiteDown | ErrorType::ConnectionTimeout => {
                    eprintln!(
                        "   {} Verify the site is reachable",
                        "→".bright_blue()
                    );
                }
                _ => {}
            }
        }
        eprintln!();
    }

    fn waf_info(
        error_type: ErrorType,
        confidence: WafConfidence,
        message: String,
        status: u16,
        headers: &HashMap<String, String>,
        body: &str,
        vendor: Option<String>,
    ) -> ErrorInfo {
        ErrorInfo {
            error_type,
            message,
            status_code: Some(status),
            headers: headers.clone(),
            body_snippet: Self::extract_body_snippet(body),
            confidence,
            vendor,
        }
    }

    fn guess_vendor(headers_l: &HashMap<String, String>, body_l: &str) -> Option<String> {
        if headers_l.contains_key("cf-ray")
            || headers_l
                .get("server")
                .map(|s| s.to_lowercase().contains("cloudflare"))
                .unwrap_or(false)
            || body_l.contains("cloudflare")
        {
            return Some("cloudflare".into());
        }
        if headers_l.keys().any(|k| k.contains("sucuri")) || body_l.contains("sucuri") {
            return Some("sucuri".into());
        }
        if body_l.contains("incapsula") || headers_l.contains_key("x-iinfo") {
            return Some("incapsula".into());
        }
        if body_l.contains("akamai") || headers_l.contains_key("x-akamai-transformed") {
            return Some("akamai".into());
        }
        if body_l.contains("mod_security") || body_l.contains("modsecurity") {
            return Some("modsecurity".into());
        }
        if body_l.contains("imunify") {
            return Some("imunify360".into());
        }
        if headers_l.contains_key("x-waf") || headers_l.contains_key("x-blocked-by") {
            return Some("generic-waf".into());
        }
        None
    }

    fn has_block_header(headers_l: &HashMap<String, String>) -> bool {
        headers_l.contains_key("x-sucuri-block")
            || headers_l.contains_key("x-blocked-by")
            || headers_l.contains_key("x-waf-event")
            || headers_l
                .get("server")
                .map(|s| s.to_lowercase().contains("imunify360"))
                .unwrap_or(false)
    }

    fn match_block_body(body_l: &str) -> Option<(ErrorType, String)> {
        let challenge_patterns = [
            ("just a moment", "Cloudflare JS challenge page"),
            ("cf-browser-verification", "Cloudflare browser verification"),
            ("cf-challenge", "Cloudflare challenge"),
            ("checking your browser", "Browser check / challenge"),
            ("attention required", "Cloudflare attention required"),
            ("enable javascript and cookies", "JS/cookie challenge"),
        ];
        for (pat, label) in challenge_patterns {
            if body_l.contains(pat) {
                return Some((ErrorType::WafChallenge, label.into()));
            }
        }

        let block_patterns = [
            ("sorry, you have been blocked", "Cloudflare hard block"),
            ("you have been blocked", "WAF hard block"),
            ("your request has been blocked", "Request blocked by WAF"),
            ("access denied", "Access denied page"), // careful - many WP pages say this
            ("the owner of this website has banned your access", "IP banned by WAF"),
            ("this website is using a security service", "Security service interstitial"),
            ("sucuri website firewall", "Sucuri firewall block"),
            ("incapsula incident id", "Incapsula block"),
            ("mod_security", "ModSecurity block"),
            ("imunify360", "Imunify360 block"),
            ("request rejected", "Request rejected by WAF"),
            ("cf-error-details", "Cloudflare error details"),
            ("error 1020", "Cloudflare Error 1020 (Access Denied)"),
            ("error 1015", "Cloudflare Error 1015 (Rate Limited)"),
        ];

        for (pat, label) in block_patterns {
            if body_l.contains(pat) {
                // "access denied" alone is too weak without other context
                if pat == "access denied"
                    && !body_l.contains("cloudflare")
                    && !body_l.contains("firewall")
                    && !body_l.contains("waf")
                    && !body_l.contains("security")
                {
                    continue;
                }
                return Some((ErrorType::WafBlocked, label.into()));
            }
        }

        None
    }

    fn extract_body_snippet(body: &str) -> Option<String> {
        let snippet: String = body.chars().take(200).collect();
        if snippet.is_empty() {
            None
        } else {
            Some(snippet)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn cdn_headers_alone_not_a_block() {
        let h = headers(&[("cf-ray", "abc-123"), ("server", "cloudflare")]);
        // Normal 200 homepage behind Cloudflare
        assert!(ErrorDetector::detect_waf(200, &h, "<html>WordPress</html>").is_none());
        // Plain 403 without block page → low confidence only
        let r = ErrorDetector::detect_waf(403, &h, "Forbidden");
        assert!(r.is_some());
        assert_eq!(r.unwrap().confidence, WafConfidence::Low);
    }

    #[test]
    fn cloudflare_challenge_page_is_high() {
        let h = headers(&[("cf-ray", "abc")]);
        let body = "<html>Just a moment... cf-browser-verification</html>";
        let r = ErrorDetector::detect_waf(403, &h, body).unwrap();
        assert_eq!(r.error_type, ErrorType::WafChallenge);
        assert_eq!(r.confidence, WafConfidence::High);
    }

    #[test]
    fn cf_mitigated_header() {
        let h = headers(&[("cf-mitigated", "challenge"), ("cf-ray", "x")]);
        let r = ErrorDetector::detect_waf(403, &h, "").unwrap();
        assert_eq!(r.error_type, ErrorType::WafChallenge);
        assert_eq!(r.confidence, WafConfidence::High);
    }

    #[test]
    fn plain_403_not_surfaced_as_waf_alert() {
        let h = headers(&[("server", "nginx")]);
        // No CDN → detect_waf returns None; response classifier → PermissionDenied
        assert!(ErrorDetector::detect_waf(403, &h, "Forbidden").is_none());
        let e = ErrorDetector::detect_response_error_with_status(403, &h, "Forbidden").unwrap();
        assert_eq!(e.error_type, ErrorType::PermissionDenied);
    }

    #[test]
    fn low_confidence_not_returned_from_response_classifier() {
        let h = headers(&[("cf-ray", "abc"), ("server", "cloudflare")]);
        // Low confidence WAF must not spam via detect_response_error_with_status
        let e = ErrorDetector::detect_response_error_with_status(403, &h, "Forbidden");
        // Falls through to PermissionDenied OR None for low waf — we return None for low then PermissionDenied
        assert!(e.is_some());
        assert_eq!(e.unwrap().error_type, ErrorType::PermissionDenied);
    }

    #[test]
    fn hard_block_body() {
        let h = headers(&[("cf-ray", "x")]);
        let body = "Sorry, you have been blocked. Cloudflare Error 1020";
        let r = ErrorDetector::detect_waf(403, &h, body).unwrap();
        assert_eq!(r.error_type, ErrorType::WafBlocked);
        assert_eq!(r.confidence, WafConfidence::High);
    }
}
