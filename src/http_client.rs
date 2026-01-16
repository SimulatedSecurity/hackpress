use anyhow::{Context, Result};
use rand::Rng;
use reqwest::blocking::{Client, ClientBuilder, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT, ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, REFERER};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use url::Url;
use colored::*;
use std::sync::atomic::AtomicBool;

pub struct HttpClient {
    client: Client,
    waf_bypass: bool,
    stealth: bool,
    pub base_url: String,
    #[allow(dead_code)]
    waf_detected: std::sync::Arc<std::sync::atomic::AtomicBool>,
    current_user_agent: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    last_referer: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    request_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

// Common user agents for WAF bypass
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
];

impl HttpClient {
    pub fn new(base_url: String, waf_bypass: bool, stealth: bool) -> Result<Self> {
        let builder = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(10))
            .cookie_store(true)
            // Use native TLS for better fingerprint matching
            .tls_built_in_root_certs(true);

        let client = builder.build().context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            waf_bypass,
            stealth,
            base_url,
            waf_detected: std::sync::Arc::new(AtomicBool::new(false)),
            current_user_agent: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_referer: std::sync::Arc::new(std::sync::Mutex::new(None)),
            request_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }
    
    #[allow(dead_code)]
    pub fn is_waf_detected(&self) -> bool {
        self.waf_detected.load(std::sync::atomic::Ordering::Relaxed)
    }
    
    #[allow(dead_code)]
    pub fn set_waf_detected(&self) {
        self.waf_detected.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get(&self, path: &str, headers: Option<HashMap<String, String>>) -> Result<Response> {
        let url = self.build_url(path)?;
        let mut request = self.client.get(&url);

        request = self.add_headers(request, headers, "GET", &url)?;

        let start_time = Instant::now();
        let response = request.send().map_err(|e| {
            // Detect connection/network errors
            if let Some(error_info) = crate::error_detection::ErrorDetector::detect_request_error(&anyhow::anyhow!("{}", e)) {
                crate::error_detection::ErrorDetector::alert_error(&error_info, false);
            }
            e
        }).context("Failed to send GET request")?;
        
        let elapsed = start_time.elapsed();
        self.check_response_time(&url, elapsed);
        
        // Update referer for next request
        if self.waf_bypass {
            let mut referer_guard = self.last_referer.lock().unwrap();
            *referer_guard = Some(url.clone());
        }
        
        Ok(response)
    }
    

    pub fn post(
        &self,
        path: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<&str>,
    ) -> Result<Response> {
        let url = self.build_url(path)?;
        let mut request = self.client.post(&url);

        request = self.add_headers(request, headers, "POST", &url)?;

        if let Some(body) = body {
            request = request.body(body.to_string());
        }

        let start_time = Instant::now();
        let response = request.send().map_err(|e| {
            // Detect connection/network errors
            if let Some(error_info) = crate::error_detection::ErrorDetector::detect_request_error(&anyhow::anyhow!("{}", e)) {
                crate::error_detection::ErrorDetector::alert_error(&error_info, false);
            }
            e
        }).context("Failed to send POST request")?;
        
        let elapsed = start_time.elapsed();
        self.check_response_time(&url, elapsed);
        
        // Update referer for next request
        if self.waf_bypass {
            let mut referer_guard = self.last_referer.lock().unwrap();
            *referer_guard = Some(url.clone());
        }
        
        Ok(response)
    }

    pub fn put(
        &self,
        path: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<&str>,
    ) -> Result<Response> {
        let url = self.build_url(path)?;
        let mut request = self.client.put(&url);

        request = self.add_headers(request, headers, "PUT", &url)?;

        if let Some(body) = body {
            request = request.body(body.to_string());
        }

        let start_time = Instant::now();
        let response = request.send().map_err(|e| {
            if let Some(error_info) = crate::error_detection::ErrorDetector::detect_request_error(&anyhow::anyhow!("{}", e)) {
                crate::error_detection::ErrorDetector::alert_error(&error_info, false);
            }
            e
        }).context("Failed to send PUT request")?;
        
        let elapsed = start_time.elapsed();
        self.check_response_time(&url, elapsed);
        
        // Update referer for next request
        if self.waf_bypass {
            let mut referer_guard = self.last_referer.lock().unwrap();
            *referer_guard = Some(url.clone());
        }
        
        Ok(response)
    }

    pub fn delete(&self, path: &str, headers: Option<HashMap<String, String>>) -> Result<Response> {
        let url = self.build_url(path)?;
        let mut request = self.client.delete(&url);

        request = self.add_headers(request, headers, "DELETE", &url)?;

        let start_time = Instant::now();
        let response = request.send().map_err(|e| {
            if let Some(error_info) = crate::error_detection::ErrorDetector::detect_request_error(&anyhow::anyhow!("{}", e)) {
                crate::error_detection::ErrorDetector::alert_error(&error_info, false);
            }
            e
        }).context("Failed to send DELETE request")?;
        
        let elapsed = start_time.elapsed();
        self.check_response_time(&url, elapsed);
        
        // Update referer for next request
        if self.waf_bypass {
            let mut referer_guard = self.last_referer.lock().unwrap();
            *referer_guard = Some(url.clone());
        }
        
        Ok(response)
    }
    
    fn build_url(&self, path: &str) -> Result<String> {
        if path.starts_with("http://") || path.starts_with("https://") {
            return Ok(path.to_string());
        }

        let base = Url::parse(&self.base_url)
            .context("Failed to parse base URL")?;
        let url = base.join(path).context("Failed to join URL")?;
        Ok(url.to_string())
    }

    fn add_headers(
        &self,
        request: reqwest::blocking::RequestBuilder,
        custom_headers: Option<HashMap<String, String>>,
        method: &str,
        _url: &str,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        let mut headers = HeaderMap::new();
        let request_count = self.request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Add user agent (consistent across requests when WAF bypass or stealth is enabled)
        let user_agent = if self.waf_bypass || self.stealth {
            // Use consistent user agent for the session
            let mut ua_guard = self.current_user_agent.lock().unwrap();
            if ua_guard.is_none() {
                *ua_guard = Some(self.random_user_agent());
            }
            ua_guard.as_ref().unwrap().clone()
        } else {
            format!("hackpress/{}", crate::constants::VERSION)
        };
        headers.insert(USER_AGENT, HeaderValue::from_str(&user_agent)?);

        // Add browser-like headers when WAF bypass is enabled (stealth mode uses minimal headers)
        if self.waf_bypass {
            let is_chrome = user_agent.contains("Chrome") && !user_agent.contains("Edg");
            let is_firefox = user_agent.contains("Firefox");
            let is_navigation = method == "GET" && request_count == 0;
            
            // Accept header
            if is_chrome {
                headers.insert(ACCEPT, HeaderValue::from_str("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")?);
            } else if is_firefox {
                headers.insert(ACCEPT, HeaderValue::from_str("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")?);
            } else {
                headers.insert(ACCEPT, HeaderValue::from_str("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")?);
            }
            
            headers.insert(ACCEPT_ENCODING, HeaderValue::from_str("gzip, deflate, br")?);
            headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_str("en-US,en;q=0.9")?);
            
            // Referer
            if request_count > 0 {
                let referer_guard = self.last_referer.lock().unwrap();
                if let Some(ref last_url) = *referer_guard {
                    headers.insert(REFERER, HeaderValue::from_str(last_url)?);
                }
            }
            
            // DNT
            if is_chrome || is_firefox {
                headers.insert(HeaderName::from_bytes(b"dnt")?, HeaderValue::from_str("1")?);
            }
            
            // Viewport-Width (Chrome)
            if is_chrome {
                let viewport_width = rand::thread_rng().gen_range(1920..2560);
                headers.insert(HeaderName::from_bytes(b"viewport-width")?, HeaderValue::from_str(&viewport_width.to_string())?);
            }
            
            // Sec-Fetch-* headers
            if is_chrome || is_firefox {
                let sec_fetch_site = if request_count == 0 { "none" } else { "same-origin" };
                let sec_fetch_mode = if is_navigation { "navigate" } else { "no-cors" };
                let sec_fetch_dest = if is_navigation { "document" } else { "empty" };
                
                headers.insert(HeaderName::from_bytes(b"sec-fetch-site")?, HeaderValue::from_str(sec_fetch_site)?);
                headers.insert(HeaderName::from_bytes(b"sec-fetch-mode")?, HeaderValue::from_str(sec_fetch_mode)?);
                headers.insert(HeaderName::from_bytes(b"sec-fetch-dest")?, HeaderValue::from_str(sec_fetch_dest)?);
                if is_navigation {
                    headers.insert(HeaderName::from_bytes(b"sec-fetch-user")?, HeaderValue::from_str("?1")?);
                }
            }
            
            headers.insert(HeaderName::from_bytes(b"connection")?, HeaderValue::from_str("keep-alive")?);
            headers.insert(HeaderName::from_bytes(b"upgrade-insecure-requests")?, HeaderValue::from_str("1")?);
            if !is_navigation {
                headers.insert(HeaderName::from_bytes(b"cache-control")?, HeaderValue::from_str("max-age=0")?);
            }
        }

        // Add custom headers
        if let Some(custom) = custom_headers {
            for (key, value) in custom {
                let header_name = HeaderName::from_bytes(key.as_bytes())
                    .context("Invalid header name")?;
                headers.insert(header_name, HeaderValue::from_str(&value)?);
            }
        }

        // WAF bypass: throttle requests to avoid rate limiting
        if self.waf_bypass {
            if request_count == 0 {
                // First request: 2-3 seconds delay (simulates initial page load)
                std::thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(2000..3000)));
            } else {
                // Subsequent requests: 1-3 seconds delay (throttled to avoid detection)
                let delay = rand::thread_rng().gen_range(1000..3000);
                std::thread::sleep(Duration::from_millis(delay));
            }
        }

        Ok(request.headers(headers))
    }
    

    fn random_user_agent(&self) -> String {
        let idx = rand::thread_rng().gen_range(0..USER_AGENTS.len());
        USER_AGENTS[idx].to_string()
    }

    #[allow(dead_code)]
    pub fn get_text(&self, path: &str, headers: Option<HashMap<String, String>>) -> Result<String> {
        let response = self.get(path, headers)?;
        let text = response.text().context("Failed to read response text")?;
        Ok(text)
    }

    #[allow(dead_code)]
    pub fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        headers: Option<HashMap<String, String>>,
    ) -> Result<T> {
        let response = self.get(path, headers)?;
        let json: T = response.json().context("Failed to parse JSON response")?;
        Ok(json)
    }

    fn check_response_time(&self, url: &str, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        
        // Threshold for throttling warning: 5 seconds
        if seconds >= 5.0 && seconds < 15.0 {
            eprintln!("{} Request to {} took {:.2}s - Possible throttling detected", 
                "⚠".bright_yellow(), 
                url.bright_cyan(), 
                seconds);
            eprintln!();
        }
        // Threshold for very slow response: 15 seconds
        else if seconds >= 15.0 {
            eprintln!("{} Request to {} took {:.2}s - Very slow response, possible rate limiting or server issues", 
                "⚠".bright_red().bold(), 
                url.bright_cyan(), 
                seconds);
            eprintln!();
        }
    }
}
