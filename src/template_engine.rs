use anyhow::Result;
use crate::http_client::HttpClient;
use crate::models::{Extractor, HttpRequest, Matcher};
use regex::Regex;
use std::collections::HashMap;

/// Shared Nuclei-style template execution helpers (matchers, extractors, HTTP).
pub struct TemplateEngine;

pub struct RequestOutcome {
    pub body: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
}

impl TemplateEngine {
    pub fn substitute_variables(text: &str, variables: &HashMap<String, String>) -> String {
        let mut result = text.to_string();
        for (key, value) in variables {
            let placeholder = format!("{{{{{}}}}}", key);
            result = result.replace(&placeholder, value);
        }
        result
    }

    pub fn execute_request(
        request: &HttpRequest,
        client: &HttpClient,
        variables: &mut HashMap<String, String>,
    ) -> Result<RequestOutcome> {
        let response = if !request.raw.is_empty() {
            let raw = Self::substitute_variables(&request.raw[0], variables);
            client.raw_request(&raw, request.max_redirects, request.cookie_reuse)?
        } else {
            let method = if request.method.is_empty() {
                "GET".to_string()
            } else {
                request.method.to_uppercase()
            };
            let path = if request.path.is_empty() {
                "".to_string()
            } else {
                Self::substitute_variables(&request.path[0], variables)
            };

            let headers = if request.headers.is_empty() {
                None
            } else {
                let mut header_map = HashMap::new();
                for (key, value) in &request.headers {
                    header_map.insert(key.clone(), Self::substitute_variables(value, variables));
                }
                Some(header_map)
            };

            let body = request
                .body
                .as_ref()
                .map(|b| Self::substitute_variables(b, variables));

            client.request(
                &method,
                &path,
                headers,
                body.as_deref(),
                request.max_redirects,
                request.cookie_reuse,
            )?
        };

        let status = response.status().as_u16();
        let mut headers_map = HashMap::new();
        for (name, value) in response.headers() {
            headers_map.insert(
                name.as_str().to_lowercase(),
                value.to_str().unwrap_or("").to_string(),
            );
        }
        let body_text = response.text().unwrap_or_default();

        let outcome = RequestOutcome {
            body: body_text,
            status,
            headers: headers_map,
        };

        // Request-level extractors update variables for subsequent requests
        Self::apply_extractors(&request.extractors, &outcome, variables);

        Ok(outcome)
    }

    pub fn match_response(
        matchers: &[Matcher],
        body: &str,
        headers: &HashMap<String, String>,
        status: u16,
    ) -> bool {
        for matcher in matchers {
            let matched = match matcher.matcher_type.as_str() {
                "status" => {
                    if matcher.status.is_empty() {
                        true
                    } else {
                        matcher.status.contains(&status)
                    }
                }
                "word" | "words" => {
                    let text = Self::matcher_text(&matcher.part, body, headers);
                    if matcher.words.is_empty() {
                        true
                    } else {
                        let case_insensitive = matcher.case_insensitive;
                        matcher.words.iter().any(|word| {
                            if case_insensitive {
                                text.to_lowercase().contains(&word.to_lowercase())
                            } else {
                                text.contains(word)
                            }
                        })
                    }
                }
                "regex" => {
                    let text = Self::matcher_text(&matcher.part, body, headers);
                    if matcher.regex.is_empty() {
                        true
                    } else {
                        matcher.regex.iter().any(|pattern| {
                            Regex::new(pattern)
                                .map(|re| re.is_match(&text))
                                .unwrap_or(false)
                        })
                    }
                }
                "size" => {
                    let size = body.len();
                    if matcher.size.is_empty() {
                        true
                    } else {
                        matcher.size.contains(&size)
                    }
                }
                _ => true,
            };

            if matcher.negative {
                if matched {
                    return false;
                }
            } else if !matched {
                return false;
            }
        }

        true
    }

    pub fn apply_extractors(
        extractors: &[Extractor],
        outcome: &RequestOutcome,
        variables: &mut HashMap<String, String>,
    ) {
        for extractor in extractors {
            if let Some((name, value)) = Self::run_extractor(extractor, outcome) {
                variables.insert(name, value);
            }
        }
    }

    fn run_extractor(extractor: &Extractor, outcome: &RequestOutcome) -> Option<(String, String)> {
        let var_name = extractor
            .name
            .clone()
            .or_else(|| extractor.group_name.clone())?;

        let part = if extractor.part.is_empty() {
            "body"
        } else {
            extractor.part.as_str()
        };
        let text = Self::matcher_text(part, &outcome.body, &outcome.headers);

        let value = match extractor.extractor_type.as_str() {
            "regex" => Self::extract_regex(extractor, &text)?,
            "json" => Self::extract_json(extractor, &outcome.body)?,
            _ => return None,
        };

        Some((var_name, value))
    }

    fn extract_regex(extractor: &Extractor, text: &str) -> Option<String> {
        let group = extractor.group.unwrap_or(0);
        for pattern in &extractor.regex {
            let re = Regex::new(pattern).ok()?;
            if let Some(caps) = re.captures(text) {
                if let Some(m) = caps.get(group) {
                    return Some(m.as_str().to_string());
                }
                // Fallback to full match
                if let Some(m) = caps.get(0) {
                    return Some(m.as_str().to_string());
                }
            }
        }
        None
    }

    fn extract_json(extractor: &Extractor, body: &str) -> Option<String> {
        let value: serde_json::Value = serde_json::from_str(body).ok()?;
        for path in &extractor.json {
            if let Some(found) = Self::json_path(&value, path) {
                return Some(match found {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string().trim_matches('"').to_string(),
                });
            }
        }
        None
    }

    /// Supports `token`, `data.token`, or JSON pointer `/data/token`.
    fn json_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
        if path.starts_with('/') {
            return value.pointer(path);
        }
        let mut current = value;
        for segment in path.split('.').filter(|s| !s.is_empty()) {
            current = current.get(segment)?;
        }
        Some(current)
    }

    fn matcher_text(part: &str, body: &str, headers: &HashMap<String, String>) -> String {
        match part {
            "header" | "headers" => headers
                .values()
                .map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" "),
            "all" => {
                let header_text = headers
                    .values()
                    .map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("{} {}", header_text, body)
            }
            _ => body.to_string(),
        }
    }

    /// Run HTTP steps + request/template matchers + template-level extractors.
    /// Returns (matched, details).
    pub fn run_http_flow(
        http: &[HttpRequest],
        template_matchers: &[Matcher],
        template_extractors: &[Extractor],
        client: &HttpClient,
        variables: &mut HashMap<String, String>,
    ) -> Result<(bool, String)> {
        let mut last = RequestOutcome {
            body: String::new(),
            status: 0,
            headers: HashMap::new(),
        };

        for request in http {
            last = Self::execute_request(request, client, variables)?;

            if !request.matchers.is_empty()
                && !Self::match_response(
                    &request.matchers,
                    &last.body,
                    &last.headers,
                    last.status,
                )
            {
                return Ok((false, "Request matchers did not match".to_string()));
            }
        }

        Self::apply_extractors(template_extractors, &last, variables);

        let matched = if template_matchers.is_empty() {
            true
        } else {
            Self::match_response(template_matchers, &last.body, &last.headers, last.status)
        };

        let details = if matched {
            let mut parts = vec![format!(
                "Status: {}, Response length: {}",
                last.status,
                last.body.len()
            )];
            let mut seen = std::collections::HashSet::new();
            let mut push_extracted = |name: &str, raw: &str| {
                if seen.insert(name.to_string()) {
                    parts.push(format!("{}={}", name, raw));
                }
            };
            for extractor in template_extractors {
                if let Some(name) = extractor.name.as_ref().or(extractor.group_name.as_ref()) {
                    if let Some(raw) = variables.get(name) {
                        push_extracted(name, raw);
                    }
                }
            }
            for request in http {
                for extractor in &request.extractors {
                    if let Some(name) = extractor.name.as_ref().or(extractor.group_name.as_ref()) {
                        if let Some(raw) = variables.get(name) {
                            push_extracted(name, raw);
                        }
                    }
                }
            }
            parts.join(" | ")
        } else {
            "Matchers did not match".to_string()
        };

        Ok((matched, details))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Matcher;

    fn word_matcher(words: &[&str], part: &str, case_insensitive: bool, negative: bool) -> Matcher {
        Matcher {
            matcher_type: "word".to_string(),
            part: part.to_string(),
            words: words.iter().map(|w| w.to_string()).collect(),
            regex: vec![],
            status: vec![],
            size: vec![],
            case_insensitive,
            negative,
        }
    }

    fn status_matcher(codes: &[u16]) -> Matcher {
        Matcher {
            matcher_type: "status".to_string(),
            part: String::new(),
            words: vec![],
            regex: vec![],
            status: codes.to_vec(),
            size: vec![],
            case_insensitive: false,
            negative: false,
        }
    }

    #[test]
    fn status_matcher_matches() {
        let matchers = vec![status_matcher(&[200, 201])];
        assert!(TemplateEngine::match_response(
            &matchers,
            "",
            &HashMap::new(),
            200
        ));
        assert!(!TemplateEngine::match_response(
            &matchers,
            "",
            &HashMap::new(),
            404
        ));
    }

    #[test]
    fn word_matcher_case_insensitive() {
        let matchers = vec![word_matcher(&["WordPress"], "body", true, false)];
        assert!(TemplateEngine::match_response(
            &matchers,
            "powered by wordpress",
            &HashMap::new(),
            200
        ));
    }

    #[test]
    fn negative_matcher_inverts() {
        let matchers = vec![word_matcher(&["error"], "body", false, true)];
        assert!(TemplateEngine::match_response(
            &matchers,
            "all good",
            &HashMap::new(),
            200
        ));
        assert!(!TemplateEngine::match_response(
            &matchers,
            "error occurred",
            &HashMap::new(),
            200
        ));
    }

    #[test]
    fn regex_matcher() {
        let matchers = vec![Matcher {
            matcher_type: "regex".to_string(),
            part: "body".to_string(),
            words: vec![],
            regex: vec![r"uid=\d+".to_string()],
            status: vec![],
            size: vec![],
            case_insensitive: false,
            negative: false,
        }];
        assert!(TemplateEngine::match_response(
            &matchers,
            "uid=0 gid=0",
            &HashMap::new(),
            200
        ));
    }

    #[test]
    fn substitute_variables() {
        let mut vars = HashMap::new();
        vars.insert("target".to_string(), "https://example.com".to_string());
        vars.insert(
            "plugin_path".to_string(),
            "/wp-content/plugins/x/".to_string(),
        );
        let result = TemplateEngine::substitute_variables("{{target}}{{plugin_path}}vuln.php", &vars);
        assert_eq!(result, "https://example.com/wp-content/plugins/x/vuln.php");
    }

    #[test]
    fn extract_regex_into_variable() {
        let extractor = Extractor {
            extractor_type: "regex".to_string(),
            name: Some("nonce".to_string()),
            part: "body".to_string(),
            regex: vec![r#"name="_wpnonce" value="([^"]+)""#.to_string()],
            json: vec![],
            group: Some(1),
            group_name: None,
        };
        let outcome = RequestOutcome {
            body: r#"<input name="_wpnonce" value="abc123" />"#.to_string(),
            status: 200,
            headers: HashMap::new(),
        };
        let mut vars = HashMap::new();
        TemplateEngine::apply_extractors(&[extractor], &outcome, &mut vars);
        assert_eq!(vars.get("nonce").map(String::as_str), Some("abc123"));
    }

    #[test]
    fn extract_json_dot_path() {
        let extractor = Extractor {
            extractor_type: "json".to_string(),
            name: Some("token".to_string()),
            part: "body".to_string(),
            regex: vec![],
            json: vec!["data.token".to_string()],
            group: None,
            group_name: None,
        };
        let outcome = RequestOutcome {
            body: r#"{"data":{"token":"xyz"}}"#.to_string(),
            status: 200,
            headers: HashMap::new(),
        };
        let mut vars = HashMap::new();
        TemplateEngine::apply_extractors(&[extractor], &outcome, &mut vars);
        assert_eq!(vars.get("token").map(String::as_str), Some("xyz"));
    }

    #[test]
    fn parse_raw_via_substitute() {
        let mut vars = HashMap::new();
        vars.insert("id".to_string(), "42".to_string());
        let raw = TemplateEngine::substitute_variables(
            "GET /wp-json/wp/v2/users/{{id}} HTTP/1.1\nAccept: application/json",
            &vars,
        );
        assert!(raw.contains("/users/42"));
    }
}
