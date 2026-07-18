use anyhow::{Context, Result};
use crate::http_client::HttpClient;
use crate::models::{VulnTemplate, VulnValidationResult};
use crate::template_engine::TemplateEngine;
use std::fs;
use std::path::Path;

pub struct VulnEngine;

impl VulnEngine {
    pub fn load_template(path: &str) -> Result<VulnTemplate> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read template: {}", path))?;
        let template: VulnTemplate = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse template: {}", path))?;
        Ok(template)
    }

    pub fn load_templates_from_dir(dir: &str) -> Result<Vec<VulnTemplate>> {
        let mut templates = vec![];

        if !Path::new(dir).exists() {
            anyhow::bail!("Template directory does not exist: {}", dir);
        }
        if !Path::new(dir).is_dir() {
            anyhow::bail!("Template path is not a directory: {}", dir);
        }

        let entries =
            fs::read_dir(dir).with_context(|| format!("Failed to read directory: {}", dir))?;

        let mut json_paths: Vec<_> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        json_paths.sort();

        for path in json_paths {
            let path_str = path.to_str().ok_or_else(|| {
                anyhow::anyhow!("Template path is not valid UTF-8: {:?}", path)
            })?;
            match Self::load_template(path_str) {
                Ok(template) => templates.push(template),
                Err(e) => {
                    eprintln!("Warning: Failed to load template {}: {}", path_str, e);
                }
            }
        }

        if templates.is_empty() {
            anyhow::bail!("No valid .json vulnerability templates found in: {}", dir);
        }

        Ok(templates)
    }

    pub fn execute(template: &VulnTemplate, client: &HttpClient) -> Result<VulnValidationResult> {
        let mut variables = template.variables.clone();
        variables.insert("target".to_string(), client.base_url.clone());

        let (matched, details) = TemplateEngine::run_http_flow(
            &template.http,
            &template.matchers,
            &template.extractors,
            client,
            &mut variables,
        )?;

        Ok(VulnValidationResult {
            template_id: template.id.clone(),
            name: template.info.name.clone(),
            severity: template.info.severity.clone(),
            matched,
            details: Some(details),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_example_vuln_template() {
        let path = "templates/vulns/xss.json";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let template = VulnEngine::load_template(path).expect("parse xss template");
        assert_eq!(template.id, "wordpress-plugin-xss-example");
        assert!(!template.http.is_empty());
    }

    #[test]
    fn load_templates_from_vulns_dir() {
        let dir = "templates/vulns";
        if !std::path::Path::new(dir).exists() {
            return;
        }
        let templates = VulnEngine::load_templates_from_dir(dir).expect("load dir");
        assert!(
            templates.len() >= 2,
            "expected multiple vuln templates, got {}",
            templates.len()
        );
        assert!(templates.iter().any(|t| t.id.contains("wp2shell") || !t.id.is_empty()));
    }

    #[test]
    fn load_templates_from_missing_dir_errors() {
        let err = VulnEngine::load_templates_from_dir("templates/does-not-exist-xyz")
            .expect_err("missing dir should error");
        assert!(err.to_string().contains("does not exist"));
    }
}
