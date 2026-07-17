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

        let entries =
            fs::read_dir(dir).with_context(|| format!("Failed to read directory: {}", dir))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                match Self::load_template(path.to_str().unwrap()) {
                    Ok(template) => templates.push(template),
                    Err(e) => {
                        eprintln!("Warning: Failed to load template {:?}: {}", path, e);
                    }
                }
            }
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
}
