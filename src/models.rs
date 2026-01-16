use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Vulnerability database models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityDatabase {
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    #[serde(rename = "type")]
    pub vuln_type: String, // plugin, theme, or core
    pub target: String,
    pub affected_versions: Vec<String>,
    pub severity: String,
    pub description: String,
    pub references: Vec<String>,
    pub exploit_template: Option<String>,
}

// Template models (Nuclei-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitTemplate {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default)]
    pub http: Vec<HttpRequest>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnTemplate {
    pub id: String,
    pub info: TemplateInfo,
    #[serde(default)]
    pub variables: HashMap<String, String>,
    #[serde(default)]
    pub http: Vec<HttpRequest>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    pub author: Vec<String>,
    pub severity: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub reference: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub raw: Vec<String>,
    #[serde(default)]
    pub max_redirects: Option<u32>,
    #[serde(default)]
    pub cookie_reuse: bool,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub matcher_type: String, // word, regex, status, size, etc.
    #[serde(default)]
    pub part: String, // body, header, url, all, etc.
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub size: Vec<usize>,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(default)]
    pub negative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extractor {
    #[serde(rename = "type")]
    pub extractor_type: String, // regex, json, xpath, etc.
    #[serde(default)]
    pub part: String,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub json: Vec<String>,
    #[serde(default)]
    pub group: Option<usize>,
    #[serde(default)]
    pub group_name: Option<String>,
}

// Scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub target: String,
    pub tech_stack: Option<TechStackInfo>,
    pub robots_txt: Option<RobotsTxtInfo>,
    pub wordpress: Option<WordPressInfo>,
    pub wordpress_config: Option<WordPressConfig>,
    pub plugins: Vec<DetectedPlugin>,
    pub themes: Vec<DetectedTheme>,
    pub vulnerabilities: Vec<FoundVulnerability>,
    pub vuln_validations: Vec<VulnValidationResult>,
    pub exploit_results: Vec<ExploitResult>,
    pub usernames: Vec<EnumeratedUsername>,
    pub file_disclosures: Vec<FileDisclosure>,
    pub bruteforce_results: Option<BruteforceResults>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechStackInfo {
    pub ip: Option<String>,
    pub country: Option<String>,
    pub ip_info: Option<String>, // ASN or other IP information
    pub server: Option<String>,
    pub php_version: Option<String>,
    pub cdn: Option<String>,
    pub security_headers: Vec<String>,
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub relevant_headers: Vec<(String, String)>, // Headers like x-powered-by, PleskLin, etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotsTxtInfo {
    pub disallowed: Vec<String>,
    pub sitemap: Vec<String>,
    pub findings: Vec<String>,
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordPressInfo {
    pub version: Option<String>,
    pub detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordPressConfig {
    pub xmlrpc_enabled: bool,
    pub comments_allowed: bool,
    pub signup_enabled: bool,
    pub login_path: Option<String>, // None if standard (wp-login.php) is valid, Some(path) if different path is valid
    #[serde(default)]
    pub login_path_validated: bool, // true if we validated that standard or alternative path works
    #[serde(default)]
    pub path_disclosure: Option<String>, // Disclosed path if found in error messages
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPlugin {
    pub slug: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTheme {
    pub slug: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub text_domain: Option<String>, // Used for SVN lookup
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundVulnerability {
    pub id: String,
    pub severity: String,
    pub description: String,
    pub affected_component: String,
    pub component_version: String,
    pub affected_versions: Vec<String>,
    pub references: Vec<String>,
    pub vuln_type: String, // core, theme, or plugin
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnValidationResult {
    pub template_id: String,
    pub name: String,
    pub severity: String,
    pub matched: bool,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitResult {
    pub template_id: String,
    pub name: String,
    pub severity: String,
    pub success: bool,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDisclosure {
    pub path: String,
    pub file_type: String,
    pub accessible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteforceResults {
    pub successful: Vec<Credential>,
    pub failed_count: usize,
    pub total_attempts: usize,
    pub account_lockouts: usize,
    pub captcha_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumeratedUsername {
    pub username: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: String,
    pub endpoint: String,
}
