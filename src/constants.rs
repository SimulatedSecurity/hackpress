// Application constants
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Repository and project URLs
pub const REPOSITORY_URL: &str = "https://github.com/simulatedsecurity/hackpress";
pub const GITHUB_REPO_OWNER: &str = "SimulatedSecurity";
pub const GITHUB_REPO_NAME: &str = "hackpress";
pub const GITHUB_BRANCH: &str = "main";

// GitHub API endpoints
pub const GITHUB_API_BASE: &str = "https://api.github.com/repos";
pub const GITHUB_RAW_BASE: &str = "https://raw.githubusercontent.com";

// Database folder on GitHub
pub const GITHUB_DATABASE_PATH: &str = "database";

// Local database directory
pub const DATABASE_DIR: &str = "database";

// WordPress API URLs
pub const WORDPRESS_VERSION_API_URL: &str = "https://api.wordpress.org/core/version-check/1.7/";

// WordPress SVN URLs
pub const WORDPRESS_PLUGINS_SVN_BASE: &str = "https://plugins.svn.wordpress.org";
pub const WORDPRESS_THEMES_SVN_BASE: &str = "https://themes.svn.wordpress.org";

// IP Geolocation API
pub const IP_API_BASE_URL: &str = "http://ip-api.com/json";

// HTTP Client defaults
pub const SVN_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

// Timeouts (in seconds)
pub const DEFAULT_HTTP_TIMEOUT: u64 = 30;
pub const IP_API_TIMEOUT: u64 = 5;
pub const WORDPRESS_API_TIMEOUT: u64 = 5;
