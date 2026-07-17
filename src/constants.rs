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

// WordPress.org APIs
pub const WORDPRESS_VERSION_API_URL: &str = "https://api.wordpress.org/core/version-check/1.7/";
pub const WORDPRESS_PLUGINS_INFO_API: &str =
    "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information";
pub const WORDPRESS_THEMES_INFO_API: &str =
    "https://api.wordpress.org/themes/info/1.2/?action=theme_information";

// IP Geolocation API
pub const IP_API_BASE_URL: &str = "http://ip-api.com/json";

// Timeouts (in seconds)
pub const DEFAULT_HTTP_TIMEOUT: u64 = 30;
pub const IP_API_TIMEOUT: u64 = 5;
pub const WORDPRESS_API_TIMEOUT: u64 = 5;
