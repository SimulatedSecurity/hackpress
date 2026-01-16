use anyhow::Result;
use crate::database::DatabaseManager;
use crate::detection::WordPressDetector;
use crate::enumeration::UsernameEnumerator;
use crate::file_disclosure::FileDisclosureChecker;
use crate::http_client::HttpClient;
use crate::models::ScanResults;
use crate::tech_stack::TechStackAnalyzer;
use crate::vulnerability_matcher::VulnerabilityMatcher;
use crate::output::OutputFormatter;
use crate::constants;
use std::path::Path;

pub struct Scanner;

impl Scanner {
    pub fn scan(client: &HttpClient, verbose: bool, use_realtime_output: bool, force: bool, stealth: bool, enumerate: Option<Vec<String>>, enumerate_all: Option<Vec<String>>) -> Result<ScanResults> {
        let target = client.base_url.clone();

        // Print header at start (only for table format, non-verbose, real-time output)
        if use_realtime_output {
            OutputFormatter::print_header(&target);
        }

        // Browser-like behavior: Visit homepage first when WAF bypass is enabled
        // This simulates realistic request ordering (/, assets, wp-json, then sensitive paths)
        // Note: We check if client has waf_bypass, but we can't access it directly
        // The WAF bypass behavior is handled in HttpClient internally
        
        // Tech stack analysis
        let tech_stack = TechStackAnalyzer::analyze_headers(client).ok();
        if use_realtime_output {
            if let Some(ref ts) = tech_stack {
                OutputFormatter::print_tech_stack_section(ts);
            }
        }

        let robots_txt = TechStackAnalyzer::analyze_robots_txt(client).ok().flatten();
        if use_realtime_output {
            if let Some(ref robots) = robots_txt {
                OutputFormatter::print_robots_section(robots);
            }
        }

        // WordPress detection (output is printed in real-time within detect_wordpress function)
        let wordpress = WordPressDetector::detect_wordpress(client, verbose, use_realtime_output).ok().flatten();
        
        // If WordPress is not detected, exit early and return results (unless --force is used)
        if !force && (wordpress.is_none() || wordpress.as_ref().map(|w| !w.detected).unwrap_or(true)) {
            return Ok(ScanResults {
                target,
                tech_stack,
                robots_txt,
                wordpress,
                wordpress_config: None,
                plugins: vec![],
                themes: vec![],
                vulnerabilities: vec![],
                vuln_validations: vec![],
                exploit_results: vec![],
                usernames: vec![],
                file_disclosures: vec![],
                bruteforce_results: None,
            });
        }
        
        // WordPress configuration checks (output is printed in real-time within check_wordpress_config function)
        let (wordpress_config, waf_detected) = WordPressDetector::check_wordpress_config(client, verbose, use_realtime_output)
            .unwrap_or((None, false));
        
        // If WAF is detected, stop scan early to avoid further blocks
        if waf_detected {
            use colored::*;
            eprintln!("\n{} Scan stopped early due to WAF blocking detection.", "⚠".bright_red().bold());
            eprintln!("   To continue scanning with browser-like behavior, use --waf-bypass flag.");
            return Ok(ScanResults {
                target,
                tech_stack,
                robots_txt,
                wordpress,
                wordpress_config,
                plugins: vec![],
                themes: vec![],
                vulnerabilities: vec![],
                vuln_validations: vec![],
                exploit_results: vec![],
                usernames: vec![],
                file_disclosures: vec![],
                bruteforce_results: None,
            });
        }
        
        // Enumerate themes (output is printed in real-time within enumerate_themes function)
        // In stealth mode, limit theme enumeration to reduce traffic
        let mut themes = if stealth {
            WordPressDetector::enumerate_themes_stealth(client, verbose, use_realtime_output).unwrap_or_default()
        } else {
            WordPressDetector::enumerate_themes(client, verbose, use_realtime_output).unwrap_or_default()
        };

        // Enumerate plugins (output is printed in real-time within enumerate_plugins function)
        // In stealth mode, limit plugin enumeration to reduce traffic
        let mut plugins = if stealth {
            WordPressDetector::enumerate_plugins_stealth(client, verbose, use_realtime_output).unwrap_or_default()
        } else {
            WordPressDetector::enumerate_plugins(client, verbose, use_realtime_output).unwrap_or_default()
        };

        // Collect existing slugs to avoid duplicates
        let mut existing_plugin_slugs: std::collections::HashSet<String> = plugins.iter().map(|p| p.slug.clone()).collect();
        let mut existing_theme_slugs: std::collections::HashSet<String> = themes.iter().map(|t| t.slug.clone()).collect();

        // Enumerate from database files if requested (after passive detection)
        if let Some(ref enum_types) = enumerate {
            let use_top = true; // --enumerate uses top files
            let wants_themes = enum_types.iter().any(|t| t.to_lowercase() == "themes");
            let wants_plugins = enum_types.iter().any(|t| t.to_lowercase() == "plugins");

            // Enumerate themes first if requested
            if wants_themes {
                let enumerated_themes = WordPressDetector::enumerate_themes_from_file(
                    client,
                    verbose,
                    use_realtime_output,
                    use_top,
                    &existing_theme_slugs,
                    |current, total| {
                        OutputFormatter::print_progress_bar(current, total, "Enumerating themes");
                    }
                ).unwrap_or_default();
                OutputFormatter::print_progress_complete();

                // Add only non-duplicate themes
                for theme in enumerated_themes {
                    if !existing_theme_slugs.contains(&theme.slug) {
                        existing_theme_slugs.insert(theme.slug.clone());
                        themes.push(theme);
                    }
                }
            }

            // Enumerate plugins after themes
            if wants_plugins {
                let enumerated_plugins = WordPressDetector::enumerate_plugins_from_file(
                    client,
                    verbose,
                    use_realtime_output,
                    use_top,
                    &existing_plugin_slugs,
                    |current, total| {
                        OutputFormatter::print_progress_bar(current, total, "Enumerating plugins");
                    }
                ).unwrap_or_default();
                OutputFormatter::print_progress_complete();

                // Add only non-duplicate plugins
                for plugin in enumerated_plugins {
                    if !existing_plugin_slugs.contains(&plugin.slug) {
                        existing_plugin_slugs.insert(plugin.slug.clone());
                        plugins.push(plugin);
                    }
                }
            }
        }

        if let Some(ref enum_all_types) = enumerate_all {
            let use_top = false; // --enumerate-all uses complete files
            let wants_themes = enum_all_types.iter().any(|t| t.to_lowercase() == "themes");
            let wants_plugins = enum_all_types.iter().any(|t| t.to_lowercase() == "plugins");

            // Enumerate themes first if requested
            if wants_themes {
                let enumerated_themes = WordPressDetector::enumerate_themes_from_file(
                    client,
                    verbose,
                    use_realtime_output,
                    use_top,
                    &existing_theme_slugs,
                    |current, total| {
                        OutputFormatter::print_progress_bar(current, total, "Enumerating themes");
                    }
                ).unwrap_or_default();
                OutputFormatter::print_progress_complete();

                // Add only non-duplicate themes
                for theme in enumerated_themes {
                    if !existing_theme_slugs.contains(&theme.slug) {
                        existing_theme_slugs.insert(theme.slug.clone());
                        themes.push(theme);
                    }
                }
            }

            // Enumerate plugins after themes
            if wants_plugins {
                let enumerated_plugins = WordPressDetector::enumerate_plugins_from_file(
                    client,
                    verbose,
                    use_realtime_output,
                    use_top,
                    &existing_plugin_slugs,
                    |current, total| {
                        OutputFormatter::print_progress_bar(current, total, "Enumerating plugins");
                    }
                ).unwrap_or_default();
                OutputFormatter::print_progress_complete();

                // Add only non-duplicate plugins
                for plugin in enumerated_plugins {
                    if !existing_plugin_slugs.contains(&plugin.slug) {
                        existing_plugin_slugs.insert(plugin.slug.clone());
                        plugins.push(plugin);
                    }
                }
            }
        }

        // Vulnerability matching - auto-download if not exists locally
        let vuln_db = if !Path::new(&format!("{}/vulns.json", constants::DATABASE_DIR)).exists() {
            if verbose {
                println!("[verbose] Vulnerability database not found locally, downloading from GitHub...");
            }
            // Auto-download only vulns.json
            if let Err(e) = DatabaseManager::download_vulns_db() {
                if verbose {
                    eprintln!("[verbose] Failed to auto-download vulnerability database: {}", e);
                }
                None
            } else {
                DatabaseManager::load_vulns().ok()
            }
        } else {
            DatabaseManager::load_vulns().ok()
        };
        
        let vulnerabilities = if let Some(db) = &vuln_db {
            VulnerabilityMatcher::match_vulnerabilities(
                db,
                &plugins,
                &themes,
                wordpress.as_ref().and_then(|w| w.version.as_deref()),
            )
        } else {
            vec![]
        };
        
        // Display vulnerabilities as found (real-time output)
        if use_realtime_output {
            for (idx, vuln) in vulnerabilities.iter().enumerate() {
                OutputFormatter::print_vulnerability_item_real_time(vuln, idx, idx == 0);
            }
            if !vulnerabilities.is_empty() {
                OutputFormatter::print_section_end();
            }
        }

        // Username enumeration (output is printed in real-time within enumerate function)
        // Skip archive enumeration in stealth mode
        let usernames = if stealth {
            UsernameEnumerator::enumerate_stealth(client, verbose, use_realtime_output).unwrap_or_default()
        } else {
            UsernameEnumerator::enumerate(client, verbose, use_realtime_output).unwrap_or_default()
        };

        // File disclosure checks (output is printed in real-time within check function)
        // Skip bruteforcing in stealth mode
        let file_disclosures = if stealth {
            FileDisclosureChecker::check_stealth(client, verbose, use_realtime_output).unwrap_or_default()
        } else {
            FileDisclosureChecker::check(client, verbose, use_realtime_output).unwrap_or_default()
        };
        
        // Close sections if they were printed
        if use_realtime_output {
            if !usernames.is_empty() {
                OutputFormatter::print_section_end();
            }
            if !file_disclosures.is_empty() {
                OutputFormatter::print_section_end();
            }
        }

        Ok(ScanResults {
            target,
            tech_stack,
            robots_txt,
            wordpress,
            wordpress_config,
            plugins,
            themes,
            vulnerabilities,
            vuln_validations: vec![],
            exploit_results: vec![],
            usernames,
            file_disclosures,
            bruteforce_results: None,
        })
    }
}
