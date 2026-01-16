use anyhow::Result;
use crate::http_client::HttpClient;
use crate::models::FileDisclosure;

pub struct FileDisclosureChecker;

impl FileDisclosureChecker {
    pub fn check(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Vec<FileDisclosure>> {
        Self::check_internal(client, verbose, use_realtime_output, false)
    }
    
    pub fn check_stealth(client: &HttpClient, verbose: bool, use_realtime_output: bool) -> Result<Vec<FileDisclosure>> {
        Self::check_internal(client, verbose, use_realtime_output, true)
    }
    
    fn check_internal(client: &HttpClient, verbose: bool, use_realtime_output: bool, stealth: bool) -> Result<Vec<FileDisclosure>> {
        let mut disclosures = vec![];

        // In stealth mode, skip bruteforcing files and backups
        if stealth {
            if verbose {
                eprintln!("     [verbose] Stealth mode: skipping file/backup bruteforcing");
            }
            return Ok(disclosures);
        }

        // Check for wp-config.php backups
        let config_backups = vec![
            "wp-config.php.bak",
            "wp-config.php~",
            "wp-config.php.old",
            "wp-config.php.orig",
            "wp-config.php.save",
            "wp-config.php.swp",
            "wp-config.php.txt",
            "wp-config.old.php",
            "wp-config.php.backup",
        ];

        for backup in config_backups {
            if let Ok(response) = client.get(&format!("/{}", backup), None) {
                if response.status().is_success() {
                    let body = response.text().ok();
                    let accessible = body.as_ref()
                        .map(|b| b.contains("DB_NAME") || b.contains("DB_PASSWORD") || b.contains("DB_USER"))
                        .unwrap_or(false);
                    
                    let disclosure = FileDisclosure {
                        path: backup.to_string(),
                        file_type: "wp-config-backup".to_string(),
                        accessible,
                    };
                    disclosures.push(disclosure.clone());
                    // Display as found (real-time output)
                    if use_realtime_output {
                        crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                    }
                }
            }
        }

        // Check for database dumps
        let db_dumps = vec![
            "database.sql",
            "db.sql",
            "backup.sql",
            "dump.sql",
            "database.sql.gz",
            "db.sql.gz",
            "backup.sql.gz",
        ];

        for dump in db_dumps {
            if let Ok(response) = client.get(&format!("/{}", dump), None) {
                if response.status().is_success() {
                    let disclosure = FileDisclosure {
                        path: dump.to_string(),
                        file_type: "database-dump".to_string(),
                        accessible: true,
                    };
                    disclosures.push(disclosure.clone());
                    // Display as found (real-time output)
                    if use_realtime_output {
                        crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                    }
                }
            }
        }

        // Check for error logs
        let error_logs = vec![
            "error_log",
            "debug.log",
            "error.log",
            "wp-content/debug.log",
        ];

        for log_file in error_logs {
            if let Ok(response) = client.get(&format!("/{}", log_file), None) {
                if response.status().is_success() {
                    let disclosure = FileDisclosure {
                        path: log_file.to_string(),
                        file_type: "error-log".to_string(),
                        accessible: true,
                    };
                    disclosures.push(disclosure.clone());
                    // Display as found (real-time output)
                    if use_realtime_output {
                        crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                    }
                }
            }
        }

        // Check for version control
        let vcs_paths = vec![
            ".git/config",
            ".git/HEAD",
            ".svn/entries",
            ".hg/requires",
        ];

        for vcs_path in vcs_paths {
            if let Ok(response) = client.get(&format!("/{}", vcs_path), None) {
                if response.status().is_success() {
                    let disclosure = FileDisclosure {
                        path: vcs_path.to_string(),
                        file_type: "version-control".to_string(),
                        accessible: true,
                    };
                    disclosures.push(disclosure.clone());
                    // Display as found (real-time output)
                    if use_realtime_output {
                        crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                    }
                }
            }
        }

        // Check for readme files
        if let Ok(response) = client.get("/readme.html", None) {
            if response.status().is_success() {
                let disclosure = FileDisclosure {
                    path: "readme.html".to_string(),
                    file_type: "readme".to_string(),
                    accessible: true,
                };
                disclosures.push(disclosure.clone());
                // Display as found (real-time output)
                if use_realtime_output {
                    crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                }
            }
        }

        // Check for directory listing (skip in stealth mode)
        if !stealth {
            let directory_paths = vec![
                "/wp-includes",
                "/wp-content/uploads",
            ];

            for dir_path in directory_paths {
            if verbose {
                eprintln!("     [verbose] Checking directory listing for: {}", dir_path);
            }
            
            if let Ok(response) = client.get(dir_path, None) {
                let status = response.status().as_u16();
                
                if status == 200 {
                    if let Ok(body) = response.text() {
                        // Check if response contains directory listing indicators
                        let is_directory_listing = Self::is_directory_listing(&body);
                        
                        if is_directory_listing {
                            let disclosure = FileDisclosure {
                                path: dir_path.to_string(),
                                file_type: "directory-listing".to_string(),
                                accessible: true,
                            };
                            disclosures.push(disclosure.clone());
                            // Display as found (real-time output)
                            if use_realtime_output {
                                crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                            }
                            if verbose {
                                eprintln!("     [verbose] ✓ Directory listing enabled on: {}", dir_path);
                            }
                        } else if verbose {
                            eprintln!("     [verbose] Directory listing not detected on: {} (status: {})", dir_path, status);
                        }
                    }
                } else if verbose {
                    eprintln!("     [verbose] Directory listing check for {} returned status: {}", dir_path, status);
                }
            } else if verbose {
                eprintln!("     [verbose] Failed to check directory listing for: {}", dir_path);
            }
            }
        } else if verbose {
            eprintln!("     [verbose] Stealth mode: skipping directory enumeration");
        }

        // Check for common backup paths (skip in stealth mode - already handled above)
        let backup_paths = vec![
            "/backup.zip",
            "/backup.rar",
            "/wp-content.rar",
            "/wp-content.zip",       
            "/wp-content/updraft/",
            "/wp-content/uploads.rar",
            "/wp-content/uploads.zip",
            "/wp-content/uploads/wpvivid-backups/",
            "/wp-content/backups/",
        ];

        for backup_path in backup_paths {
            if verbose {
                eprintln!("     [verbose] Checking backup path: {}", backup_path);
            }
            
            if let Ok(response) = client.get(backup_path, None) {
                let status = response.status().as_u16();
                
                if status == 200 {
                    // Check if it's a file (backup.zip, backup.ro) or directory
                    let is_file = backup_path.ends_with(".zip") || backup_path.ends_with(".ro");
                    
                    if is_file {
                        // It's a backup file - check if it's actually a backup file
                        // Extract content-type header before reading body
                        let content_type = response.headers()
                            .get("content-type")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string());
                        
                        if let Ok(body) = response.text() {
                            // Check if it looks like a zip file or contains backup indicators
                            let is_backup = body.starts_with("PK") || // ZIP file signature
                                          body.contains("backup") ||
                                          body.contains("database") ||
                                          body.contains("dump");
                            
                            let content_type_match = content_type.as_ref()
                                .map(|ct| ct.contains("zip") || ct.contains("octet-stream"))
                                .unwrap_or(false);
                            
                            if is_backup || content_type_match {
                                let disclosure = FileDisclosure {
                                    path: backup_path.to_string(),
                                    file_type: "backup-file".to_string(),
                                    accessible: true,
                                };
                                disclosures.push(disclosure.clone());
                                // Display as found (real-time output)
                                if use_realtime_output {
                                    crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                                }
                                if verbose {
                                    eprintln!("     [verbose] ✓ Backup file found: {}", backup_path);
                                }
                            }
                        } else {
                            // If we can't read body but got 200, assume it's accessible
                            let disclosure = FileDisclosure {
                                path: backup_path.to_string(),
                                file_type: "backup-file".to_string(),
                                accessible: true,
                            };
                            disclosures.push(disclosure.clone());
                            // Display as found (real-time output)
                            if use_realtime_output {
                                crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                            }
                            if verbose {
                                eprintln!("     [verbose] ✓ Backup file accessible: {}", backup_path);
                            }
                        }
                    } else {
                        // It's a directory - check for directory listing or files
                        if let Ok(body) = response.text() {
                            let is_directory_listing = Self::is_directory_listing(&body);
                            
                            if is_directory_listing {
                                let disclosure = FileDisclosure {
                                    path: backup_path.to_string(),
                                    file_type: "backup-directory-listing".to_string(),
                                    accessible: true,
                                };
                                disclosures.push(disclosure.clone());
                                // Display as found (real-time output)
                                if use_realtime_output {
                                    crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                                }
                                if verbose {
                                    eprintln!("     [verbose] ✓ Backup directory listing enabled: {}", backup_path);
                                }
                            } else {
                                // Check if directory contains backup files (even without listing)
                                let backup_file_patterns = vec![
                                    r#"(?i)\.(zip|sql|gz|tar|bak|backup)"#,
                                    r#"(?i)backup.*\.(zip|sql|gz|tar)"#,
                                    r#"(?i)dump.*\.(sql|gz)"#,
                                ];
                                
                                use regex::Regex;
                                let mut found_backup_files = false;
                                for pattern in backup_file_patterns {
                                    if let Ok(re) = Regex::new(pattern) {
                                        if re.is_match(&body) {
                                            found_backup_files = true;
                                            break;
                                        }
                                    }
                                }
                                
                                if found_backup_files {
                                    let disclosure = FileDisclosure {
                                        path: backup_path.to_string(),
                                        file_type: "backup-directory".to_string(),
                                        accessible: true,
                                    };
                                    disclosures.push(disclosure.clone());
                                    // Display as found (real-time output)
                                    if use_realtime_output {
                                        crate::output::OutputFormatter::print_file_disclosure_item_real_time(&disclosure, disclosures.len() == 1);
                                    }
                                    if verbose {
                                        eprintln!("     [verbose] ✓ Backup directory accessible with files: {}", backup_path);
                                    }
                                } else if verbose {
                                    eprintln!("     [verbose] Backup directory accessible but no backup files detected: {}", backup_path);
                                }
                            }
                        }
                    }
                } else if verbose {
                    eprintln!("     [verbose] Backup path check for {} returned status: {}", backup_path, status);
                }
            } else if verbose {
                eprintln!("     [verbose] Failed to check backup path: {}", backup_path);
            }
        }

        Ok(disclosures)
    }

    fn is_directory_listing(body: &str) -> bool {
        use regex::Regex;
        
        // Common directory listing indicators
        let indicators = vec![
            r"(?i)<title>.*index of.*</title>",
            r"(?i)<h1>.*index of.*</h1>",
            r"(?i)directory listing",
            r"(?i)parent directory",
            r#"(?i)<a\s+href=["']\.\./["']"#,
            r#"(?i)<a\s+href=["'][^"']*\.(php|js|css|txt|jpg|png|gif|zip|sql)["']"#,
            r"(?i)<table.*>.*<tr>.*<td>.*<a\s+href",
            r"(?i)apache.*server.*at",
            r"(?i)nginx.*directory",
        ];

        for pattern in indicators {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(body) {
                    // Additional check: make sure it's not a WordPress page
                    // WordPress pages usually contain "wp-content" or "wp-includes" in links but not as directory listing
                    let wordpress_indicators = vec![
                        r"(?i)wp-content/themes",
                        r"(?i)wp-content/plugins",
                        r"(?i)wordpress",
                    ];
                    
                    let mut has_wordpress_content = false;
                    for wp_pattern in wordpress_indicators {
                        if let Ok(wp_re) = Regex::new(wp_pattern) {
                            if wp_re.is_match(body) {
                                has_wordpress_content = true;
                                break;
                            }
                        }
                    }
                    
                    // If it has directory listing indicators but also WordPress content structure,
                    // check if it's actually a directory listing (has file links) vs WordPress page
                    if has_wordpress_content {
                        // Check for actual file links in directory listing format
                        let file_link_pattern = Regex::new(r#"(?i)<a\s+href=["']([^"']+\.(php|js|css|txt|jpg|png|gif|zip|sql|bak|old|log))["']"#).unwrap();
                        if file_link_pattern.is_match(body) {
                            return true;
                        }
                    } else {
                        return true;
                    }
                }
            }
        }

        false
    }
}
