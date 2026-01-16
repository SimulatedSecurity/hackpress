mod cli;
mod constants;
mod database;
mod detection;
mod enumeration;
mod error_detection;
mod exploits;
mod file_disclosure;
mod http_client;
mod interactive;
mod models;
mod output;
mod scanner;
mod tech_stack;
mod vulns;
mod bruteforce;
mod vulnerability_matcher;

use anyhow::Result;
use cli::{Cli, Commands};
use database::DatabaseManager;
use exploits::ExploitEngine;
use output::OutputFormatter;
use scanner::Scanner;
use vulns::VulnEngine;
use bruteforce::BruteforceEngine;
use http_client::HttpClient;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

fn main() -> Result<()> {
    let cli = <Cli as clap::Parser>::parse();

    match &cli.command {
        Commands::Scan { url, enumerate, enumerate_all } => {
            // Validate that both --enumerate and --enumerate-all are not used simultaneously
            if enumerate.is_some() && enumerate_all.is_some() {
                eprintln!("Error: --enumerate and --enumerate-all cannot be used together");
                std::process::exit(1);
            }
            
            let client = HttpClient::new(url.clone(), cli.waf_bypass, cli.stealth)?;
            let use_realtime_output = !cli.verbose && cli.output == "table";
            let results = Scanner::scan(&client, cli.verbose, use_realtime_output, cli.force, cli.stealth, enumerate.clone(), enumerate_all.clone())?;
            // Only print final output for json/markdown, or if real-time wasn't used
            if !use_realtime_output {
                let output = OutputFormatter::format(&results, &cli.output, cli.verbose);
                println!("{}", output);
            }
            Ok(())
        }
        Commands::Exploit { url, template } => {
            let client = HttpClient::new(url.clone(), cli.waf_bypass, false)?;
            let exploit_template = ExploitEngine::load_template(template)?;
            let result = ExploitEngine::execute(&exploit_template, &client)?;
            
            let scan_results = models::ScanResults {
                target: url.clone(),
                tech_stack: None,
                robots_txt: None,
                wordpress: None,
                wordpress_config: None,
                plugins: vec![],
                themes: vec![],
                vulnerabilities: vec![],
                vuln_validations: vec![],
                exploit_results: vec![result],
                usernames: vec![],
                file_disclosures: vec![],
                bruteforce_results: None,
            };
            
            let output = OutputFormatter::format(&scan_results, &cli.output, cli.verbose);
            println!("{}", output);
            Ok(())
        }
        Commands::Vuln {
            url,
            template,
            template_dir,
        } => {
            if template.is_none() && template_dir.is_none() {
                eprintln!("Error: Either --template or --template-dir must be provided");
                std::process::exit(1);
            }

            let client = HttpClient::new(url.clone(), cli.waf_bypass, false)?;
            let mut results = vec![];

            if let Some(template_path) = template {
                // Single template execution
                let vuln_template = VulnEngine::load_template(template_path)?;
                let result = VulnEngine::execute(&vuln_template, &client)?;
                results.push(result);
            } else if let Some(dir) = template_dir {
                // Mass template execution
                let templates = VulnEngine::load_templates_from_dir(dir)?;
                let num_threads = cli.threads.max(1).min(templates.len());
                
                if num_threads == 1 {
                    // Single-threaded execution
                    for template in templates {
                        match VulnEngine::execute(&template, &client) {
                            Ok(result) => results.push(result),
                            Err(e) => eprintln!("Error executing template {}: {}", template.id, e),
                        }
                    }
                } else {
                    // Multi-threaded execution
                    let (tx, rx) = mpsc::channel();
                    let client_arc = Arc::new(client);
                    let templates_arc: Vec<_> = templates.into_iter().map(Arc::new).collect();
                    
                    let chunk_size = (templates_arc.len() + num_threads - 1) / num_threads;
                    let mut handles = vec![];
                    
                    for chunk in templates_arc.chunks(chunk_size) {
                        let chunk = chunk.to_vec();
                        let client_clone = Arc::clone(&client_arc);
                        let tx_clone = tx.clone();
                        
                        let handle = thread::spawn(move || {
                            for template in chunk {
                                match VulnEngine::execute(&template, &client_clone) {
                                    Ok(result) => {
                                        let _ = tx_clone.send(result);
                                    }
                                    Err(e) => {
                                        eprintln!("Error executing template {}: {}", template.id, e);
                                    }
                                }
                            }
                        });
                        
                        handles.push(handle);
                    }
                    
                    drop(tx);
                    
                    for handle in handles {
                        handle.join().unwrap();
                    }
                    
                    while let Ok(result) = rx.recv() {
                        results.push(result);
                    }
                }
            }

            let scan_results = models::ScanResults {
                target: url.clone(),
                tech_stack: None,
                robots_txt: None,
                wordpress: None,
                wordpress_config: None,
                plugins: vec![],
                themes: vec![],
                vulnerabilities: vec![],
                vuln_validations: results,
                exploit_results: vec![],
                usernames: vec![],
                file_disclosures: vec![],
                bruteforce_results: None,
            };
            
            let output = OutputFormatter::format(&scan_results, &cli.output, cli.verbose);
            println!("{}", output);
            Ok(())
        }
        Commands::Bruteforce {
            url,
            users,
            passwords,
            bruteforce_type,
            rate_limit,
            stop_on_success,
        } => {
            let client = HttpClient::new(url.clone(), cli.waf_bypass, false)?;
            let bf_results = BruteforceEngine::bruteforce(
                &client,
                users,
                passwords,
                bruteforce_type,
                *rate_limit,
                *stop_on_success,
            )?;
            
            let scan_results = models::ScanResults {
                target: url.clone(),
                tech_stack: None,
                robots_txt: None,
                wordpress: None,
                wordpress_config: None,
                plugins: vec![],
                themes: vec![],
                vulnerabilities: vec![],
                vuln_validations: vec![],
                exploit_results: vec![],
                usernames: vec![],
                file_disclosures: vec![],
                bruteforce_results: Some(bf_results),
            };
            
            let output = OutputFormatter::format(&scan_results, &cli.output, cli.verbose);
            println!("{}", output);
            Ok(())
        }
        Commands::Spray {
            url,
            users,
            passwords,
            bruteforce_type,
            rate_limit,
        } => {
            let client = HttpClient::new(url.clone(), cli.waf_bypass, false)?;
            let bf_results = BruteforceEngine::spray(
                &client,
                users,
                passwords,
                bruteforce_type,
                *rate_limit,
            )?;
            
            let scan_results = models::ScanResults {
                target: url.clone(),
                tech_stack: None,
                robots_txt: None,
                wordpress: None,
                wordpress_config: None,
                plugins: vec![],
                themes: vec![],
                vulnerabilities: vec![],
                vuln_validations: vec![],
                exploit_results: vec![],
                usernames: vec![],
                file_disclosures: vec![],
                bruteforce_results: Some(bf_results),
            };
            
            let output = OutputFormatter::format(&scan_results, &cli.output, cli.verbose);
            println!("{}", output);
            Ok(())
        }
        Commands::Update => {
            DatabaseManager::update_all()?;
            Ok(())
        }
        Commands::Interactive => {
            let mut session = interactive::InteractiveSession::new();
            session.run()?;
            Ok(())
        }
    }
}
