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
mod template_engine;
mod vulns;
mod bruteforce;
mod vulnerability_matcher;

use anyhow::Result;
use bruteforce::BruteforceEngine;
use cli::{Cli, Commands};
use database::DatabaseManager;
use exploits::ExploitEngine;
use http_client::HttpClient;
use models::ScanResults;
use output::OutputFormatter;
use scanner::Scanner;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use vulns::VulnEngine;

fn main() -> Result<()> {
    let cli = <Cli as clap::Parser>::parse();

    match &cli.command {
        Commands::Scan {
            url,
            enumerate,
            enumerate_all,
        } => {
            if enumerate.is_some() && enumerate_all.is_some() {
                eprintln!("Error: --enumerate and --enumerate-all cannot be used together");
                std::process::exit(1);
            }

            let client = HttpClient::new(url.clone(), cli.waf_bypass, cli.stealth)?;
            let use_realtime_output = !cli.verbose && cli.output == "table";
            let results = Scanner::scan(
                &client,
                cli.verbose,
                use_realtime_output,
                cli.force,
                cli.stealth,
                enumerate.clone(),
                enumerate_all.clone(),
            )?;
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

            let mut scan_results = ScanResults::for_target(url.clone());
            scan_results.exploit_results = vec![result];

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
                let vuln_template = VulnEngine::load_template(template_path)?;
                let result = VulnEngine::execute(&vuln_template, &client)?;
                results.push(result);
            } else if let Some(dir) = template_dir {
                let templates = VulnEngine::load_templates_from_dir(dir)?;
                let num_threads = cli.threads.max(1).min(templates.len());

                if num_threads == 1 {
                    for template in templates {
                        match VulnEngine::execute(&template, &client) {
                            Ok(result) => results.push(result),
                            Err(e) => eprintln!("Error executing template {}: {}", template.id, e),
                        }
                    }
                } else {
                    let (tx, rx) = mpsc::channel();
                    let client_arc = Arc::new(client);
                    let templates_arc: Vec<_> = templates.into_iter().map(Arc::new).collect();

                    let chunk_size = templates_arc.len().div_ceil(num_threads);
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
                                        eprintln!(
                                            "Error executing template {}: {}",
                                            template.id, e
                                        );
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

            let mut scan_results = ScanResults::for_target(url.clone());
            scan_results.vuln_validations = results;

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

            let mut scan_results = ScanResults::for_target(url.clone());
            scan_results.bruteforce_results = Some(bf_results);

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

            let mut scan_results = ScanResults::for_target(url.clone());
            scan_results.bruteforce_results = Some(bf_results);

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
