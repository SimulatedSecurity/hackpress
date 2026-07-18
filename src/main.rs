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
mod targets;
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
use targets::resolve_targets;
use vulns::VulnEngine;

fn main() -> Result<()> {
    let cli = <Cli as clap::Parser>::parse();

    match &cli.command {
        Commands::Scan {
            url,
            url_list,
            enumerate,
            enumerate_all,
        } => {
            if enumerate.is_some() && enumerate_all.is_some() {
                eprintln!("Error: --enumerate and --enumerate-all cannot be used together");
                std::process::exit(1);
            }

            let targets = resolve_targets(url.as_deref(), url_list.as_deref())?;
            let multi = targets.len() > 1 || url_list.is_some();
            let total = targets.len();

            for (idx, target) in targets.iter().enumerate() {
                let client = HttpClient::new(target.clone(), cli.waf_bypass, cli.stealth)?;
                // Compact progress lines when scanning a URL list
                let use_realtime_output = !multi && !cli.verbose && cli.output == "table";
                match Scanner::scan(
                    &client,
                    cli.verbose,
                    use_realtime_output,
                    cli.force,
                    cli.stealth,
                    enumerate.clone(),
                    enumerate_all.clone(),
                ) {
                    Ok(results) => {
                        if multi {
                            let vulnerable = !results.vulnerabilities.is_empty();
                            OutputFormatter::print_url_list_result(
                                idx + 1,
                                total,
                                "scan",
                                target,
                                vulnerable,
                            );
                        } else if !use_realtime_output {
                            let output = OutputFormatter::format(&results, &cli.output, cli.verbose);
                            println!("{}", output);
                        }
                    }
                    Err(e) => {
                        if multi {
                            eprintln!(
                                "{} [{}/{}] [scan] {} - error: {}",
                                "!",
                                idx + 1,
                                total,
                                target,
                                e
                            );
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
            Ok(())
        }
        Commands::Exploit {
            url,
            url_list,
            template,
            template_dir,
        } => {
            if template.is_none() && template_dir.is_none() {
                eprintln!("Error: Either --template or --template-dir must be provided");
                std::process::exit(1);
            }

            let targets = resolve_targets(url.as_deref(), url_list.as_deref())?;
            let multi = targets.len() > 1 || url_list.is_some();
            let total = targets.len();

            let templates = if let Some(template_path) = template {
                vec![ExploitEngine::load_template(template_path)?]
            } else if let Some(dir) = template_dir {
                ExploitEngine::load_templates_from_dir(dir)?
            } else {
                vec![]
            };

            let total_jobs = total.saturating_mul(templates.len().max(1));
            let mut job = 0usize;

            for target in targets.iter() {
                let client = HttpClient::new(target.clone(), cli.waf_bypass, false)?;

                if multi {
                    for tmpl in &templates {
                        job += 1;
                        match ExploitEngine::execute(tmpl, &client) {
                            Ok(result) => {
                                OutputFormatter::print_url_list_result(
                                    job,
                                    total_jobs,
                                    &result.template_id,
                                    target,
                                    result.success,
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "{} [{}/{}] [{}] {} - error: {}",
                                    "!",
                                    job,
                                    total_jobs,
                                    tmpl.id,
                                    target,
                                    e
                                );
                            }
                        }
                    }
                } else {
                    let mut results = vec![];
                    for tmpl in &templates {
                        match ExploitEngine::execute(tmpl, &client) {
                            Ok(result) => results.push(result),
                            Err(e) => {
                                eprintln!("Error executing template {}: {}", tmpl.id, e)
                            }
                        }
                    }
                    let mut scan_results = ScanResults::for_target(target.clone());
                    scan_results.exploit_results = results;
                    let output =
                        OutputFormatter::format(&scan_results, &cli.output, cli.verbose);
                    println!("{}", output);
                }
            }
            Ok(())
        }
        Commands::Vuln {
            url,
            url_list,
            template,
            template_dir,
        } => {
            if template.is_none() && template_dir.is_none() {
                eprintln!("Error: Either --template or --template-dir must be provided");
                std::process::exit(1);
            }

            let targets = resolve_targets(url.as_deref(), url_list.as_deref())?;
            let multi = targets.len() > 1 || url_list.is_some();
            let total = targets.len();

            let templates = if let Some(template_path) = template {
                vec![VulnEngine::load_template(template_path)?]
            } else if let Some(dir) = template_dir {
                VulnEngine::load_templates_from_dir(dir)?
            } else {
                vec![]
            };

            // Compact progress: one line per (target × template)
            let total_jobs = total.saturating_mul(templates.len().max(1));
            let mut job = 0usize;

            for target in targets.iter() {
                let client = HttpClient::new(target.clone(), cli.waf_bypass, false)?;

                if multi {
                    for tmpl in &templates {
                        job += 1;
                        match VulnEngine::execute(tmpl, &client) {
                            Ok(result) => {
                                OutputFormatter::print_url_list_result(
                                    job,
                                    total_jobs,
                                    &result.template_id,
                                    target,
                                    result.matched,
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "{} [{}/{}] [{}] {} - error: {}",
                                    "!",
                                    job,
                                    total_jobs,
                                    tmpl.id,
                                    target,
                                    e
                                );
                            }
                        }
                    }
                } else {
                    // Single-target: keep existing table/json output (incl. threaded template-dir)
                    let mut results = vec![];
                    if templates.len() == 1 || cli.threads <= 1 {
                        for tmpl in &templates {
                            match VulnEngine::execute(tmpl, &client) {
                                Ok(result) => results.push(result),
                                Err(e) => {
                                    eprintln!("Error executing template {}: {}", tmpl.id, e)
                                }
                            }
                        }
                    } else {
                        let (tx, rx) = mpsc::channel();
                        let client_arc = Arc::new(client);
                        let templates_arc: Vec<_> =
                            templates.iter().cloned().map(Arc::new).collect();
                        let num_threads = cli.threads.max(1).min(templates_arc.len());
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

                    let mut scan_results = ScanResults::for_target(target.clone());
                    scan_results.vuln_validations = results;
                    let output = OutputFormatter::format(&scan_results, &cli.output, cli.verbose);
                    println!("{}", output);
                }
            }
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
