use anyhow::Result;
use colored::*;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

pub struct InteractiveSession {
    target: Option<String>,
    url_list: Option<String>,
    waf_bypass: bool,
    stealth: bool,
    verbose: bool,
    threads: usize,
    output: String,
    force: bool,
    enumerate: Option<Vec<String>>,
    enumerate_all: Option<Vec<String>>,
}

impl InteractiveSession {
    pub fn new() -> Self {
        Self {
            target: None,
            url_list: None,
            waf_bypass: false,
            stealth: false,
            verbose: false,
            threads: 10,
            output: "table".to_string(),
            force: false,
            enumerate: None,
            enumerate_all: None,
        }
    }

    pub fn run(&mut self) -> Result<()> {
        println!("{}", "=".repeat(60).bright_black());
        println!("{}", "Hackpress Interactive Console".bright_red().bold());
        println!("{}", "=".repeat(60).bright_black());
        println!();
        println!("Type '{}' for available commands", "help".bright_cyan());
        println!("Type '{}' to exit", "exit".bright_cyan());
        println!();

        let mut rl = DefaultEditor::new()?;
        let history_path = dirs::home_dir()
            .map(|p| p.join(".hackpress_history"))
            .unwrap_or_else(|| std::path::PathBuf::from(".hackpress_history"));

        let _ = rl.load_history(&history_path);

        loop {
            // Use plain prompt for rustyline to avoid ANSI code issues on Windows
            let prompt = self.get_prompt_plain();
            match rl.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    let _ = rl.add_history_entry(line);

                    if let Err(e) = self.handle_command(line) {
                        eprintln!("{} {}", "Error:".bright_red(), e);
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    println!("{}", "\nUse 'exit' to quit".bright_yellow());
                    continue;
                }
                Err(ReadlineError::Eof) => {
                    println!("{}", "\nExiting...".bright_yellow());
                    break;
                }
                Err(err) => {
                    eprintln!("Error: {:?}", err);
                    break;
                }
            }
        }

        let _ = rl.save_history(&history_path);
        Ok(())
    }

    fn get_prompt_plain(&self) -> String {
        let target_display = if let Some(ref list) = self.url_list {
            format!("url-list:{}", list)
        } else {
            self.target
                .as_ref()
                .map(|t| t.as_str())
                .unwrap_or("not set")
                .to_string()
        };
        // Use plain text prompt to avoid ANSI code issues on Windows terminals
        format!("hackpress [{}] > ", target_display)
    }

    fn handle_command(&mut self, line: &str) -> Result<()> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(());
        }

        let command = parts[0].to_lowercase();
        let args = &parts[1..];

        match command.as_str() {
            "exit" | "quit" | "q" => {
                println!("{}", "Exiting interactive mode...".bright_yellow());
                std::process::exit(0);
            }
            "help" | "h" | "?" => {
                self.print_help();
            }
            "set" => {
                self.handle_set(args)?;
            }
            "unset" => {
                self.handle_unset(args)?;
            }
            "show" => {
                self.handle_show(args)?;
            }
            "scan" => {
                self.handle_scan(args)?;
            }
            "exploit" => {
                self.handle_exploit(args)?;
            }
            "vuln" => {
                self.handle_vuln(args)?;
            }
            "bruteforce" | "brute" => {
                self.handle_bruteforce(args)?;
            }
            "spray" => {
                self.handle_spray(args)?;
            }
            "update" => {
                self.handle_update()?;
            }
            "clear" | "cls" => {
                print!("\x1B[2J\x1B[1;1H");
            }
            _ => {
                println!(
                    "{} Unknown command: '{}'. Type 'help' for available commands.",
                    "Error:".bright_red(),
                    command
                );
            }
        }

        Ok(())
    }

    fn print_help(&self) {
        println!();
        println!("{}", "Available Commands:".bright_cyan().bold());
        println!();
        println!("  {} {}", "set".bright_green(), "target <url>          Set single target URL");
        println!("  {} {}", "set".bright_green(), "url-list <file>       Set targets file (one URL per line)");
        println!("  {} {}", "set".bright_green(), "waf-bypass            Enable WAF bypass");
        println!("  {} {}", "set".bright_green(), "stealth               Enable stealth mode");
        println!("  {} {}", "set".bright_green(), "verbose               Enable verbose output");
        println!("  {} {}", "set".bright_green(), "threads <num>         Set thread count (default: 10)");
        println!("  {} {}", "set".bright_green(), "output <format>       Set output format (json/table/markdown)");
        println!("  {} {}", "set".bright_green(), "force                 Force complete scan even if WordPress not detected");
        println!("  {} {}", "set".bright_green(), "enumerate <types>     Enumerate plugins/themes from top database files");
        println!("  {} {}", "set".bright_green(), "enumerate-all <types> Enumerate plugins/themes from complete database files");
        println!("  {} {}", "set".bright_green(), "                      Types: plugins, themes, or plugins,themes");
        println!();
        println!("  {} {}", "unset".bright_yellow(), "target               Clear single target");
        println!("  {} {}", "unset".bright_yellow(), "url-list             Clear URL list file");
        println!("  {} {}", "unset".bright_yellow(), "waf-bypass            Disable WAF bypass");
        println!("  {} {}", "unset".bright_yellow(), "stealth               Disable stealth mode");
        println!("  {} {}", "unset".bright_yellow(), "verbose              Disable verbose output");
        println!("  {} {}", "unset".bright_yellow(), "force                Disable force scan");
        println!("  {} {}", "unset".bright_yellow(), "enumerate            Disable enumeration from top files");
        println!("  {} {}", "unset".bright_yellow(), "enumerate-all        Disable enumeration from complete files");
        println!();
        println!("  {} {}", "show".bright_blue(), "options               Show current options");
        println!("  {} {}", "show".bright_blue(), "target                Show current target / url-list");
        println!();
        println!("  {} {}", "scan".bright_magenta(), "                      Run WordPress security scan");
        println!("  {} {}", "exploit".bright_magenta(), " <template>          Execute exploit template");
        println!("  {} {}", "exploit".bright_magenta(), " -d <dir>            Run all exploit templates in dir");
        println!("  {} {}", "vuln".bright_magenta(), " <template>           Run single vulnerability validation");
        println!("  {} {}", "vuln".bright_magenta(), " -d <dir>             Run mass vulnerability validation");
        println!("  {} {}", "bruteforce".bright_magenta(), " <users> <passwords>  Run password bruteforcing");
        println!("  {} {}", "spray".bright_magenta(), " <users> <passwords>   Run password spraying");
        println!("  {} {}", "update".bright_magenta(), "                      Update vulnerability databases");
        println!();
        println!("  {} {}", "clear".bright_white(), "                      Clear screen");
        println!("  {} {}", "help".bright_white(), "                      Show this help message");
        println!("  {} {}", "exit".bright_white(), "                      Exit interactive mode");
        println!();
        println!("{}", "Note: with url-list set, scan/vuln/exploit print compact lines:".bright_black());
        println!("{}", "  1/30 [template-id] https://target - vulnerable".bright_black());
        println!("{}", "  (vuln -d <dir> counts each template×URL as one job)".bright_black());
        println!();
    }

    fn handle_set(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("Usage: set <option> [value]");
            return Ok(());
        }

        match args[0] {
            "target" => {
                if args.len() < 2 {
                    println!("Usage: set target <url>");
                    return Ok(());
                }
                self.url_list = None;
                self.target = Some(args[1].to_string());
                println!("{} Target set to: {}", "✓".bright_green(), args[1].bright_cyan());
            }
            "url-list" | "url_list" | "targets-list" | "targets_list" => {
                if args.len() < 2 {
                    println!("Usage: set url-list <file>");
                    return Ok(());
                }
                // Validate file early
                let _ = crate::targets::load_url_list(args[1])?;
                self.target = None;
                self.url_list = Some(args[1].to_string());
                println!(
                    "{} URL list set to: {}",
                    "✓".bright_green(),
                    args[1].bright_cyan()
                );
            }
            "waf-bypass" => {
                self.waf_bypass = true;
                println!("{} WAF bypass enabled", "✓".bright_green());
            }
            "verbose" => {
                self.verbose = true;
                println!("{} Verbose output enabled", "✓".bright_green());
            }
            "threads" => {
                if args.len() < 2 {
                    println!("Usage: set threads <number>");
                    return Ok(());
                }
                match args[1].parse::<usize>() {
                    Ok(n) => {
                        self.threads = n;
                        println!("{} Threads set to: {}", "✓".bright_green(), n);
                    }
                    Err(_) => {
                        println!("{} Invalid thread count", "Error:".bright_red());
                    }
                }
            }
            "output" => {
                if args.len() < 2 {
                    println!("Usage: set output <json|table|markdown>");
                    return Ok(());
                }
                let format = args[1].to_lowercase();
                if ["json", "table", "markdown"].contains(&format.as_str()) {
                    self.output = format;
                    println!("{} Output format set to: {}", "✓".bright_green(), self.output);
                } else {
                    println!("{} Invalid output format. Use: json, table, or markdown", "Error:".bright_red());
                }
            }
            "force" => {
                self.force = true;
                println!("{} Force scan enabled", "✓".bright_green());
            }
            "stealth" => {
                self.stealth = true;
                println!("{} Stealth mode enabled", "✓".bright_green());
            }
            "enumerate" => {
                if args.len() < 2 {
                    println!("Usage: set enumerate <plugins|themes|plugins,themes>");
                    return Ok(());
                }
                let types: Vec<String> = args[1]
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| s == "plugins" || s == "themes")
                    .collect();
                
                if types.is_empty() {
                    println!("{} Invalid types. Use: plugins, themes, or plugins,themes", "Error:".bright_red());
                    return Ok(());
                }
                
                // Cannot use enumerate and enumerate-all simultaneously
                if self.enumerate_all.is_some() {
                    println!("{} Cannot use enumerate and enumerate-all simultaneously. Unset enumerate-all first.", "Error:".bright_red());
                    return Ok(());
                }
                
                self.enumerate = Some(types.clone());
                println!("{} Enumeration enabled: {}", "✓".bright_green(), types.join(", "));
            }
            "enumerate-all" | "enumerate_all" => {
                if args.len() < 2 {
                    println!("Usage: set enumerate-all <plugins|themes|plugins,themes>");
                    return Ok(());
                }
                let types: Vec<String> = args[1]
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| s == "plugins" || s == "themes")
                    .collect();
                
                if types.is_empty() {
                    println!("{} Invalid types. Use: plugins, themes, or plugins,themes", "Error:".bright_red());
                    return Ok(());
                }
                
                // Cannot use enumerate and enumerate-all simultaneously
                if self.enumerate.is_some() {
                    println!("{} Cannot use enumerate and enumerate-all simultaneously. Unset enumerate first.", "Error:".bright_red());
                    return Ok(());
                }
                
                self.enumerate_all = Some(types.clone());
                println!("{} Enumeration (complete) enabled: {}", "✓".bright_green(), types.join(", "));
            }
            _ => {
                println!("{} Unknown option: {}", "Error:".bright_red(), args[0]);
            }
        }

        Ok(())
    }

    fn handle_unset(&mut self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            println!("Usage: unset <option>");
            return Ok(());
        }

        match args[0] {
            "target" => {
                self.target = None;
                println!("{} Target cleared", "✓".bright_green());
            }
            "url-list" | "url_list" | "targets-list" | "targets_list" => {
                self.url_list = None;
                println!("{} URL list cleared", "✓".bright_green());
            }
            "waf-bypass" => {
                self.waf_bypass = false;
                println!("{} WAF bypass disabled", "✓".bright_green());
            }
            "verbose" => {
                self.verbose = false;
                println!("{} Verbose output disabled", "✓".bright_green());
            }
            "force" => {
                self.force = false;
                println!("{} Force scan disabled", "✓".bright_green());
            }
            "stealth" => {
                self.stealth = false;
                println!("{} Stealth mode disabled", "✓".bright_green());
            }
            "enumerate" => {
                self.enumerate = None;
                println!("{} Enumeration (top) disabled", "✓".bright_green());
            }
            "enumerate-all" | "enumerate_all" => {
                self.enumerate_all = None;
                println!("{} Enumeration (complete) disabled", "✓".bright_green());
            }
            _ => {
                println!("{} Unknown option: {}", "Error:".bright_red(), args[0]);
            }
        }

        Ok(())
    }

    fn handle_show(&self, args: &[&str]) -> Result<()> {
        if args.is_empty() {
            self.handle_show(&["options"])?;
            return Ok(());
        }

        match args[0] {
            "options" => {
                println!();
                println!("{}", "Current Options:".bright_cyan().bold());
                println!(
                    "  Target:     {}",
                    self.target
                        .as_ref()
                        .map(|t| t.as_str())
                        .unwrap_or("not set")
                        .bright_cyan()
                );
                println!(
                    "  URL list:   {}",
                    self.url_list
                        .as_ref()
                        .map(|t| t.as_str())
                        .unwrap_or("not set")
                        .bright_cyan()
                );
                println!("  WAF Bypass: {}", if self.waf_bypass { "enabled".bright_green() } else { "disabled".bright_red() });
                println!("  Stealth:    {}", if self.stealth { "enabled".bright_green() } else { "disabled".bright_red() });
                println!("  Verbose:    {}", if self.verbose { "enabled".bright_green() } else { "disabled".bright_red() });
                println!("  Force:      {}", if self.force { "enabled".bright_green() } else { "disabled".bright_red() });
                println!("  Threads:     {}", self.threads.to_string().bright_cyan());
                println!("  Output:      {}", self.output.bright_cyan());
                if let Some(ref enum_types) = self.enumerate {
                    println!("  Enumerate:   {} ({})", "enabled".bright_green(), enum_types.join(", "));
                } else {
                    println!("  Enumerate:   {}", "disabled".bright_red());
                }
                if let Some(ref enum_all_types) = self.enumerate_all {
                    println!("  Enumerate-All: {} ({})", "enabled".bright_green(), enum_all_types.join(", "));
                } else {
                    println!("  Enumerate-All: {}", "disabled".bright_red());
                }
                println!();
            }
            "target" => {
                if let Some(ref list) = self.url_list {
                    println!("URL list: {}", list.bright_cyan());
                } else if let Some(target) = &self.target {
                    println!("Target: {}", target.bright_cyan());
                } else {
                    println!(
                        "{} Set 'set target <url>' or 'set url-list <file>' first.",
                        "Error:".bright_red()
                    );
                }
            }
            _ => {
                println!("{} Unknown option: {}", "Error:".bright_red(), args[0]);
            }
        }

        Ok(())
    }

    fn ensure_targets(&self) -> Result<Vec<String>> {
        crate::targets::resolve_targets(self.target.as_deref(), self.url_list.as_deref())
            .map_err(|_| {
                anyhow::anyhow!(
                    "No target set. Use 'set target <url>' or 'set url-list <file>' first."
                )
            })
    }

    fn ensure_single_target(&self) -> Result<String> {
        if self.url_list.is_some() {
            anyhow::bail!(
                "bruteforce/spray require a single target. Unset url-list and use 'set target <url>'."
            );
        }
        self.target.clone().ok_or_else(|| {
            anyhow::anyhow!("Target not set. Use 'set target <url>' first.")
        })
    }

    fn handle_vuln(&mut self, args: &[&str]) -> Result<()> {
        let targets = self.ensure_targets()?;
        let multi = targets.len() > 1 || self.url_list.is_some();
        let total = targets.len();

        let mut template: Option<String> = None;
        let mut template_dir: Option<String> = None;

        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "-t" | "--template" => {
                    if i + 1 < args.len() {
                        template = Some(args[i + 1].to_string());
                        i += 2;
                    } else {
                        return Err(anyhow::anyhow!("--template requires a path"));
                    }
                }
                "-d" | "--template-dir" | "--dir" => {
                    if i + 1 < args.len() {
                        template_dir = Some(args[i + 1].to_string());
                        i += 2;
                    } else {
                        return Err(anyhow::anyhow!("--template-dir requires a path"));
                    }
                }
                _ => {
                    if template.is_none() && template_dir.is_none() {
                        template = Some(args[i].to_string());
                    }
                    i += 1;
                }
            }
        }

        if template.is_none() && template_dir.is_none() {
            println!("Usage: vuln <template_path> OR vuln -d <template_directory>");
            return Ok(());
        }
        if template.is_some() && template_dir.is_some() {
            return Err(anyhow::anyhow!(
                "Provide either a template file or -d <template-dir>, not both"
            ));
        }

        let templates = if let Some(template_path) = template {
            if !multi {
                println!(
                    "{} Running vulnerability validation: {}...",
                    "→".bright_blue(),
                    template_path.bright_cyan()
                );
            }
            vec![crate::vulns::VulnEngine::load_template(&template_path)?]
        } else if let Some(dir) = template_dir {
            if !multi {
                println!(
                    "{} Running mass vulnerability validation from {}...",
                    "→".bright_blue(),
                    dir.bright_cyan()
                );
            }
            crate::vulns::VulnEngine::load_templates_from_dir(&dir)?
        } else {
            vec![]
        };

        let total_jobs = total.saturating_mul(templates.len().max(1));
        let mut job = 0usize;

        for url in targets.iter() {
            let client =
                crate::http_client::HttpClient::new(url.clone(), self.waf_bypass, self.stealth)?;

            if multi {
                for tmpl in &templates {
                    job += 1;
                    match crate::vulns::VulnEngine::execute(tmpl, &client) {
                        Ok(result) => {
                            crate::output::OutputFormatter::print_url_list_result(
                                job,
                                total_jobs,
                                &result.template_id,
                                url,
                                result.matched,
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "{} [{}/{}] [{}] {} - error: {}",
                                "!".bright_red(),
                                job,
                                total_jobs,
                                tmpl.id,
                                url,
                                e
                            );
                        }
                    }
                }
            } else {
                // Single target: threaded mass validation when template-dir + threads > 1
                let mut results = vec![];
                if templates.len() == 1 || self.threads <= 1 {
                    for tmpl in &templates {
                        match crate::vulns::VulnEngine::execute(tmpl, &client) {
                            Ok(result) => results.push(result),
                            Err(e) => eprintln!("Error executing template {}: {}", tmpl.id, e),
                        }
                    }
                } else {
                    let (tx, rx) = std::sync::mpsc::channel();
                    let client_arc = std::sync::Arc::new(client);
                    let templates_arc: Vec<_> =
                        templates.iter().cloned().map(std::sync::Arc::new).collect();
                    let num_threads = self.threads.max(1).min(templates_arc.len());
                    let chunk_size = templates_arc.len().div_ceil(num_threads);
                    let mut handles = vec![];

                    for chunk in templates_arc.chunks(chunk_size) {
                        let chunk = chunk.to_vec();
                        let client_clone = std::sync::Arc::clone(&client_arc);
                        let tx_clone = tx.clone();

                        let handle = std::thread::spawn(move || {
                            for template in chunk {
                                match crate::vulns::VulnEngine::execute(&template, &client_clone) {
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

                let mut scan_results = crate::models::ScanResults::for_target(url.clone());
                scan_results.vuln_validations = results;
                let output = crate::output::OutputFormatter::format(
                    &scan_results,
                    &self.output,
                    self.verbose,
                );
                println!("{}", output);
            }
        }

        Ok(())
    }

    fn handle_scan(&mut self, _args: &[&str]) -> Result<()> {
        let targets = self.ensure_targets()?;
        let multi = targets.len() > 1 || self.url_list.is_some();
        let total = targets.len();

        if self.enumerate.is_some() && self.enumerate_all.is_some() {
            eprintln!(
                "{} Cannot use enumerate and enumerate-all simultaneously",
                "Error:".bright_red()
            );
            return Err(anyhow::anyhow!(
                "Cannot use enumerate and enumerate-all simultaneously"
            ));
        }

        for (idx, url) in targets.iter().enumerate() {
            if !multi {
                println!(
                    "{} Running scan on {}...",
                    "→".bright_blue(),
                    url.bright_cyan()
                );
            }

            let client =
                crate::http_client::HttpClient::new(url.clone(), self.waf_bypass, self.stealth)?;
            let use_realtime_output = !multi && !self.verbose && self.output == "table";
            match crate::scanner::Scanner::scan(
                &client,
                self.verbose,
                use_realtime_output,
                self.force,
                self.stealth,
                self.enumerate.clone(),
                self.enumerate_all.clone(),
            ) {
                Ok(results) => {
                    if multi {
                        crate::output::OutputFormatter::print_url_list_result(
                            idx + 1,
                            total,
                            "scan",
                            url,
                            !results.vulnerabilities.is_empty(),
                        );
                    } else if !use_realtime_output {
                        let output = crate::output::OutputFormatter::format(
                            &results,
                            &self.output,
                            self.verbose,
                        );
                        println!("{}", output);
                    }
                }
                Err(e) => {
                    if multi {
                        eprintln!(
                            "{} [{}/{}] [scan] {} - error: {}",
                            "!".bright_red(),
                            idx + 1,
                            total,
                            url,
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

    fn handle_exploit(&mut self, args: &[&str]) -> Result<()> {
        let targets = self.ensure_targets()?;
        let multi = targets.len() > 1 || self.url_list.is_some();
        let total = targets.len();

        let mut template: Option<String> = None;
        let mut template_dir: Option<String> = None;

        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "-t" | "--template" => {
                    if i + 1 < args.len() {
                        template = Some(args[i + 1].to_string());
                        i += 2;
                    } else {
                        return Err(anyhow::anyhow!("--template requires a path"));
                    }
                }
                "-d" | "--template-dir" | "--dir" => {
                    if i + 1 < args.len() {
                        template_dir = Some(args[i + 1].to_string());
                        i += 2;
                    } else {
                        return Err(anyhow::anyhow!("--template-dir requires a path"));
                    }
                }
                _ => {
                    if template.is_none() && template_dir.is_none() {
                        template = Some(args[i].to_string());
                    }
                    i += 1;
                }
            }
        }

        if template.is_none() && template_dir.is_none() {
            println!("Usage: exploit <template_path> OR exploit -d <template_directory>");
            return Ok(());
        }
        if template.is_some() && template_dir.is_some() {
            return Err(anyhow::anyhow!(
                "Provide either a template file or -d <template-dir>, not both"
            ));
        }

        let templates = if let Some(template_path) = template {
            if !multi {
                println!(
                    "{} Executing exploit template: {}...",
                    "→".bright_blue(),
                    template_path.bright_cyan()
                );
            }
            vec![crate::exploits::ExploitEngine::load_template(&template_path)?]
        } else if let Some(dir) = template_dir {
            if !multi {
                println!(
                    "{} Executing exploit templates from {}...",
                    "→".bright_blue(),
                    dir.bright_cyan()
                );
            }
            crate::exploits::ExploitEngine::load_templates_from_dir(&dir)?
        } else {
            vec![]
        };

        let total_jobs = total.saturating_mul(templates.len().max(1));
        let mut job = 0usize;

        for url in targets.iter() {
            let client =
                crate::http_client::HttpClient::new(url.clone(), self.waf_bypass, self.stealth)?;

            if multi {
                for tmpl in &templates {
                    job += 1;
                    match crate::exploits::ExploitEngine::execute(tmpl, &client) {
                        Ok(result) => {
                            crate::output::OutputFormatter::print_url_list_result(
                                job,
                                total_jobs,
                                &result.template_id,
                                url,
                                result.success,
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "{} [{}/{}] [{}] {} - error: {}",
                                "!".bright_red(),
                                job,
                                total_jobs,
                                tmpl.id,
                                url,
                                e
                            );
                        }
                    }
                }
            } else {
                let mut results = vec![];
                for tmpl in &templates {
                    match crate::exploits::ExploitEngine::execute(tmpl, &client) {
                        Ok(result) => results.push(result),
                        Err(e) => eprintln!("Error executing template {}: {}", tmpl.id, e),
                    }
                }
                let mut scan_results = crate::models::ScanResults::for_target(url.clone());
                scan_results.exploit_results = results;
                let output = crate::output::OutputFormatter::format(
                    &scan_results,
                    &self.output,
                    self.verbose,
                );
                println!("{}", output);
            }
        }

        Ok(())
    }

    fn handle_bruteforce(&mut self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            println!("Usage: bruteforce <users_file> <passwords_file> [options]");
            return Ok(());
        }

        let url = self.ensure_single_target()?;
        let users = args[0].to_string();
        let passwords = args[1].to_string();

        let mut bruteforce_type = "wp-login".to_string();
        let mut rate_limit = 10u64;
        let mut stop_on_success = false;

        let mut i = 2;
        while i < args.len() {
            match args[i] {
                "--bruteforce-type" | "--type" => {
                    if i + 1 < args.len() {
                        bruteforce_type = args[i + 1].to_string();
                        i += 2;
                    } else {
                        return Err(anyhow::anyhow!("--bruteforce-type requires a value"));
                    }
                }
                "--rate-limit" | "--rate" => {
                    if i + 1 < args.len() {
                        rate_limit = args[i + 1].parse()
                            .map_err(|_| anyhow::anyhow!("Invalid rate limit"))?;
                        i += 2;
                    } else {
                        return Err(anyhow::anyhow!("--rate-limit requires a value"));
                    }
                }
                "--stop-on-success" | "--stop" => {
                    stop_on_success = true;
                    i += 1;
                }
                _ => i += 1,
            }
        }

        println!("{} Running bruteforce attack on {}...", 
            "→".bright_blue(), url.bright_cyan());

        let client = crate::http_client::HttpClient::new(url.clone(), self.waf_bypass, self.stealth)?;
        let bf_results = crate::bruteforce::BruteforceEngine::bruteforce(
            &client,
            &users,
            &passwords,
            &bruteforce_type,
            rate_limit,
            stop_on_success,
        )?;

        let scan_results = crate::models::ScanResults {
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

        let output = crate::output::OutputFormatter::format(&scan_results, &self.output, self.verbose);
        println!("{}", output);

        Ok(())
    }

    fn handle_spray(&mut self, args: &[&str]) -> Result<()> {
        if args.len() < 2 {
            println!("Usage: spray <users_file> <passwords_file> [options]");
            return Ok(());
        }

        let url = self.ensure_single_target()?;
        let users = args[0].to_string();
        let passwords = args[1].to_string();

        let mut bruteforce_type = "wp-login".to_string();
        let mut rate_limit = 2u64;

        let mut i = 2;
        while i < args.len() {
            match args[i] {
                "--bruteforce-type" | "--type" => {
                    if i + 1 < args.len() {
                        bruteforce_type = args[i + 1].to_string();
                        i += 2;
                    } else {
                        return Err(anyhow::anyhow!("--bruteforce-type requires a value"));
                    }
                }
                "--rate-limit" | "--rate" => {
                    if i + 1 < args.len() {
                        rate_limit = args[i + 1].parse()
                            .map_err(|_| anyhow::anyhow!("Invalid rate limit"))?;
                        i += 2;
                    } else {
                        return Err(anyhow::anyhow!("--rate-limit requires a value"));
                    }
                }
                _ => i += 1,
            }
        }

        println!("{} Running password spray attack on {}...", 
            "→".bright_blue(), url.bright_cyan());

        let client = crate::http_client::HttpClient::new(url.clone(), self.waf_bypass, self.stealth)?;
        let bf_results = crate::bruteforce::BruteforceEngine::spray(
            &client,
            &users,
            &passwords,
            &bruteforce_type,
            rate_limit,
        )?;

        let scan_results = crate::models::ScanResults {
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

        let output = crate::output::OutputFormatter::format(&scan_results, &self.output, self.verbose);
        println!("{}", output);

        Ok(())
    }

    fn handle_update(&self) -> Result<()> {
        println!("{} Updating vulnerability databases...", "→".bright_blue());
        crate::database::DatabaseManager::update_all()?;
        println!("{} Database update complete", "✓".bright_green());
        Ok(())
    }
}
