mod error;
mod http;
mod parsers;
mod deps_resolver;
mod osv;
mod schemas;
mod tui;
mod function_extractor;
mod code_walker;

use std::collections::HashMap;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode};

use crate::{
    code_walker::VulnerableUsage,
    deps_resolver::resolve_all_deps,
    error::AppError,
    function_extractor::get_all_vulnerable_function_signatures,
    http::download_package_source,
    osv::VulnFetcher,
    tui::{App, draw},
};

#[derive(Parser)]
#[command(name = "pypi-scanner")]
#[command(about = "Scanning PyPI-packages for vulnerabilities")]
struct Cli {
    package: String,
    version: String,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    println!("Gathering data...");
    let deps = resolve_all_deps(&cli.package, &cli.version).await?;

    println!("Checking for vulnerabilities...");
    let vuln_fetcher = VulnFetcher::new();
    let vulns = vuln_fetcher.fetch_vulnerabilities(deps).await?;

    println!("Analyzing reachability...");
    let vuln_functions = get_all_vulnerable_function_signatures(&vulns)?;
    let tmp_dir = download_package_source(&cli.package, &cli.version).await?;
    let tmp_prefix = tmp_dir.path().to_string_lossy().to_string();

    let mut reachability: HashMap<String, Vec<VulnerableUsage>> = HashMap::new();

    for vf in &vuln_functions {
        // skip vulns belonging to the root package itself
        if vf.package_id == cli.package || vf.functions.is_empty() {
            continue;
        }
        let usages =
            find_vulnerable_usages_in_package(tmp_dir.path(), &vf.package_id, &vf.functions)?;

        if usages.is_empty() {
            continue;
        }

        let mut stripped: Vec<VulnerableUsage> = usages
            .into_iter()
            .map(|u| VulnerableUsage {
                file: u
                    .file
                    .strip_prefix(&tmp_prefix)
                    .unwrap_or(&u.file)
                    .trim_start_matches('/')
                    .to_string(),
                function: u.function,
            })
            .collect();

        stripped.sort_by(|a, b| a.file.cmp(&b.file).then(a.function.cmp(&b.function)));
        stripped.dedup_by(|a, b| a.file == b.file && a.function == b.function);

        reachability.insert(vf.vuln_id.clone(), stripped);
    }

    drop(tmp_dir);

    let mut terminal = ratatui::init();
    let mut app = App::new(vulns, reachability);

    loop {
        terminal.draw(|f| draw(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => app.next(),
                KeyCode::Up   | KeyCode::Char('k') => app.prev(),
                KeyCode::Char('q') | KeyCode::Esc  => break,
                _ => {}
            }
        }
    }

    ratatui::restore();
    Ok(())
}

use crate::code_walker::find_vulnerable_usages_in_package;
