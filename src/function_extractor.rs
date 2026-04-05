use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{code_walker::find_vulnerable_usages_in_package, deps_resolver::resolve_all_deps, error::AppError, http::download_package_source, osv::VulnFetcher, schemas::OsvVuln};

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
pub struct VulnsForReachabilitySearch {
    pub vuln_id: String,
    pub package_id: String,
    pub functions: Vec<String>,
}

pub fn get_all_vulnerable_function_signatures(vulns: &Vec<OsvVuln>) -> Result<Vec<VulnsForReachabilitySearch>, AppError> {

    let vuln_functions = vulns.into_iter().map(|v| {
        let details = v.details.clone().unwrap_or_default();
        let summary = v.summary.clone().unwrap_or_default();
        let vuln_id = v.id.clone();

        let mut functions = extract_identifiers(&details);
        functions.extend(extract_identifiers(&summary));

        VulnsForReachabilitySearch{
            vuln_id,
            package_id: get_package(&v).to_string(),
            functions,
        }
    }).collect();

    Ok(vuln_functions)
}

fn extract_identifiers(text: &str) -> Vec<String> {
    let patterns = vec![
        // backtick-wrappade identifiers: `extract_zipped_paths()`
        r"`([\w\.]+\([\w=,\s]*\))`",
        // backtick-wrappade utan parens: `trust_env`, `Cookie`, `Proxy-Authorization`  
        r"`([\w\.\-]+)`",
        // code-formatted i markdown: **`something`**
        r"\*\*`([\w\.]+)`\*\*",
    ];

    let mut results = vec![];
    for pattern in patterns {
        let re = Regex::new(pattern).unwrap();
        for cap in re.captures_iter(text) {
            results.push(cap[1].to_string());
        }
    }
    results.sort();
    results.dedup();
    results
}

fn get_package(entry: &OsvVuln) -> &str {
    entry.affected.as_ref()
        .and_then(|a| a.first())
        .and_then(|a| a.package.as_ref())
        .map(|p| p.name.as_str())
        .unwrap_or("—")
}

#[tokio::test]
async fn test_get_all_vulnerable_function_signatures() {
    let package_id = "requests";
    let version = "2.20.0";

    println!("Gathering data...");
    let deps = resolve_all_deps(package_id, version).await.unwrap();

    println!("Checking for vulnerabilities...");
    let vuln_fetcher = VulnFetcher::new();
    let vulns = vuln_fetcher.fetch_vulnerabilities(deps).await.unwrap();

    println!("Extracting functions...");

    let vuln_functions = tokio::task::spawn_blocking(move || {get_all_vulnerable_function_signatures(&vulns)}).await.unwrap().unwrap();

    println!("Fetching source code...");
    let tmp_dir = download_package_source(&package_id, &version).await.unwrap();

    for vf in vuln_functions {
        if vf.package_id == package_id {continue;}
        let code_results = find_vulnerable_usages_in_package(tmp_dir.path(), &vf.package_id, &vf.functions).unwrap();

        println!("{}", serde_json::to_string(&code_results).unwrap())
    }

    

    
}
