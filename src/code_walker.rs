use std::collections::HashMap;
use std::path::Path;
use serde::{Deserialize, Serialize};
use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};
use walkdir::WalkDir;

use crate::error::AppError;

#[derive(Debug, Deserialize, Serialize)]
pub struct VulnerableUsage {
    pub file: String,
    pub function: String,
}

const BUILTINS: &[&str] = &[
    "str", "int", "float", "bool", "list", "dict", "set", "tuple",
    "len", "range", "print", "encode", "decode", "read", "write",
    "open", "super", "type", "isinstance", "hasattr", "getattr",
    "u", "b", "r", // vanliga compat-wrappers i gamla requests
];

pub fn find_vulnerable_usages_in_package(
    root: &Path,
    vulnerable_package: &str,
    vulnerable_functions: &[String],
) -> Result<Vec<VulnerableUsage>, AppError> {
    let language = tree_sitter_python::LANGUAGE.into();
    let mut parser = Parser::new();
    parser.set_language(&language).unwrap();

    let import_query = Query::new(
        &language,
        r#"[
          (import_statement name: (dotted_name) @import)
          (import_from_statement
            module_name: (dotted_name) @module
            name: (_) @name)
          (import_from_statement
            module_name: (dotted_name) @module
            name: (aliased_import name: (dotted_name) @name alias: (identifier) @alias))
        ]"#,
    )
    .unwrap();

    let call_query = Query::new(
        &language,
        r#"(call function: [
            (identifier) @fn
            (attribute attribute: (identifier) @fn)
        ])"#,
    )
    .unwrap();

    let mut results = vec![];

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
                .filter(|e| {
            let path = e.path();
            let is_py = path.extension().map_or(false, |ext| ext == "py");
            let is_test = path.components().any(|c| {
                let s = c.as_os_str().to_string_lossy();
                s == "tests" || s == "test" || s.starts_with("test_")
            });
            is_py && !is_test
        })
    {
        let source = std::fs::read_to_string(entry.path())?;
        let tree = parser.parse(&source, None).unwrap();
        let root = tree.root_node();

        let mut import_map: HashMap<String, String> = HashMap::new();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&import_query, root, source.as_bytes());

        while let Some(m) = matches.next() {
            let mut module_text: Option<String> = None;
            let mut name_text: Option<String> = None;
            let mut alias_text: Option<String> = None;

            for cap in m.captures {
                let cap_name = &import_query.capture_names()[cap.index as usize];

                if !cap_name.is_empty() && !BUILTINS.contains(&cap_name) && vulnerable_functions.iter().any(|f| f.contains(cap_name)) {
                    results.push(VulnerableUsage { file: entry.path().to_string_lossy().to_string(), function: cap_name.to_string() });
                }

                let text = cap.node.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                match cap_name.as_ref() {
                    "module" => module_text = Some(text),
                    "name" => name_text = Some(text),
                    "alias" => alias_text = Some(text),
                    "import" => {
                        if text.contains(vulnerable_package) {
                            import_map.insert(text, vulnerable_package.to_string());
                        }
                    }
                    _ => {}
                }
            }

            if let Some(module) = module_text {
                if module.contains(vulnerable_package) {
                    if let Some(alias) = alias_text {
                        import_map.insert(alias, vulnerable_package.to_string());
                    } else if let Some(name) = name_text {
                        import_map.insert(name, vulnerable_package.to_string());
                    }
                }
            }
        }

        if import_map.is_empty() {
            continue;
        }

        let mut cursor2 = QueryCursor::new();
        let mut call_matches = cursor2.matches(&call_query, root, source.as_bytes());

        while let Some(m) = call_matches.next() {
            for cap in m.captures {
                let name = cap.node.utf8_text(source.as_bytes()).unwrap_or("");
                if !name.is_empty() && vulnerable_functions.iter().any(|f| f.contains(name)) {
                    results.push(VulnerableUsage {
                        file: entry.path().to_string_lossy().to_string(),
                        function: name.to_string(),
                    });
                }
            }
        }
    }

    Ok(results)
}