use clang::{Clang, Index, TranslationUnit};
use internal::VulnerabilityScanner;
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};

pub mod analyzer;
mod internal;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[derive(Serialize, Deserialize)]
pub(crate) struct Report {
    pub line_number: u32, // 32 bit integer unsigned
    pub vulnerability_class: String,
}

/*
 * TODO:
 * 1. Create Trait based axiomatization rules. Sus
 * 2. Create state trackers for current code context. Rizz
 * // Keep it as static as possible.
 * 3. As for as practicable stay onto AST only and try not to go beyond and rely upon LLVM IR. Atul
 */

pub(crate) fn try_analyze(src: String, _fname: String) -> Result<Vec<Report>> {
    let mut scanner = VulnerabilityScanner::new(src.as_str());

    scanner.register_check("Use after free", internal::detect_use_after_free);
    scanner.run();

    Ok(scanner.found_patterns())
}
