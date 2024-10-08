use clang::{Clang, Entity, EntityKind, Index, TranslationUnit, Type, TypeKind};
use std::collections::HashMap;
use std::env;
use std::env::var;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Report;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn with_temporary_directory<F: FnOnce(&Path)>(f: F) {
    let exe = env::current_exe()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let mut path;

    loop {
        path = env::temp_dir().join(format!("{}{}", exe, COUNTER.fetch_add(1, Ordering::SeqCst)));

        if !path.exists() {
            break;
        }
    }

    fs::create_dir(&path).unwrap();
    f(&path);
    fs::remove_dir_all(&path).unwrap();
}

pub fn with_temporary_files<F: FnOnce(&Path, Vec<PathBuf>)>(files: &[(&str, &str)], f: F) {
    with_temporary_directory(|d| {
        let files = files
            .iter()
            .map(|&(n, v)| {
                let file = d.join(n);
                fs::File::create(&file)
                    .unwrap()
                    .write_all(v.as_bytes())
                    .unwrap();
                file
            })
            .collect::<Vec<_>>();

        f(d, files);
    });
}

fn with_temporary_file<F: FnOnce(&Path, &Path)>(name: &str, contents: &str, f: F) {
    with_temporary_files(&[(name, contents)], |d, fs| f(d, &fs[0]));
}

pub fn with_translation_unit<'c, F>(
    clang: &'c Clang,
    name: &str,
    contents: &str,
    arguments: &[&str],
    f: F,
) where
    F: FnOnce(&Path, &Path, TranslationUnit),
{
    with_temporary_file(name, contents, |d, file| {
        let index = Index::new(clang, false, false);
        f(
            d,
            &file,
            index.parser(file).arguments(arguments).parse().unwrap(),
        );
    });
}

pub fn with_types<'c, F: FnOnce(Vec<Type>)>(clang: &'c Clang, contents: &str, f: F) {
    with_translation_unit(clang, "test.cpp", contents, &[], |_, _, tu| {
        f(tu.get_entity()
            .get_children()
            .iter()
            .flat_map(|e| e.get_type().into_iter())
            .collect());
    });
}

type VulnerabilityCheck = fn(&Entity, &mut HashMap<String, u32>, &mut Vec<(String, u32)>);

pub struct VulnerabilityScanner {
    source_code: String,
    checks: Vec<(String, VulnerabilityCheck)>,
    results: HashMap<String, Vec<(String, u32)>>,
}

impl VulnerabilityScanner {
    pub fn new(source_code: &str) -> Self {
        Self {
            source_code: source_code.to_string(),
            checks: Vec::new(),
            results: HashMap::new(),
        }
    }

    pub fn register_check(&mut self, name: &str, check: VulnerabilityCheck) {
        self.checks.push((name.to_string(), check));
    }

    pub fn run(&mut self) {
        let Ok(clang) = Clang::new() else {
            unreachable!("Unable to create Clang instance");
            return;
        };
        let index = Index::new(&clang, false, false);

        let mut free_lines = HashMap::new();

        with_temporary_file("place_holder.cpp", self.source_code.as_str(), |_, f| {
            let translation_unit = index.parser(f).parse().unwrap();
            translation_unit.get_entity().visit_children(|entity, _| {
                for (name, check) in &self.checks {
                    let mut results = self.results.entry(name.clone()).or_insert(Vec::new());
                    check(&entity, &mut free_lines, &mut results);
                }
                clang::EntityVisitResult::Recurse
            });
        });
    }

    pub fn report(&self) {
        for (name, results) in &self.results {
            if results.is_empty() {
                println!("No {} vulnerabilities detected.", name);
            } else {
                println!("{} vulnerabilities found:", name);
                for (var_name, line) in results {
                    println!("Variable '{}' involved at line {}", var_name, line);
                }
            }
        }
    }
    pub fn found_patterns(&self) -> Vec<Report> {
        let mut ret: Vec<Report> = vec![]; // init a vec
        for (name, results) in &self.results {
            if results.is_empty() {
                break;
            } else {
                for (_var_name, line) in results {
                    ret.push(Report {
                        line_number: *line,
                        vulnerability_class: name.to_string(),
                    });
                }
            }
        }

        ret
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Allocated,
    Deallocated,
    Reassigned,
}

/*
pub(crate) fn detect_use_after_free(
    entity: &Entity,
    var_states: &mut HashMap<String, VariableState>,
    results: &mut Vec<(String, u32)>,
) {
    match entity.get_kind() {
        EntityKind::CallExpr => {
            if let Some(called_function) = entity.get_name() {
                // Check if this is an allocation or free function
                if let Some(result_type) = entity.get_type() {
                    if result_type.get_kind() == TypeKind::Pointer {
                        // Allocation operation
                        if let Some(parent) = entity.get_lexical_parent() {
                            if let EntityKind::VarDecl | EntityKind::DeclRefExpr = parent.get_kind()
                            {
                                if let Some(var_name) = parent.get_name() {
                                    let line = entity
                                        .get_location()
                                        .map_or(0, |loc| loc.get_spelling_location().line);
                                    let state = var_states
                                        .entry(var_name.clone())
                                        .or_insert_with(VariableState::new);

                                    match state.state {
                                        State::Initial | State::Deallocation => {
                                            state.transition(State::Allocation, line)
                                        }
                                        State::Usage | State::Reassignment => {
                                            state.transition(State::Reassignment, line)
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                } else if called_function == "free" || called_function == "delete" {
                    // Deallocation operation
                    if let Some(var_name) = entity
                        .get_arguments()
                        .as_ref()
                        .and_then(|args| args.first())
                        .and_then(|arg| arg.get_name())
                    {
                        let line = entity
                            .get_location()
                            .map_or(0, |loc| loc.get_spelling_location().line);
                        if let Some(state) = var_states.get_mut(&var_name) {
                            if state.state == State::Usage || state.state == State::Allocation {
                                state.transition(State::Deallocation, line);
                            }
                        }
                    }
                }
            }
        }
        EntityKind::DeclRefExpr => {
            if let Some(var_name) = entity.get_name() {
                let line = entity
                    .get_location()
                    .map_or(0, |loc| loc.get_spelling_location().line);
                if let Some(state) = var_states.get_mut(&var_name) {
                    match state.state {
                        State::Deallocation => {
                            // Use-after-free detected
                            results.push((var_name.clone(), line));
                            state.transition(State::Initial, line); // Reset to initial after detection
                        }
                        State::Allocation | State::Reassignment => {
                            state.transition(State::Usage, line);
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }
}*/

fn detect_use_after_free_internal(
    entity: &Entity,
    free_lines: &mut HashMap<String, u32>,
    variable_states: &mut HashMap<String, State>,
    results: &mut Vec<(String, u32)>,
) {
    match entity.get_kind() {
        EntityKind::CallExpr => handle_call_expr(entity, free_lines, variable_states),
        EntityKind::BinaryOperator => handle_reassignment(entity, variable_states, free_lines),
        EntityKind::NewExpr => handle_new_expr(entity, variable_states, free_lines),
        EntityKind::DeclRefExpr => handle_decl_ref_expr(entity, variable_states, results),
        EntityKind::DeleteExpr => handle_delete_expr(entity, variable_states, free_lines),
        _ => {}
    }

    for child in entity.get_children() {
        detect_use_after_free_internal(&child, free_lines, variable_states, results);
    }
}

fn handle_call_expr(
    entity: &Entity,
    free_lines: &mut HashMap<String, u32>,
    variable_states: &mut HashMap<String, State>,
) {
    if let Some(function_name) = entity.get_name() {
        if function_name == "malloc" || function_name == "calloc" {
            handle_allocation(entity, variable_states, free_lines);
        } else if function_name == "free" {
            handle_deallocation(entity, variable_states, free_lines);
        }
    }
}

fn handle_binary_operator(
    entity: &Entity,
    variable_states: &mut HashMap<String, State>,
    free_lines: &mut HashMap<String, u32>,
) {
    if is_assignment(entity) {
        if let Some(var_name) = entity.get_name() {
            if is_pointer_assignment(entity) {
                variable_states.insert(var_name.clone(), State::Reassigned);
                if let Some(location) = entity.get_location() {
                    free_lines.remove(&var_name);
                    println!(
                        "Memory reassigned for '{}' at line {}",
                        var_name,
                        location.get_spelling_location().line
                    );
                }
            }
        }
    }
}

fn is_assignment(entity: &Entity) -> bool {
    if let Some(op) = entity.get_display_name() {
        return op.contains('=') && !op.contains("==");
    }
    false
}

fn is_pointer_assignment(entity: &Entity) -> bool {
    entity.get_children().iter().any(|child| {
        if let Some(child_type) = child.get_type() {
            return child_type.get_kind() == TypeKind::Pointer;
        }
        false
    })
}

fn handle_allocation(
    entity: &Entity,
    variable_states: &mut HashMap<String, State>,
    free_lines: &mut HashMap<String, u32>,
) {
    if let Some(parent) = entity.get_semantic_parent() {
        if let Some(var_name) = parent.get_name() {
            variable_states.insert(var_name.clone(), State::Allocated);
            if let Some(location) = parent.get_location() {
                // free_lines.insert(var_name, location.get_spelling_location().line);
            }
        }
    }
}

fn handle_deallocation(
    entity: &Entity,
    variable_states: &mut HashMap<String, State>,
    free_lines: &mut HashMap<String, u32>,
) {
    if let Some(arg) = entity
        .get_arguments()
        .as_ref() // operate on the reference
        .and_then(|args| args.first())
    {
        if let Some(var_name) = arg.get_name() {
            if let Some(location) = arg.get_location() {
                let line = location.get_spelling_location().line;
                println!("Memory freed for '{}' at line {}", var_name, line);
                free_lines.insert(var_name.clone(), line);
                variable_states.insert(var_name.clone(), State::Deallocated);
            }
        }
    }
}

fn handle_new_expr(
    entity: &Entity,
    variable_states: &mut HashMap<String, State>,
    free_lines: &mut HashMap<String, u32>,
) {
    if let Some(parent) = entity.get_semantic_parent() {
        if let Some(var_name) = parent.get_name() {
            variable_states.insert(var_name.clone(), State::Allocated);
            /* if let Some(location) = parent.get_location() {
                println!(
                    "Memory allocated (new) for '{}' at line {}",
                    var_name,
                    location.get_spelling_location().line
                );
            } */
        }
    }
}

fn handle_delete_expr(
    entity: &Entity,
    variable_states: &mut HashMap<String, State>,
    free_lines: &mut HashMap<String, u32>,
) {
    if let Some(arg) = entity
        .get_arguments()
        .as_ref()
        .and_then(|args| args.first())
    {
        if let Some(var_name) = arg.get_name() {
            if let Some(location) = arg.get_location() {
                let line = location.get_spelling_location().line;
                println!("Memory freed (delete) for '{}' at line {}", var_name, line);
                free_lines.insert(var_name.clone(), line);
                variable_states.insert(var_name.clone(), State::Deallocated);
            }
        }
    }
}

fn handle_reassignment(
    entity: &Entity,
    variable_states: &mut HashMap<String, State>,
    free_lines: &mut HashMap<String, u32>,
) {
    if is_assignment(entity) {
        if let Some(var_name) = entity.get_name() {
            if is_pointer_assignment(entity) {
                variable_states.insert(var_name.clone(), State::Reassigned);
                if let Some(location) = entity.get_location() {
                    free_lines.remove(&var_name);
                    println!(
                        "Memory reassigned for '{}' at line {}",
                        var_name,
                        location.get_spelling_location().line
                    );
                }
            }
        }
    }
}

fn handle_decl_ref_expr(
    entity: &Entity,
    variable_states: &HashMap<String, State>,
    results: &mut Vec<(String, u32)>,
) {
    if let Some(var_name) = entity.get_name() {
        if let Some(state) = variable_states.get(&var_name) {
            if *state == State::Deallocated {}
            {
                if let Some(location) = entity.get_location() {
                    let line = location.get_spelling_location().line;
                    println!(
                        "Use-after-free detected for '{}' at line {}",
                        var_name, line
                    );
                    results.push((var_name, line));
                }
            }
        }
    }
}

pub(crate) fn detect_use_after_free(
    entity: &Entity,
    free_lines: &mut HashMap<String, u32>,
    results: &mut Vec<(String, u32)>,
) {
    let mut variable_states = HashMap::new();
    detect_use_after_free_internal(entity, free_lines, &mut variable_states, results);
}

/* pub(crate) fn detect_use_after_free(
    entity: &Entity,
    free_lines: &mut HashMap<String, u32>,
    results: &mut Vec<(String, u32)>,
) {
    match entity.get_kind() {
        EntityKind::CallExpr => {
            // NOTE: Mark function calls
            // Handle free or delete calls
            if handle_free_or_delete(entity, free_lines).is_none() {
                // If not a free/delete, check if the function returns a pointer
                if let Some(result_type) = entity.get_type() {
                    if result_type.get_kind() == TypeKind::Pointer {
                        // For a variable that returns a pointer type its HIGHLY likely that it is a Heap allocated memory
                        // Check if the result of the function call is assigned to a variable
                        if entity.get_lexical_parent().is_some() {
                            let parent = entity.get_lexical_parent().unwrap();
                            match parent.get_kind() {
                                EntityKind::BinaryOperator => {
                                    if let Some(op) = parent.get_name() {
                                        if op.contains('=') && !op.contains("==") {
                                            let Some(name) = entity.get_name() else {
                                                unreachable!("Expected a variable name on the left side of the assignment operator");
                                            };
                                            free_lines.remove(&name);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        /* if let EntityKind::VarDecl
                        | EntityKind::DeclRefExpr
                        | EntityKind::BinaryOperator = parent.get_kind()
                        {
                            if let Some(var_name) = parent.get_name() {
                                free_lines.remove(&var_name); // Reset free status
                            }
                        } */
                    }
                }
            }
        }
        EntityKind::NewExpr => {
            if let Some(var_name) = entity.get_name() {
                free_lines.remove(&var_name); // Reset free status
            }
        }
        EntityKind::DeleteExpr => {
            if let Some(var_name) = entity
                .get_children()
                .first()
                .and_then(|child| child.get_name())
            {
                if let Some(location) = entity.get_location() {
                    let line = location.get_spelling_location().line;
                    free_lines.insert(var_name.clone(), line);
                }
            }
        }
        EntityKind::DeclRefExpr => {
            if let Some(var_name) = entity.get_name() {
                if let Some(free_line) = free_lines.get(&var_name) {
                    if let Some(location) = entity.get_location() {
                        let line = location.get_spelling_location().line;
                        if line > *free_line {
                            results.push((var_name, line));
                        }
                    }
                }
            }
        }
        _ => {}
    }
} */

/* Function to detect use-after-free vulnerabilities
pub(crate) fn detect_use_after_free(
    entity: &Entity,
    free_lines: &mut HashMap<String, u32>,
    results: &mut Vec<(String, u32)>,
) {
    match entity.get_kind() {
        EntityKind::CallExpr => {
            handle_free_or_delete(entity, free_lines);
        }

        /*
        // TODO: Add lifetime tracking such that we can accurately not match patterns like;
        ```C++
        #include <cstdio>
        #include <cstdlib>

        int main() {
            void* p = malloc(20);
            free(p);
            p = malloc(12);
            *(int*)p = 123;
            return 0;
        }

        ```

        */
        EntityKind::DeclRefExpr => match entity.get_name() {
            Some(var_name) => {
                if let Some(free_line) = free_lines.get(&var_name) {
                    if let Some(location) = entity.get_location() {
                        let line = location.get_spelling_location().line;
                        if line > *free_line {
                            results.push((var_name, line));
                        }
                    }
                }
            }
            None => {}
        },
        _ => {}
    }
}

pub(crate) fn detect_use_after_free(
    entity: &Entity,
    free_lines: &mut HashMap<String, u32>,
    results: &mut Vec<(String, u32)>,
) {
    match entity.get_kind() {
        EntityKind::CallExpr => {
            if let Some(var_name) = entity
                .get_arguments()
                .as_ref() // work with references to keep the borrow checker happy!
                .and_then(|args| args.first())
                .and_then(|arg| arg.get_name())
            {
                match entity.get_name().as_deref() {
                    Some("free") => {
                        // Handle free() function
                        if let Some(location) = entity.get_location() {
                            let line = location.get_spelling_location().line;
                            free_lines.insert(var_name.clone(), line);
                        }
                    }
                    Some("malloc") | Some("calloc") | Some("realloc") => {
                        // Handle C-style allocations (malloc, calloc, realloc)
                        free_lines.remove(&var_name);
                    }
                    _ => {}
                }
            }
        }
        EntityKind::NewExpr => {
            // Handle C++ new allocation
            if let Some(var_name) = entity.get_name() {
                free_lines.remove(&var_name);
            }
        }
        EntityKind::DeleteExpr => {
            // Handle C++ delete deallocation
            if let Some(var_name) = entity
                .get_children()
                .first()
                .and_then(|child| child.get_name())
            {
                if let Some(location) = entity.get_location() {
                    let line = location.get_spelling_location().line;
                    free_lines.insert(var_name.clone(), line);
                }
            }
        }
        EntityKind::DeclRefExpr => {
            // Handle variable references after free
            if let Some(var_name) = entity.get_name() {
                if let Some(free_line) = free_lines.get(&var_name) {
                    if let Some(location) = entity.get_location() {
                        let line = location.get_spelling_location().line;
                        if line > *free_line {
                            results.push((var_name, line));
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn detect_use_after_free(
    entity: &Entity,
    free_lines: &mut HashMap<String, u32>,
    results: &mut Vec<(String, u32)>,
) {
    match entity.get_kind() {
        EntityKind::CallExpr => {
            if let Some(called_function) = entity.get_name() {
                if let Some(result_type) = entity.get_type() {
                    if result_type.get_kind() == TypeKind::Pointer {
                        // Check if the result of the function call is assigned to a variable
                        if let Some(parent) = entity.get_lexical_parent() {
                            if let EntityKind::VarDecl | EntityKind::DeclRefExpr = parent.get_kind()
                            {
                                if let Some(var_name) = parent.get_name() {
                                    free_lines.remove(&var_name); // Reset free status
                                }
                            }
                        }
                    }
                } else if called_function == "free" {
                    if let Some(var_name) = entity
                        .get_arguments()
                        .as_ref()
                        .and_then(|args| args.first())
                        .and_then(|arg| arg.get_name())
                    {
                        if let Some(location) = entity.get_location() {
                            let line = location.get_spelling_location().line;
                            free_lines.insert(var_name.clone(), line);
                        }
                    }
                }
            }
        }
        EntityKind::NewExpr => {
            if let Some(var_name) = entity.get_name() {
                free_lines.remove(&var_name);
            }
        }
        EntityKind::DeleteExpr => {
            if let Some(var_name) = entity
                .get_children()
                .first()
                .and_then(|child| child.get_name())
            {
                if let Some(location) = entity.get_location() {
                    let line = location.get_spelling_location().line;
                    free_lines.insert(var_name.clone(), line);
                }
            }
        }
        EntityKind::DeclRefExpr => {
            if let Some(var_name) = entity.get_name() {
                if let Some(free_line) = free_lines.get(&var_name) {
                    if let Some(location) = entity.get_location() {
                        let line = location.get_spelling_location().line;
                        if line > *free_line {
                            results.push((var_name, line));
                        }
                    }
                }
            }
        }
        _ => {}
    }
}
*/
// Work in progress Function to detect double-free vulnerabilities
fn detect_double_free(
    entity: &Entity,
    free_lines: &mut HashMap<String, u32>,
    results: &mut Vec<(String, u32)>,
) {
    match entity.get_kind() {
        EntityKind::CallExpr => {
            if let Some(var_name) = handle_free_or_delete(entity, free_lines) {
                if free_lines.contains_key(&var_name) {
                    if let Some(location) = entity.get_location() {
                        let line = location.get_spelling_location().line;
                        results.push((var_name, line));
                    }
                }
            }
        }
        _ => {}
    }
}

// Work in progress Function to detect type confusion vulnerabilities
fn detect_type_confusion(
    entity: &Entity,
    _: &mut HashMap<String, u32>,
    results: &mut Vec<(String, u32)>,
) {
    match entity.get_kind() {
        EntityKind::CStyleCastExpr => {
            if let Some(sub_entity) = entity.get_children().first() {
                match (sub_entity.get_type(), entity.get_type()) {
                    (Some(original_type), Some(cast_type)) => {
                        if original_type.get_kind() != cast_type.get_kind() {
                            if let Some(var_name) = sub_entity.get_name() {
                                if let Some(location) = entity.get_location() {
                                    let line = location.get_spelling_location().line;
                                    results.push((var_name, line));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

// Helper function to handle free/delete operations
fn handle_free_or_delete(entity: &Entity, free_lines: &mut HashMap<String, u32>) -> Option<String> {
    match entity.get_name() {
        Some(spelling) => {
            if spelling == "free" || spelling == "delete" {
                match entity
                    .get_arguments()
                    .as_ref() // to comply with rust's memory management rules!
                    .and_then(|args| args.first())
                {
                    Some(arg) => match arg.get_name() {
                        Some(var_name) => {
                            if let Some(location) = entity.get_location() {
                                let line = location.get_spelling_location().line;
                                free_lines.insert(var_name.clone(), line);
                                return Some(var_name);
                            }
                        }
                        None => {}
                    },
                    None => {
                        if spelling == "delete" {
                            if let Some(child) = entity.get_children().first() {
                                match child.get_name() {
                                    Some(var_name) => {
                                        if let Some(location) = entity.get_location() {
                                            let line = location.get_spelling_location().line;
                                            free_lines.insert(var_name.clone(), line);
                                            return Some(var_name);
                                        }
                                    }
                                    None => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        None => {}
    }
    None
}

/*

// Helper function to handle free/delete operations
fn handle_free_or_delete(entity: &Entity, free_lines: &mut HashMap<String, u32>) -> Option<String> {
    match entity.get_name() {
        Some(spelling) => {
            if spelling == "free" || spelling == "delete" {
                match entity
                    .get_arguments()
                    .as_ref() // make the borrowchecker happy
                    .and_then(|args| args.first())
                {
                    Some(arg) => match arg.get_name() {
                        Some(var_name) => {
                            if let Some(location) = entity.get_location() {
                                let line = location.get_spelling_location().line;
                                free_lines.insert(var_name.clone(), line);
                                return Some(var_name);
                            }
                        }
                        None => {}
                    },
                    None => {
                        if spelling == "delete" {
                            if let Some(child) = entity.get_children().first() {
                                match child.get_name() {
                                    Some(var_name) => {
                                        if let Some(location) = entity.get_location() {
                                            let line = location.get_spelling_location().line;
                                            free_lines.insert(var_name.clone(), line);
                                            return Some(var_name);
                                        }
                                    }
                                    None => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        None => {}
    }
    None
}
*/
