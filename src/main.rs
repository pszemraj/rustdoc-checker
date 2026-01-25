//! CLI tool to check Rust files for missing/lazy documentation.
//!
//! Designed for enforcing documentation standards on LLM-generated code.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::{
    Attribute, Block, FnArg, ItemConst, ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStatic,
    ItemStruct, ItemTrait, ItemType, Pat, ReturnType, Signature, TraitItem, Type, Visibility,
};
use walkdir::WalkDir;

const USAGE: &str = "\
rustdoc-checker - Check Rust files for missing/lazy documentation

USAGE:
    rustdoc-checker <PATH> [OPTIONS]

ARGS:
    <PATH>    Directory or file to check

OPTIONS:
    -m, --mode <MODE>    What to check: docs, lazy, both [default: both]
    -v, --verbose        Show files without issues
    --strict             Exit with code 1 if any issues found
    --exclude <DIRS>     Comma-separated directory names to exclude
    --check-private      Also check private items (not just pub)
    -h, --help           Print help
";

struct Args {
    path: PathBuf,
    mode: CheckMode,
    verbose: bool,
    strict: bool,
    exclude: Vec<String>,
    check_private: bool,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut args = env::args().skip(1).peekable();

        let mut path: Option<PathBuf> = None;
        let mut mode = CheckMode::Both;
        let mut verbose = false;
        let mut strict = false;
        let mut exclude = Vec::new();
        let mut check_private = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print!("{}", USAGE);
                    std::process::exit(0);
                }
                "-v" | "--verbose" => verbose = true,
                "--strict" => strict = true,
                "--check-private" => check_private = true,
                "-m" | "--mode" => {
                    let val = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--mode requires a value"))?;
                    mode = match val.as_str() {
                        "docs" => CheckMode::Docs,
                        "lazy" => CheckMode::Lazy,
                        "both" => CheckMode::Both,
                        _ => bail!("Invalid mode '{}'. Use: docs, lazy, both", val),
                    };
                }
                "--exclude" => {
                    let val = args
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--exclude requires a value"))?;
                    exclude = val.split(',').map(|s| s.trim().to_string()).collect();
                }
                s if s.starts_with('-') => bail!("Unknown option: {}", s),
                _ => {
                    if path.is_some() {
                        bail!("Multiple paths provided. Only one path supported.");
                    }
                    path = Some(PathBuf::from(arg));
                }
            }
        }

        let path =
            path.ok_or_else(|| anyhow::anyhow!("Missing required argument: <PATH>\n\n{}", USAGE))?;

        Ok(Self {
            path,
            mode,
            verbose,
            strict,
            exclude,
            check_private,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckMode {
    Docs,
    Lazy,
    Both,
}

#[derive(Debug, Clone)]
struct Issue {
    name: String,
    line: usize,
    issue_type: IssueType,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IssueType {
    MissingDoc,
    MissingArguments,
    MissingReturns,
    MissingErrors,
    MissingPanics,
    MissingSafety,
}

impl IssueType {
    fn as_str(&self) -> &'static str {
        match self {
            IssueType::MissingDoc => "missing_doc",
            IssueType::MissingArguments => "missing_args",
            IssueType::MissingReturns => "missing_returns",
            IssueType::MissingErrors => "missing_errors",
            IssueType::MissingPanics => "missing_panics",
            IssueType::MissingSafety => "missing_safety",
        }
    }
}

#[derive(Debug, Default)]
struct FileResult {
    filepath: PathBuf,
    issues: Vec<Issue>,
}

/// Parsed documentation sections.
#[derive(Debug, Default)]
struct DocSections {
    has_arguments: bool,
    has_returns: bool,
    has_errors: bool,
    has_panics: bool,
    has_safety: bool,
}

impl DocSections {
    fn parse(doc: &str) -> Self {
        let lower = doc.to_lowercase();
        Self {
            // Check for common section headers (# Arguments, # Parameters, ## Args, etc.)
            has_arguments: lower.contains("# argument")
                || lower.contains("# parameter")
                || lower.contains("# args")
                || lower.contains("# params"),
            has_returns: lower.contains("# return") || lower.contains("# yield"),
            has_errors: lower.contains("# error"),
            has_panics: lower.contains("# panic"),
            has_safety: lower.contains("# safety"),
        }
    }
}

/// Visitor to detect panic-prone patterns in function bodies.
struct PanicDetector {
    found_panic: bool,
}

impl PanicDetector {
    fn new() -> Self {
        Self { found_panic: false }
    }
}

impl<'ast> Visit<'ast> for PanicDetector {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(ident) = node.path.get_ident() {
            let name = ident.to_string();
            if matches!(
                name.as_str(),
                "panic"
                    | "unreachable"
                    | "todo"
                    | "unimplemented"
                    | "assert"
                    | "assert_eq"
                    | "assert_ne"
                    | "debug_assert"
                    | "debug_assert_eq"
                    | "debug_assert_ne"
            ) {
                self.found_panic = true;
            }
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(method.as_str(), "unwrap" | "expect") {
            self.found_panic = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast syn::ExprIndex) {
        // Array/slice indexing can panic on out-of-bounds
        self.found_panic = true;
        syn::visit::visit_expr_index(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        // Integer division and modulo can panic on division by zero
        if matches!(node.op, syn::BinOp::Div(_) | syn::BinOp::Rem(_)) {
            self.found_panic = true;
        }
        syn::visit::visit_expr_binary(self, node);
    }
}

/// Check if a function body contains panic-prone patterns.
fn can_panic(body: &Block) -> bool {
    let mut detector = PanicDetector::new();
    detector.visit_block(body);
    detector.found_panic
}

/// Extract doc comment from attributes.
fn extract_doc(attrs: &[Attribute]) -> Option<String> {
    let docs: Vec<String> = attrs
        .iter()
        .filter_map(|attr| {
            if attr.path().is_ident("doc") {
                if let syn::Meta::NameValue(nv) = &attr.meta {
                    if let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(s),
                        ..
                    }) = &nv.value
                    {
                        return Some(s.value());
                    }
                }
            }
            None
        })
        .collect();

    if docs.is_empty() {
        None
    } else {
        Some(docs.join("\n"))
    }
}

/// Check if visibility is public (or we're checking private items).
fn is_checkable(vis: &Visibility, check_private: bool) -> bool {
    if check_private {
        return true;
    }
    matches!(vis, Visibility::Public(_))
}

/// Count real parameters (excluding self).
fn count_params(sig: &Signature) -> usize {
    sig.inputs
        .iter()
        .filter(|arg| !matches!(arg, FnArg::Receiver(_)))
        .count()
}

/// Get parameter names for reporting.
fn get_param_names(sig: &Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(pat_type) = arg {
                if let Pat::Ident(ident) = &*pat_type.pat {
                    return Some(ident.ident.to_string());
                }
            }
            None
        })
        .collect()
}

/// Check if function returns something (not unit).
fn has_return_value(sig: &Signature) -> bool {
    !matches!(sig.output, ReturnType::Default)
}

/// Check if function returns Result.
fn returns_result(sig: &Signature) -> bool {
    if let ReturnType::Type(_, ty) = &sig.output {
        return type_is_result(ty);
    }
    false
}

/// Recursively check if a type is Result.
fn type_is_result(ty: &Type) -> bool {
    match ty {
        Type::Path(type_path) => {
            if let Some(segment) = type_path.path.segments.last() {
                let name = segment.ident.to_string();
                return name == "Result" || name.ends_with("Result");
            }
            false
        }
        Type::Group(group) => type_is_result(&group.elem),
        Type::Paren(paren) => type_is_result(&paren.elem),
        _ => false,
    }
}

/// Check if function is unsafe.
fn is_unsafe(sig: &Signature) -> bool {
    sig.unsafety.is_some()
}

struct DocChecker {
    mode: CheckMode,
    check_private: bool,
    issues: Vec<Issue>,
    context_stack: Vec<String>,
}

impl DocChecker {
    fn new(mode: CheckMode, check_private: bool) -> Self {
        Self {
            mode,
            check_private,
            issues: Vec::new(),
            context_stack: Vec::new(),
        }
    }

    fn qualified_name(&self, name: &str) -> String {
        if self.context_stack.is_empty() {
            name.to_string()
        } else {
            format!("{}::{}", self.context_stack.join("::"), name)
        }
    }

    fn should_check_missing(&self) -> bool {
        matches!(self.mode, CheckMode::Docs | CheckMode::Both)
    }

    fn should_check_lazy(&self) -> bool {
        matches!(self.mode, CheckMode::Lazy | CheckMode::Both)
    }

    fn add_issue(&mut self, name: String, line: usize, issue_type: IssueType, detail: String) {
        self.issues.push(Issue {
            name,
            line,
            issue_type,
            detail,
        });
    }

    fn check_function(
        &mut self,
        sig: &Signature,
        attrs: &[Attribute],
        vis: Option<&Visibility>,
        body: Option<&Block>,
    ) {
        let name = self.qualified_name(&sig.ident.to_string());
        let line = sig.ident.span().start().line;

        // Skip if not checkable visibility
        if let Some(v) = vis {
            if !is_checkable(v, self.check_private) {
                return;
            }
        }

        let doc = extract_doc(attrs);

        // Check for missing doc
        if self.should_check_missing() && doc.is_none() {
            self.add_issue(
                name.clone(),
                line,
                IssueType::MissingDoc,
                "Missing documentation".to_string(),
            );
            return; // No point checking lazy if no doc exists
        }

        // Check for lazy doc
        if self.should_check_lazy() {
            if let Some(ref doc_text) = doc {
                let sections = DocSections::parse(doc_text);
                let param_count = count_params(sig);

                // Check Arguments section (require if 2+ params)
                if param_count >= 2 && !sections.has_arguments {
                    let params = get_param_names(sig);
                    self.add_issue(
                        name.clone(),
                        line,
                        IssueType::MissingArguments,
                        format!(
                            "Has {} params ({}) but no # Arguments section",
                            param_count,
                            params.join(", ")
                        ),
                    );
                }

                // Check Returns section
                if has_return_value(sig) && !sections.has_returns {
                    self.add_issue(
                        name.clone(),
                        line,
                        IssueType::MissingReturns,
                        "Returns value but no # Returns section".to_string(),
                    );
                }

                // Check Errors section (for Result returns)
                if returns_result(sig) && !sections.has_errors {
                    self.add_issue(
                        name.clone(),
                        line,
                        IssueType::MissingErrors,
                        "Returns Result but no # Errors section".to_string(),
                    );
                }

                // Check Safety section (for unsafe fns)
                if is_unsafe(sig) && !sections.has_safety {
                    self.add_issue(
                        name.clone(),
                        line,
                        IssueType::MissingSafety,
                        "Unsafe function but no # Safety section".to_string(),
                    );
                }

                // Check Panics section (if function can panic)
                if let Some(block) = body {
                    if can_panic(block) && !sections.has_panics {
                        self.add_issue(
                            name.clone(),
                            line,
                            IssueType::MissingPanics,
                            "Function can panic but no # Panics section".to_string(),
                        );
                    }
                }
            }
        }
    }

    fn check_item_doc(
        &mut self,
        name: &str,
        attrs: &[Attribute],
        vis: &Visibility,
        line: usize,
        kind: &str,
    ) {
        if !is_checkable(vis, self.check_private) {
            return;
        }

        if self.should_check_missing() && extract_doc(attrs).is_none() {
            let qname = self.qualified_name(name);
            self.add_issue(
                qname,
                line,
                IssueType::MissingDoc,
                format!("Missing {} documentation", kind),
            );
        }
    }
}

impl<'ast> Visit<'ast> for DocChecker {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.check_function(&node.sig, &node.attrs, Some(&node.vis), Some(&node.block));
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        let line = node.ident.span().start().line;
        self.check_item_doc(
            &node.ident.to_string(),
            &node.attrs,
            &node.vis,
            line,
            "struct",
        );

        self.context_stack.push(node.ident.to_string());
        syn::visit::visit_item_struct(self, node);
        self.context_stack.pop();
    }

    fn visit_item_enum(&mut self, node: &'ast ItemEnum) {
        let line = node.ident.span().start().line;
        self.check_item_doc(
            &node.ident.to_string(),
            &node.attrs,
            &node.vis,
            line,
            "enum",
        );

        self.context_stack.push(node.ident.to_string());
        syn::visit::visit_item_enum(self, node);
        self.context_stack.pop();
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        let line = node.ident.span().start().line;
        self.check_item_doc(
            &node.ident.to_string(),
            &node.attrs,
            &node.vis,
            line,
            "trait",
        );

        self.context_stack.push(node.ident.to_string());
        syn::visit::visit_item_trait(self, node);
        self.context_stack.pop();
    }

    fn visit_trait_item(&mut self, node: &'ast TraitItem) {
        if let TraitItem::Fn(method) = node {
            // Trait methods are implicitly public if trait is public
            // For default implementations, pass the body for panic detection
            self.check_function(&method.sig, &method.attrs, None, method.default.as_ref());
        }
        syn::visit::visit_trait_item(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        // Get impl target name for context
        let impl_name = if let Some((_, path, _)) = &node.trait_ {
            // impl Trait for Type
            if let Some(seg) = path.segments.last() {
                format!("<impl {}>", seg.ident)
            } else {
                "<impl>".to_string()
            }
        } else {
            // impl Type
            match &*node.self_ty {
                Type::Path(p) => {
                    if let Some(seg) = p.path.segments.last() {
                        seg.ident.to_string()
                    } else {
                        "<impl>".to_string()
                    }
                }
                _ => "<impl>".to_string(),
            }
        };

        self.context_stack.push(impl_name);
        syn::visit::visit_item_impl(self, node);
        self.context_stack.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.check_function(&node.sig, &node.attrs, Some(&node.vis), Some(&node.block));
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let line = node.ident.span().start().line;
        self.check_item_doc(
            &node.ident.to_string(),
            &node.attrs,
            &node.vis,
            line,
            "module",
        );

        self.context_stack.push(node.ident.to_string());
        syn::visit::visit_item_mod(self, node);
        self.context_stack.pop();
    }

    fn visit_item_type(&mut self, node: &'ast ItemType) {
        let line = node.ident.span().start().line;
        self.check_item_doc(
            &node.ident.to_string(),
            &node.attrs,
            &node.vis,
            line,
            "type alias",
        );
        syn::visit::visit_item_type(self, node);
    }

    fn visit_item_const(&mut self, node: &'ast ItemConst) {
        let line = node.ident.span().start().line;
        self.check_item_doc(
            &node.ident.to_string(),
            &node.attrs,
            &node.vis,
            line,
            "const",
        );
        syn::visit::visit_item_const(self, node);
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        let line = node.ident.span().start().line;
        self.check_item_doc(
            &node.ident.to_string(),
            &node.attrs,
            &node.vis,
            line,
            "static",
        );
        syn::visit::visit_item_static(self, node);
    }
}

fn check_file(path: &Path, mode: CheckMode, check_private: bool) -> Result<FileResult> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let mut result = FileResult {
        filepath: path.to_path_buf(),
        issues: Vec::new(),
    };

    let file = match syn::parse_file(&content) {
        Ok(f) => f,
        Err(e) => {
            result.issues.push(Issue {
                name: "<parse>".to_string(),
                line: e.span().start().line,
                issue_type: IssueType::MissingDoc, // Reuse for parse errors
                detail: format!("Parse error: {}", e),
            });
            return Ok(result);
        }
    };

    // Check module-level doc
    if matches!(mode, CheckMode::Docs | CheckMode::Both) {
        if extract_doc(&file.attrs).is_none() {
            result.issues.push(Issue {
                name: "<module>".to_string(),
                line: 1,
                issue_type: IssueType::MissingDoc,
                detail: "Missing module-level documentation (//! comment)".to_string(),
            });
        }
    }

    let mut checker = DocChecker::new(mode, check_private);
    checker.visit_file(&file);
    result.issues.extend(checker.issues);

    // Sort for deterministic output
    result.issues.sort_by(|a, b| a.line.cmp(&b.line));

    Ok(result)
}

fn find_rust_files(root: &Path, exclude: &[String]) -> Vec<PathBuf> {
    let skip_dirs: std::collections::HashSet<&str> = ["target", ".git", "node_modules", ".cargo"]
        .into_iter()
        .chain(exclude.iter().map(|s| s.as_str()))
        .collect();

    if root.is_file() {
        return if root.extension().is_some_and(|e| e == "rs") {
            vec![root.to_path_buf()]
        } else {
            vec![]
        };
    }

    WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !skip_dirs.contains(name.as_ref())
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "rs"))
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn format_results(results: &[FileResult], base: &Path, verbose: bool) -> String {
    let mut lines = Vec::new();
    let mut total_issues = 0;
    let mut files_with_issues = 0;
    let mut by_type: HashMap<IssueType, usize> = HashMap::new();

    for result in results {
        let display_path = result
            .filepath
            .strip_prefix(base)
            .unwrap_or(&result.filepath);

        if result.issues.is_empty() {
            if verbose {
                lines.push(format!("[OK] {}", display_path.display()));
            }
            continue;
        }

        files_with_issues += 1;
        lines.push(String::new());
        lines.push(format!("{}", display_path.display()));
        lines.push("-".repeat(display_path.display().to_string().len()));

        for issue in &result.issues {
            total_issues += 1;
            *by_type.entry(issue.issue_type).or_insert(0) += 1;
            lines.push(format!(
                "  L{:4} | {:14} | {}: {}",
                issue.line,
                issue.issue_type.as_str(),
                issue.name,
                issue.detail
            ));
        }
    }

    lines.push(String::new());
    lines.push("=".repeat(60));
    lines.push(format!("Files scanned: {}", results.len()));
    lines.push(format!("Files with issues: {}", files_with_issues));
    lines.push(format!("Total issues: {}", total_issues));

    if !by_type.is_empty() {
        lines.push(String::new());
        lines.push("Breakdown by type:".to_string());
        let mut sorted: Vec<_> = by_type.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        for (issue_type, count) in sorted {
            lines.push(format!("  {:14}: {}", issue_type.as_str(), count));
        }
    }

    lines.join("\n")
}

fn main() -> Result<()> {
    let args = Args::parse()?;

    let target = args
        .path
        .canonicalize()
        .with_context(|| format!("Path does not exist: {}", args.path.display()))?;

    let files = find_rust_files(&target, &args.exclude);

    if files.is_empty() {
        eprintln!("No Rust files found.");
        return Ok(());
    }

    let mut results: Vec<FileResult> = files
        .iter()
        .filter_map(|f| check_file(f, args.mode, args.check_private).ok())
        .collect();

    // Sort by path for deterministic output
    results.sort_by(|a, b| a.filepath.cmp(&b.filepath));

    let base = if target.is_file() {
        target.parent().unwrap_or(&target)
    } else {
        &target
    };

    println!("{}", format_results(&results, base, args.verbose));

    if args.strict {
        let total: usize = results.iter().map(|r| r.issues.len()).sum();
        if total > 0 {
            std::process::exit(1);
        }
    }

    Ok(())
}
