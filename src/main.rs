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

/// CLI usage help text.
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

/// Parsed command-line arguments.
struct Args {
    path: PathBuf,
    mode: CheckMode,
    verbose: bool,
    strict: bool,
    exclude: Vec<String>,
    check_private: bool,
}

impl Args {
    /// Parses command-line arguments from `env::args()`.
    ///
    /// # Returns
    ///
    /// The parsed arguments.
    ///
    /// # Errors
    ///
    /// Returns an error if arguments are invalid or missing.
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

/// What kind of documentation issues to check for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckMode {
    /// Only check for missing documentation.
    Docs,
    /// Only check for lazy/incomplete documentation.
    Lazy,
    /// Check for both missing and lazy documentation.
    Both,
}

/// A documentation issue found during checking.
#[derive(Debug, Clone)]
struct Issue {
    name: String,
    line: usize,
    issue_type: IssueType,
    detail: String,
}

/// Categories of documentation issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum IssueType {
    /// Item has no documentation at all.
    MissingDoc,
    /// Function docs lack `# Arguments` section.
    MissingArguments,
    /// Function docs lack `# Returns` section.
    MissingReturns,
    /// Function docs lack `# Errors` section.
    MissingErrors,
    /// Function docs lack `# Panics` section.
    MissingPanics,
    /// Unsafe function docs lack `# Safety` section.
    MissingSafety,
}

impl IssueType {
    /// Returns the short string identifier for this issue type.
    ///
    /// # Returns
    ///
    /// A static string like `"missing_doc"` or `"missing_args"`.
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

/// Results from checking a single file.
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
    /// Parses a doc comment string to detect which sections are present.
    ///
    /// # Returns
    ///
    /// A `DocSections` with flags set for detected sections.
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
    /// Creates a new panic detector with no panics found yet.
    ///
    /// # Returns
    ///
    /// A fresh `PanicDetector` instance.
    fn new() -> Self {
        Self { found_panic: false }
    }
}

impl<'ast> Visit<'ast> for PanicDetector {
    /// Checks macros for panic-prone invocations like `panic!`, `assert!`, etc.
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

    /// Checks method calls for `unwrap()` and `expect()`.
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(method.as_str(), "unwrap" | "expect") {
            self.found_panic = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    /// Flags array/slice indexing which can panic on out-of-bounds.
    fn visit_expr_index(&mut self, node: &'ast syn::ExprIndex) {
        self.found_panic = true;
        syn::visit::visit_expr_index(self, node);
    }

    /// Flags division and modulo which can panic on zero divisor.
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::Div(_) | syn::BinOp::Rem(_)) {
            self.found_panic = true;
        }
        syn::visit::visit_expr_binary(self, node);
    }
}

/// Checks if a function body contains panic-prone patterns.
///
/// # Returns
///
/// `true` if any panic-prone patterns are detected.
fn can_panic(body: &Block) -> bool {
    let mut detector = PanicDetector::new();
    detector.visit_block(body);
    detector.found_panic
}

/// Extracts the doc comment string from a list of attributes.
///
/// # Returns
///
/// The combined doc comment text, or `None` if no doc comments exist.
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

/// Checks if an item should be checked based on its visibility.
///
/// # Arguments
///
/// * `vis` - The visibility of the item.
/// * `check_private` - Whether to check private items.
///
/// # Returns
///
/// `true` if the item should be checked.
fn is_checkable(vis: &Visibility, check_private: bool) -> bool {
    if check_private {
        return true;
    }
    match vis {
        Visibility::Inherited => false,
        Visibility::Restricted(r) => !r.path.is_ident("self"),
        _ => true,
    }
}

/// Counts real parameters (excluding `self`).
///
/// # Returns
///
/// The number of non-self parameters.
fn count_params(sig: &Signature) -> usize {
    sig.inputs
        .iter()
        .filter(|arg| !matches!(arg, FnArg::Receiver(_)))
        .count()
}

/// Gets parameter names for issue reporting.
///
/// # Returns
///
/// A list of parameter names.
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

/// Checks if function returns something other than unit.
///
/// # Returns
///
/// `true` if the function has an explicit return type.
fn has_return_value(sig: &Signature) -> bool {
    !matches!(sig.output, ReturnType::Default)
}

/// Checks if function returns a `Result` type.
///
/// # Returns
///
/// `true` if the return type is `Result`.
fn returns_result(sig: &Signature) -> bool {
    if let ReturnType::Type(_, ty) = &sig.output {
        return type_is_result(ty);
    }
    false
}

/// Recursively checks if a type is `Result`.
///
/// # Returns
///
/// `true` if the type is or contains `Result`.
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

/// Checks if function is `unsafe`.
///
/// # Returns
///
/// `true` if the function is marked `unsafe`.
fn is_unsafe(sig: &Signature) -> bool {
    sig.unsafety.is_some()
}

/// AST visitor that checks documentation on Rust items.
struct DocChecker {
    mode: CheckMode,
    check_private: bool,
    issues: Vec<Issue>,
    context_stack: Vec<String>,
}

impl DocChecker {
    /// Creates a new doc checker with the specified mode and visibility settings.
    ///
    /// # Arguments
    ///
    /// * `mode` - What kind of issues to check for.
    /// * `check_private` - Whether to check private items.
    ///
    /// # Returns
    ///
    /// A new `DocChecker` instance.
    fn new(mode: CheckMode, check_private: bool) -> Self {
        Self {
            mode,
            check_private,
            issues: Vec::new(),
            context_stack: Vec::new(),
        }
    }

    /// Builds a qualified name using the current context stack.
    ///
    /// # Returns
    ///
    /// The fully qualified name (e.g., `"Foo::bar::method"`).
    fn qualified_name(&self, name: &str) -> String {
        if self.context_stack.is_empty() {
            name.to_string()
        } else {
            format!("{}::{}", self.context_stack.join("::"), name)
        }
    }

    /// Checks if we should look for missing documentation.
    ///
    /// # Returns
    ///
    /// `true` if mode is `Docs` or `Both`.
    fn should_check_missing(&self) -> bool {
        matches!(self.mode, CheckMode::Docs | CheckMode::Both)
    }

    /// Checks if we should look for lazy documentation.
    ///
    /// # Returns
    ///
    /// `true` if mode is `Lazy` or `Both`.
    fn should_check_lazy(&self) -> bool {
        matches!(self.mode, CheckMode::Lazy | CheckMode::Both)
    }

    /// Records an issue found during checking.
    ///
    /// # Arguments
    ///
    /// * `name` - The qualified name of the item with the issue.
    /// * `line` - The line number where the issue was found.
    /// * `issue_type` - The category of issue.
    /// * `detail` - A human-readable description of the issue.
    fn add_issue(&mut self, name: String, line: usize, issue_type: IssueType, detail: String) {
        self.issues.push(Issue {
            name,
            line,
            issue_type,
            detail,
        });
    }

    /// Checks a function for documentation issues.
    ///
    /// # Arguments
    ///
    /// * `sig` - The function signature.
    /// * `attrs` - The function's attributes (including doc comments).
    /// * `vis` - The visibility, or `None` for trait methods.
    /// * `body` - The function body for panic detection, if available.
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

    /// Checks a non-function item for missing documentation.
    ///
    /// # Arguments
    ///
    /// * `name` - The item's identifier.
    /// * `attrs` - The item's attributes.
    /// * `vis` - The item's visibility.
    /// * `line` - The line number of the item.
    /// * `kind` - A description of the item type (e.g., "struct", "enum").
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
    /// Visits a free function and checks its documentation.
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.check_function(&node.sig, &node.attrs, Some(&node.vis), Some(&node.block));
        syn::visit::visit_item_fn(self, node);
    }

    /// Visits a struct and checks its documentation.
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

    /// Visits an enum and checks its documentation.
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

    /// Visits a trait and checks its documentation.
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

    /// Visits a trait item (method) and checks its documentation.
    fn visit_trait_item(&mut self, node: &'ast TraitItem) {
        if let TraitItem::Fn(method) = node {
            // Trait methods are implicitly public if trait is public
            // For default implementations, pass the body for panic detection
            self.check_function(&method.sig, &method.attrs, None, method.default.as_ref());
        }
        syn::visit::visit_trait_item(self, node);
    }

    /// Visits an impl block and sets up context for nested items.
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

    /// Visits an impl method and checks its documentation.
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.check_function(&node.sig, &node.attrs, Some(&node.vis), Some(&node.block));
        syn::visit::visit_impl_item_fn(self, node);
    }

    /// Visits a module and checks its documentation.
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

    /// Visits a type alias and checks its documentation.
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

    /// Visits a const and checks its documentation.
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

    /// Visits a static and checks its documentation.
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

/// Parses and checks a single Rust file for documentation issues.
///
/// # Arguments
///
/// * `path` - Path to the Rust file.
/// * `mode` - What kind of issues to check for.
/// * `check_private` - Whether to check private items.
///
/// # Returns
///
/// A `FileResult` containing any issues found.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
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

/// Recursively finds all `.rs` files under a directory, respecting exclusions.
///
/// # Arguments
///
/// * `root` - The root path (file or directory) to search.
/// * `exclude` - Directory names to skip.
///
/// # Returns
///
/// A list of paths to Rust source files.
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

/// Formats check results into a human-readable report string.
///
/// # Arguments
///
/// * `results` - The check results from all files.
/// * `base` - Base path for displaying relative paths.
/// * `verbose` - Whether to show files without issues.
///
/// # Returns
///
/// A formatted report string ready for printing.
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

/// Entry point: parses args, finds files, checks documentation, and reports results.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns an error if argument parsing or file operations fail.
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
