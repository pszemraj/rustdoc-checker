// example_bad.rs - Examples of issues this tool catches
// Run: rustdoc-checker example_bad.rs

// ISSUE: No module-level //! comment

/// This is fine - simple function, one param
pub fn greet(name: &str) -> String {
    format!("Hello, {}", name)
}

// ISSUE: missing_doc - no docstring at all
pub fn undocumented_function(a: i32, b: i32) -> i32 {
    a + b
}

/// Adds numbers together.
// ISSUE: missing_args - has 3 params but no # Arguments section
// ISSUE: missing_returns - returns value but no # Returns section
pub fn add_numbers(a: i32, b: i32, c: i32) -> i32 {
    a + b + c
}

/// Reads a config file.
// ISSUE: missing_args - has 2 params
// ISSUE: missing_returns - returns value
// ISSUE: missing_errors - returns Result but no # Errors section
pub fn read_config(path: &str, validate: bool) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}

/// Does something dangerous.
// ISSUE: missing_safety - unsafe fn but no # Safety section
pub unsafe fn dangerous_operation(ptr: *mut u8) {
    *ptr = 42;
}

/// Well-documented function - no issues.
///
/// # Arguments
///
/// * `x` - The first value
/// * `y` - The second value
///
/// # Returns
///
/// The sum of x and y
pub fn well_documented(x: i32, y: i32) -> i32 {
    x + y
}

/// Well-documented Result function - no issues.
///
/// # Arguments
///
/// * `path` - Path to the file
/// * `create` - Whether to create if missing
///
/// # Returns
///
/// The file contents as a string
///
/// # Errors
///
/// Returns an error if the file cannot be read
pub fn well_documented_result(path: &str, create: bool) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}

/// Well-documented unsafe function - no issues.
///
/// # Safety
///
/// The caller must ensure `ptr` is valid and properly aligned.
pub unsafe fn well_documented_unsafe(ptr: *mut u8) {
    *ptr = 0;
}

// ISSUE: missing_doc - struct without docs
pub struct UndocumentedStruct {
    pub field: i32,
}

/// A documented struct - no issues.
pub struct DocumentedStruct {
    pub field: i32,
}

/// Divides two numbers.
// ISSUE: missing_panics - can panic on division by zero but no # Panics section
pub fn divide(a: i32, b: i32) -> i32 {
    a / b
}

/// Gets an element from a slice.
// ISSUE: missing_panics - uses array indexing which can panic
pub fn get_element(items: &[i32], idx: usize) -> i32 {
    items[idx]
}

/// Unwraps an optional value.
// ISSUE: missing_panics - uses .unwrap() which can panic
pub fn must_have_value(opt: Option<i32>) -> i32 {
    opt.unwrap()
}

/// Asserts a condition before computing.
// ISSUE: missing_panics - uses assert! which can panic
pub fn compute_with_assert(x: i32) -> i32 {
    assert!(x > 0);
    x * 2
}

/// Well-documented function that can panic - no issues.
///
/// # Panics
///
/// Panics if `b` is zero.
pub fn well_documented_divide(a: i32, b: i32) -> i32 {
    a / b
}

/// Well-documented function with unwrap - no issues.
///
/// # Panics
///
/// Panics if the option is `None`.
pub fn well_documented_unwrap(opt: Option<i32>) -> i32 {
    opt.unwrap()
}

// --- Visibility edge cases ---

// ISSUE: missing_doc - pub(crate) should be checked in default mode
pub(crate) fn crate_visible_undocumented() -> bool {
    true
}

// ISSUE: missing_doc - pub(super) should be checked in default mode
pub(super) fn super_visible_undocumented() -> bool {
    true
}

// NO ISSUE: pub(self) is effectively private, skipped in default mode
pub(self) fn self_visible_function() -> bool {
    true
}

// NO ISSUE: truly private (no pub keyword), skipped in default mode
fn private_function() -> bool {
    true
}

/// Documented pub(crate) function - no issues.
pub(crate) fn crate_visible_documented() -> bool {
    true
}
