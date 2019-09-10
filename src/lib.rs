// Many variables have names that mimic the names in the ElectionGuard spec, like `Mil` for
// `M_{i,l}`.  These names don't fit Rust's normal style guidelines.
#![allow(non_snake_case)]

pub mod crypto;
pub mod check;
pub mod schema;
pub mod serialize;
pub mod generate;
pub mod errors;

#[cfg(test)] mod test_gen_check;
