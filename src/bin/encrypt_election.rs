//! Tool for generating encrypted election records for testing.  Reads a JSON-encoded
//! `generate::Election` from stdin, encrypts it, and writes a JSON-encoded `schema::Record` to
//! stdout.

use serde_json::{from_reader, to_writer_pretty};
use std::io;
use rand::thread_rng;

use electionguard_verify::generate;

fn main() {
    let input = from_reader::<_, generate::Election>(io::stdin()).unwrap();
    let enc = generate::generate(&mut thread_rng(), input);
    to_writer_pretty(io::stdout(), &enc).unwrap();
}
