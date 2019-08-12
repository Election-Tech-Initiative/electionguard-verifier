use serde_json::from_reader;
use std::fs::File;
use std::io;
use std::io::{stdin, BufReader};
use structopt::StructOpt;

mod ballot;
mod crypto;
mod decryption;
mod election;
mod encrypted;
mod mod_arith;
mod trustee;

#[structopt(
    name = "electionguard_verify",
    about = "Verify the results of an election."
)]
#[derive(StructOpt)]
struct Options {
    /// The path to the JSON file containing the election results.
    /// We read from STDIN if not present.
    #[structopt(parse(from_os_str))]
    #[structopt(short = "i", long = "input")]
    input: Option<std::path::PathBuf>,
}

#[derive(Debug)]
enum Error {
    IO(io::Error),
    JSON(serde_json::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IO(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Error {
        Error::JSON(error)
    }
}

fn main() -> Result<(), Error> {
    let opt = Options::from_args();

    let input: election::Record = match opt.input {
        None => from_reader(BufReader::new(stdin()))?,
        Some(path) => from_reader(BufReader::new(File::open(path)?))?,
    };

    // let errors = input.validate();

    // if errors.is_empty() {
    //     Ok(())
    // } else {
    //     Err(errors.into())
    // }

    Ok(())
}
