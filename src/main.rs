use serde_json::from_reader;
use std::fs::File;
use std::io::{self, stdin, BufReader};
use structopt::StructOpt;

use electionguard_verify::election;

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

fn run() -> Result<election::Status, Error> {
    let opt = Options::from_args();

    let input: election::Record = match opt.input {
        None => from_reader(BufReader::new(stdin()))?,
        Some(path) => from_reader(BufReader::new(File::open(path)?))?,
    };

    Ok(input.check())
}

const EXIT_SUCCESS: i32 = 0;
const EXIT_FAILURE: i32 = 1;
const EXIT_IO_ERROR: i32 = 74; // EX_IOERR
const EXIT_PARSE_ERROR: i32 = 65; // EX_DATAERR

fn main() {
    match run() {
        Ok(status) => {
            if status.is_ok() {
                std::process::exit(EXIT_SUCCESS)
            } else {
                eprintln!("{:?}", status);
                std::process::exit(EXIT_FAILURE)
            }
        }
        Err(Error::IO(e)) => {
            eprintln!("{}", e);
            std::process::exit(EXIT_IO_ERROR)
        }
        Err(Error::JSON(e)) => {
            eprintln!("{}", e);
            std::process::exit(EXIT_PARSE_ERROR)
        }
    }
}
