use serde_json::from_reader;
use std::{
    error::Error,
    fs,
    io::{Cursor, Read},
};

use electionguard_verify::schema;

#[test]
fn test_parsing() -> Result<(), Box<dyn Error>> {
    for file in fs::read_dir("tests/records/")? {
        let file = file?;
        if let Some(ext) = file.path().extension() {
            if ext == "json" {
                let input = fs::read_to_string(file.path())?;
                let mut reader = Cursor::new(input);
                from_reader::<_, schema::Record>(reader.by_ref())
                    .expect(&format!("{:#?} should parse", file.file_name()));
            }
        }
    }

    Ok(())
}
