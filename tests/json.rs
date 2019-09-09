use serde_json::from_reader;
use std::io::Cursor;
use std::io::Read;

use electionguard_verify::schema;

#[test]
fn test_parsing() {
    let input = include_str!("generated.json");
    let mut reader = Cursor::new(input);
    from_reader::<_, schema::Record>(reader.by_ref()).expect("JSON should parse");
}
