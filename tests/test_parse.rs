use std::fs;
use std::io;
use std::path::Path;
use std::str::FromStr;

use security_txt::Line;

#[test]
fn parse() -> io::Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files");
    let mut haserror = false;
    for entry in dir.read_dir()? {
        let file = entry?.path();
        let data = fs::read_to_string(&file)?;

        for (i, line) in data.lines().enumerate() {
            if let Err(e) = Line::from_str(line) {
                haserror = true;
                println!("Errored in {}, line {}: {}", file.display(), i, e);
            }
        }
    }
    if haserror {
        panic!("Errored");
    }
    Ok(())
}
