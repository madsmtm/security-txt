use std::fs;
use std::io;
use std::path::Path;

use security_txt;

#[test]
fn parse() -> io::Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/files");
    let mut haserror = false;
    for entry in dir.read_dir()? {
        let file = entry?.path();
        let data = fs::read_to_string(&file)?;

        for (i, field) in security_txt::parse_fields(&data).enumerate() {
            if let Err(e) = field {
                haserror = true;
                println!("Errored in {}, #{}: {}", file.display(), i, e);
            }
        }

        if let Err(e) = security_txt::parse(&data) {
            haserror = true;
            println!("Failed parsing file {}: {}", file.display(), e);
        }
    }

    if haserror {
        panic!("Errored");
    }

    Ok(())
}
