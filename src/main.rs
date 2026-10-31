// The honeypot program. It crashes with "not yet implemented" until you've done
// Stage 2. After that, the README shows how to try it.

use std::fs::{DirBuilder, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use honeypot::login::{TIMEOUT, listen_on_localhost};
use honeypot::visit::serve_and_record;

const PORT: u16 = 2323;
const LOG_DIR: &str = "logs";
const LOG_FILE: &str = "logs/visits.jsonl";

fn main() -> io::Result<()> {
    let listener = listen_on_localhost(PORT)?;

    // Logs hold passwords people try, so only your user account may read them.
    // 0o700 and 0o600 mean the same as `chmod 700` and `chmod 600`.
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(LOG_DIR)?;
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(LOG_FILE)?;

    println!("Fake login listening on {}.", listener.local_addr()?);
    println!("Try it from another terminal: nc 127.0.0.1 {PORT}");
    println!("Press Ctrl+C to stop.");

    // Every visit gets logged, even if the login fails. An error here means a
    // connection couldn't be accepted or the log couldn't be written, and that
    // shouldn't stop the program either, so report it and carry on.
    loop {
        match serve_and_record(&listener, &mut log, TIMEOUT) {
            Ok(visit) => println!("{}", visit.to_json_line()?),
            Err(error) => eprintln!("could not record a visit: {error}"),
        }
    }
}
