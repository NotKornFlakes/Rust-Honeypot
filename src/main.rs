// The honeypot program. It crashes with "not yet implemented" until you've done
// Stage 1. After that, the README shows how to try it.

use std::fs::{DirBuilder, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use honeypot::login::{listen_on_localhost, serve_one};

const PORT: u16 = 2323;
const LOG_DIR: &str = "logs";
const LOG_FILE: &str = "logs/login.log";

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

    // One bad connection shouldn't stop the program, so report errors and carry on.
    loop {
        match serve_one(&listener, &mut log) {
            Ok(attempt) => println!("{attempt}"),
            Err(error) => eprintln!("connection failed: {error}"),
        }
    }
}
