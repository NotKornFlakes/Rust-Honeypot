// The honeypot program. It crashes with "not yet implemented" until you've done
// Stage 3. After that, the README shows how to try it.

use std::io;
use std::path::Path;

use honeypot::log_files::{DailyLog, screen_line, today};
use honeypot::login::{TIMEOUT, listen_on_localhost};
use honeypot::visit::serve_and_record;

const PORT: u16 = 2323;
const LOG_DIR: &str = "logs";

fn main() -> io::Result<()> {
    let listener = listen_on_localhost(PORT)?;

    // This refuses to start if other users could read the logs.
    let mut log = DailyLog::open(Path::new(LOG_DIR), today())?;

    println!("Fake login listening on {}.", listener.local_addr()?);
    println!("Try it from another terminal: nc 127.0.0.1 {PORT}");
    println!("Press Ctrl+C to stop.");

    loop {
        // The visit is written to memory first and to the file in one go, so a line
        // can never get split across two days' files.
        let mut line = Vec::new();

        // Every visit gets logged, even if the login fails. An error here means a
        // connection couldn't be accepted or the log couldn't be written, and that
        // shouldn't stop the program either, so report it and carry on.
        match serve_and_record(&listener, &mut line, TIMEOUT) {
            Ok(visit) => {
                if let Err(error) = log.append(today(), &line) {
                    eprintln!("could not write to the log: {error}");
                }
                println!("{}", screen_line(&visit));
            }
            Err(error) => eprintln!("could not record a visit: {error}"),
        }
    }
}
