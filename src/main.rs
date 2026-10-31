// The honeypot program. It crashes with "not yet implemented" until you've done
// Stage 4. After that, the README shows how to try it.

use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;

use honeypot::log_files::{DailyLog, today};
use honeypot::login::{TIMEOUT, listen_on_localhost};
use honeypot::server::{
    Limits, MAX_CONNECTIONS, MAX_LOG_BYTES_PER_DAY, MAX_PER_IP, Shared, serve_next,
};

const PORT: u16 = 2323;
const LOG_DIR: &str = "logs";

fn main() -> io::Result<()> {
    let listener = listen_on_localhost(PORT)?;

    // This refuses to start if other users could read the logs.
    let log = DailyLog::open(Path::new(LOG_DIR), today())?;
    let limits = Limits::new(MAX_CONNECTIONS, MAX_PER_IP);
    let shared = Shared::new(log, limits, MAX_LOG_BYTES_PER_DAY, TIMEOUT)?;

    println!("Fake login listening on {}.", listener.local_addr()?);
    println!("Try it from another terminal: nc 127.0.0.1 {PORT}");
    println!("Press Ctrl+C to stop.");

    loop {
        // An error here means a connection couldn't be accepted or a thread couldn't
        // start. If the computer has run out of something, this would fail again at once,
        // so wait a moment instead of using all the CPU reporting it.
        if let Err(error) = serve_next(&listener, &shared) {
            eprintln!("could not serve a connection: {error}");
            thread::sleep(Duration::from_millis(100));
        }
    }
}
