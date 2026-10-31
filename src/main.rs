// The honeypot program. It crashes with "not yet implemented" until you've done
// Stage 5. After that, the README shows how to try it.

// This makes the compiler refuse any `unsafe` code in this file.
#![forbid(unsafe_code)]

use std::env;
use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;

use honeypot::deploy::{
    MAX_TRACKED_ADDRESSES, MAX_VISITS_PER_MINUTE, RateLimit, Settings, current_uid, refuse_root,
};
use honeypot::log_files::{DailyLog, today};
use honeypot::login::TIMEOUT;
use honeypot::server::{
    Limits, MAX_CONNECTIONS, MAX_LOG_BYTES_PER_DAY, MAX_PER_IP, Shared, serve_next,
};

const LOG_DIR: &str = "logs";

fn main() -> io::Result<()> {
    refuse_root(current_uid()?)?;

    // `skip(1)` leaves out the program's own name, like `sys.argv[1:]` in Python.
    let args: Vec<String> = env::args().skip(1).collect();
    let listener = Settings::from_args(&args)?.open_listener()?;

    // This refuses to start if other users could read the logs.
    let log = DailyLog::open(Path::new(LOG_DIR), today())?;
    let limits = Limits::new(MAX_CONNECTIONS, MAX_PER_IP);
    let rate = RateLimit::new(MAX_VISITS_PER_MINUTE, MAX_TRACKED_ADDRESSES);
    let shared = Shared::new(log, limits, MAX_LOG_BYTES_PER_DAY, TIMEOUT)?.with_rate_limit(rate);

    println!("Fake login listening on {}.", listener.local_addr()?);
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
