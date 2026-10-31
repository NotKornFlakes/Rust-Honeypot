# honeypot: learning Rust by building a research honeypot

A small program that pretends to be a login prompt and other services, then
records what people try against it. It's for research only: the goal is to study
how new vulnerabilities get exploited, and to learn Rust along the way.

Each stage teaches a handful of Rust ideas. You write the code, and the tests tell
you when it works.

## Safety rules

These apply to every stage. If a change would break one of them, don't make it.

1. **Low-interaction only.** Every response is fake. There is never a real shell,
   and nothing an attacker sends is ever run. That includes commands, scripts and
   uploaded files.
2. **It never connects out.** The honeypot only listens. It never attacks or scans
   anyone and never hacks back. It also never follows a link or downloads a file
   that an attacker sends: those are recorded as text and nothing more. It only uses
   TCP, never UDP, and never relays traffic, so nobody can use it to attack someone
   else.
3. **Localhost only until Stage 7.** Develop and test on `127.0.0.1`. Before
   anything faces the internet, Stage 7 moves it to a separate cloud server, away
   from your home network, after checking the provider's terms. New fake services
   are still built and tested on localhost before they're deployed.
4. **Logs are sensitive.** They hold IP addresses and the passwords people try,
   and some of those may be real passwords. Keep logs out of git (`logs/` is
   ignored), readable only by you, and delete them when you no longer need them.
   Never publish raw logs, and never type your own real passwords when testing.
5. **It never impersonates anyone.** Fake services stay generic, with no real
   company's name, logo or look, and nothing that lures people to them. A fake login
   that copies a real brand is phishing, even by accident.

## How to work through a stage

1. Open the stage's file and read it from top to bottom.
2. Find the next `todo!()` and replace it with your code.
3. Run that exercise's tests. The top of the stage's file shows the exact command.
4. Repeat until `cargo test` passes.

| Command          | What it does                                   |
| ---------------- | ---------------------------------------------- |
| `cargo test`     | Run every test                                 |
| `cargo test ex2` | Run only the tests with `ex2` in their name    |
| `cargo check`    | Check for errors quickly, without building     |
| `cargo run`      | Build and run the program                      |
| `cargo clippy`   | Suggest more idiomatic ways to write your code |
| `cargo fmt`      | Format your code in the standard Rust style    |

When you're stuck, ask Claude for a hint or a review rather than the answer.

## Trying it after Stage 4

1. Start it with `cargo run`.
2. In a second terminal, connect with `nc 127.0.0.1 2323`, and leave it sitting there.
3. In a third terminal, connect the same way. You get a prompt straight away, even
   though the second terminal is silent.
4. In the third terminal, type `adm` without pressing Enter, and wait 30 seconds for
   the time limit.
5. See the record with `jq . logs/visits-*.jsonl`. It shows `"username": "adm"` and
   `"outcome": "timed_out"`.
6. Try the cap on one address: `for i in 1 2 3 4 5; do sleep 35 | nc 127.0.0.1 2323 & done`.
   Only four `login:` prompts appear, and the first terminal reports the refusal
   when the next visit ends.

The first terminal hides passwords and most of each IP address, and the log keeps the
full details. If other users can read a log, the program refuses to start.

Log files older than `KEEP_DAYS` (30 days, set in `src/log_files.rs`) are deleted
for good. Only files named exactly like `visits-2026-10-31.jsonl` are ever deleted.

## Roadmap

The honeypot goes live with only the fake login, so the least code possible faces the
internet at first. The other fake services follow one at a time.

### Before going live

- [x] **Stage 1: Fake login on localhost** (`src/login.rs`): `&str` views, cleaning
      hostile input, `Result`, the `?` operator, reading and writing, `TcpListener`
- [x] **Stage 2: Structured logs** (`src/visit.rs`): one JSON object per line with
      the time and source IP, for every visitor, including those who leave without
      typing. Adding crates, `serde` and `serde_json`, `Option`, handling a `Result`
      yourself, `if let`
- [x] **Stage 3: Protecting the logs** (`src/log_files.rs`): checking file
      permissions, a new file each day, deleting old logs automatically, hiding
      passwords and IPs on screen. Bit masks, making your own errors, `chrono`, `?` on
      an `Option`, enums that hold data
- [ ] **Stage 4: Many connections at once** (`src/server.rs`): a thread for each
      visitor, one time limit for a whole visit, caps on connections overall and per
      IP, a daily budget for the log, keeping text sent without a newline. `Instant`,
      `HashMap`, `Drop`, `Arc` and `Mutex`, threads
- [ ] **Stage 5: Safety checks**: tests that fail if the code ever runs a program,
      opens an outbound connection, uses UDP or uses `unsafe`, so the rules above are
      enforced on every `cargo test`. Checking your crates for known vulnerabilities
      with `cargo audit`
- [ ] **Stage 6: Ready to deploy**: a limit on new connections per IP each minute, so
      one source can't use up the day's log budget with quick visits. A setting for the
      listen address, with localhost as the default and an explicit confirmation needed
      for anything else. Refusing to run as root. A flood test on localhost, to prove
      the limits hold under load
- [ ] **Stage 7: Isolation and going live**: the only stage that faces the internet.
      Finish this whole checklist first:
  - [ ] Read the cloud provider's terms and confirm that honeypots are allowed
  - [ ] Check the local rules for storing IP addresses and passwords, write down how
        long you'll keep them, and set `KEEP_DAYS` to match
  - [ ] Use a dedicated cloud account and server, with no connection to your home
        network or other projects, and no real credentials or personal data on it
  - [ ] Block all outbound traffic in the cloud firewall except replies to incoming
        connections, then test that an outbound connection really fails
  - [ ] Keep admin access separate from the fake services: its own port, its own SSH
        key used nowhere else, and allowed only from your IP
  - [ ] Use IPv4 only for now, because the cap per IP is easy to get around on IPv6
  - [ ] Run the honeypot as an unprivileged user, with no cloud permissions. Forward
        the public port to 2323 in the firewall instead of running it as root
  - [ ] Run it under systemd with memory and task limits, no new privileges, a
        read-only filesystem except for `logs/`, and a restart if it fails
  - [ ] Make sure the disk has room for `KEEP_DAYS` days of the daily log budget (3 GB
        by default), with space to spare
  - [ ] Copy logs off by pulling them over admin access, so the server never sends
        anything out. Keep the copies private, and delete them on the same schedule
  - [ ] Build the program on your own computer and upload it. To update the server,
        rebuild it from a fresh image instead of opening up outbound traffic
  - [ ] Set up one command that destroys the whole server, and test it
  - [ ] Decide when you'll use it. Any unexpected outbound traffic or an abuse report
        from the provider means destroy first and investigate afterwards
  - [ ] Start with the fake login only, and check the logs for a day

### After going live

Build and test each of these on localhost, and deploy it only once its tests and the
safety checks pass.

- [ ] **Stage 8: A fake web login**: reading simple HTTP requests by hand, with limits
      on their size. Fixed, generic fake pages built into the program, never files
      named in a request. Recording paths, headers and submitted fields, `Vec` and
      iterators. This is where most attempts to exploit new vulnerabilities will show up
- [ ] **Stage 9: More fake services**: a `FakeService` trait, plus fixed banners and
      prompts for FTP and SSH (the version banner only), all sharing the same limits.
      Your own traits and enums
- [ ] **Stage 10: Reports**: reading your JSON logs back, top usernames, passwords,
      paths and services, what changed from day to day, matching paths against a
      local list of known vulnerabilities, `HashMap` and sorting. Reports are plain text
      only, because the logs hold hostile text. Passwords and IPs are hidden by default
