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
   that an attacker sends: those are recorded as text and nothing more.
3. **Localhost only until Stage 9.** Develop and test on `127.0.0.1`. Before
   anything faces the internet, Stage 9 moves it to a separate cloud server, away
   from your home network, after checking the provider's terms.
4. **Logs are sensitive.** They hold IP addresses and the passwords people try,
   and some of those may be real passwords. Keep logs out of git (`logs/` is
   ignored), readable only by you, and delete them when you no longer need them.
   Never publish raw logs, and never type your own real passwords when testing.

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

## Trying it after Stage 2

1. Start it with `cargo run`.
2. In a second terminal, connect with `nc 127.0.0.1 2323`.
3. Type a made-up username and password. It will always say `Login incorrect`.
4. Connect again, and press Ctrl+C without typing anything.
5. See what it recorded in the first terminal and in `logs/visits.jsonl`.
6. To read the log more easily, run `jq . logs/visits.jsonl`.

## Roadmap

- [ ] **Stage 1: Fake login on localhost** (`src/login.rs`): `&str` views, cleaning
      hostile input, `Result`, the `?` operator, reading and writing, `TcpListener`
- [ ] **Stage 2: Structured logs** (`src/visit.rs`): one JSON object per line with
      the time and source IP, for every visitor, including those who leave without
      typing. Adding crates, `serde` and `serde_json`, `Option`, handling a `Result`
      yourself, `if let`
- [ ] **Stage 3: Protecting the logs**: checking file permissions, a new file each
      day, deleting old logs automatically, hiding passwords and IPs on screen
- [ ] **Stage 4: Many connections at once**: threads, a cap on connections so
      nobody can overwhelm it, `Arc` and `Mutex`
- [ ] **Stage 5: A fake web login**: reading simple HTTP requests by hand, fixed
      fake pages, recording paths, headers and submitted fields, `Vec` and iterators
- [ ] **Stage 6: More fake services**: a `FakeService` trait, plus fixed banners and
      prompts for FTP and SSH (the version banner only), your own traits and enums
- [ ] **Stage 7: Reports**: reading your JSON logs back, top usernames, passwords,
      paths and services, what changed from day to day, matching paths against a
      local list of known vulnerabilities, `HashMap` and sorting. Passwords and IPs
      are hidden by default.
- [ ] **Stage 8: Safety checks**: tests that fail if the code ever runs a program,
      opens an outbound connection or uses `unsafe`, so the rules above are enforced
      on every `cargo test`
- [ ] **Stage 9: Isolation before going live**: the only stage that faces the
      internet. Finish this whole checklist first:
  - [ ] Read the cloud provider's terms and confirm that honeypots are allowed
  - [ ] Check the local rules for storing IP addresses and passwords, and write
        down how long you'll keep them
  - [ ] Use a dedicated cloud account and server, with no connection to your home
        network or other projects, and no real credentials or personal data on it
  - [ ] Block all outbound traffic in the cloud firewall, then test that an outbound
        connection really fails
  - [ ] Keep admin access separate from the fake services: its own port, key only,
        and allowed only from your IP
  - [ ] Run the honeypot as an unprivileged user, with no cloud permissions
  - [ ] Add an explicit setting for the listen address, with localhost as the default
  - [ ] Set up one command that destroys the whole server, and test it
  - [ ] Start with one fake service, and check the logs for a day before adding more
