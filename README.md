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
3. **Localhost only until Stage 6.** Develop and test on `127.0.0.1`. Before
   anything faces the internet, Stage 6 moves it to a separate cloud server, away
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

## Trying it after Stage 5

1. Start it with `cargo run`. In a second terminal, connect with `nc 127.0.0.1 2323`.
2. Stop it, and try `cargo run -- --listen 0.0.0.0:2323`. It refuses to start. The `--`
   passes what follows to your program instead of to `cargo`. Don't add
   `--checklist-done` on your own computer. That flag is for the Stage 6 server.
3. Start it normally again, and in a second terminal run the flood test:
   `for i in $(seq 1 200); do nc -z 127.0.0.1 2323; done`. Then run
   `wc -l logs/visits-*.jsonl`. No more than 60 of those visits are logged each minute,
   and the first terminal reports the ones it refused.

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
- [x] **Stage 4: Many connections at once** (`src/server.rs`): a thread for each
      visitor, one time limit for a whole visit, caps on connections overall and per
      IP, a daily budget for the log, keeping text sent without a newline. `Instant`,
      `HashMap`, `Drop`, `Arc` and `Mutex`, threads
- [x] **Stage 5: Ready to deploy** (`src/deploy.rs`): a setting for the listen address,
      with localhost as the default and a deliberate flag needed for anything else.
      Refusing to run as root. A limit on visits per IP each minute. Tests that fail if
      the code ever starts a program, connects out or uses UDP, and a compiler ban on
      `unsafe`. `.parse()`, `map_err`, `while let`, slicing text, `.any(...)`
- [ ] **Stage 6: Going live on a Google Cloud e2-micro**: the only stage that faces the
      internet, and it's setup rather than Rust. Finish this whole checklist first.
      [`deploy/README.md`](deploy/README.md) has the commands, in order:
  - **Permission**
    - [x] Ask Google in writing whether a research honeypot is allowed, and say that it
          records IP addresses and the passwords people type. Their
          [Acceptable Use Policy](https://cloud.google.com/terms/aup) doesn't mention
          honeypots, but it bars anything "invasive" and items of a "deceptive nature".
          Without a paid [support plan](https://docs.cloud.google.com/support/docs/overview)
          you may not get an answer. Keep any reply. If the answer is no, use a different
          provider. If there's no answer, going ahead is your own decision and your own
          risk, so write down the date, what you read and why you went ahead
      - **2026-11-01, going ahead without an answer.** I asked Google support on 2026-10-31
        and never got a reply. I read the Acceptable Use Policy above. This is my own
        judgment and my own risk, and I accept that Google may close the account. It's a
        throwaway project, and the whole server can be rebuilt from Terraform
    - [x] Check the local rules for storing IP addresses and passwords, for both your
          country and the server's. Write down how long you'll keep them, and set
          `KEEP_DAYS` to match
      - **2026-11-01, keeping logs for 30 days.** `KEEP_DAYS` is 30. There was no
        country-by-country legal review. The decision rests on these safeguards, each
        checked that day against the running server and the code it was built from:
        - Logs stay private on the server: the folder is `0700` and the files `0600`, so
          only the `honeypot` user and root can read them, and the program refuses to start
          otherwise
        - Log files more than 30 days old are deleted, on the first visit of each new day
          and whenever the program starts
        - Passwords show as `(hidden)` in screen output, and the server discards that output
        - Logs never go into git: `.gitignore` covers them, none are in the history, and
          downloaded copies stay in `~/honeypot-logs`, outside the repo
  - **Isolation**
    - [x] Use a Google account and project with nothing else in them, a unique password
          and 2-Step Verification. No connection to your home network or other projects,
          and no real credentials or personal data on the server
    - [x] Set a budget alert. [Free Tier](https://docs.cloud.google.com/free/docs/free-cloud-features)
          covers the e2-micro, 30 GB of standard disk and 1 GB of outbound traffic a month.
          It doesn't cover the [public IP address](https://cloud.google.com/vpc/network-pricing),
          at about $3.60 a month. An alert warns you, but it doesn't stop the spending
    - [x] In Google Cloud's firewall, open only the fake service's port, plus the admin
          port from Google's IAP range alone
    - [x] Block outbound traffic twice: with a firewall rule, and on the server itself
          with `nftables`, allowing only replies to incoming connections and what the
          server needs from its own metadata server. Google's
          [firewall rules](https://docs.cloud.google.com/firewall/docs/firewalls) don't
          apply to that traffic. Install what you need first, then close both, and test
          each one alone to prove an outbound connection really fails
    - [x] Keep admin access separate from the fake services: an IAP tunnel, so the public
          IP shows no admin port, its own SSH key used nowhere else, and no password logins
    - [x] Give the server no service account, so it has no Google Cloud permissions
    - [x] Use IPv4 only. The program refuses to listen on IPv6
    - [x] Leave snapshots, flow logs and the Ops Agent off, so logs aren't copied somewhere
          your retention plan can't reach
  - **Running it**
    - [x] Install `cargo audit` with `cargo install cargo-audit`, run it on your own
          computer, and deal with anything it finds. Then build with
          `cargo build --release --target x86_64-unknown-linux-musl`, which runs on any
          x86-64 Linux server
    - [x] Upload the program and run it as an unprivileged user with no other access. Use
          `nftables` to forward the public port to 2323, instead of running it as root
    - [x] Run it under systemd with `--listen 0.0.0.0:2323 --checklist-done`. Set memory,
          CPU and task limits, no new privileges, a read-only filesystem except for
          `logs/`, and a restart if it fails
    - [x] Make sure the disk has room for `KEEP_DAYS` days of the daily log budget (3 GB
          by default), with space to spare
    - [x] Copy logs off by pulling them over admin access, so the server never sends
          anything out. Keep the copies private, and delete them on the same schedule
    - [x] To update the server, reinstall it from a fresh image instead of leaving outbound
          traffic open
  - **Stopping it**
    - [x] Practise your emergency stop before the port opens:
          `gcloud compute instances stop honeypot`, or Stop in the Cloud Console. It keeps
          the disk, so you can investigate afterwards. `terraform destroy` removes the
          server and its logs, and deleting the project ends everything for good
    - [x] Decide when you'll use it. Any outbound attempt by the honeypot, any other
          unexplained outbound traffic or an abuse report from Google means stop first and
          investigate afterwards
    - [ ] Start with the fake login only, and check the logs for a day

### After going live

Build and test each of these on localhost. Anything that runs on the server is deployed
only once its tests and the safety checks pass.

- [ ] **Stage 7: A fake web service**: reading HTTP requests by hand and logging each one
      in full (method, path, headers and body), so you can spot attempts to exploit
      newly announced vulnerabilities. `Vec`, iterators, working with raw bytes.
  - Every reply is one fixed, generic page built into the program. It never serves files,
    repeats anything from the request, redirects or acts as a proxy
  - Requests have a size limit. Anything longer is cut off and marked, with its full
    size recorded. Each IP also gets a share of the daily log budget, so large requests
    from one source can't use it all up
  - Bodies are stored encoded, so payloads stay byte for byte and can't affect your
    terminal. Nothing in them is ever run, and links in them are never followed
  - The screen shows only the method and the escaped path, never headers or bodies
  - It starts with plain HTTP. Requests sent only over HTTPS won't be seen, because that
    needs a certificate and another crate, so it would be a later addition
  - Before opening the port, check that Google's answer covers full request logging. Open
    the port in both firewalls, and forward it to a port above 1024 instead of running as
    root
- [ ] **Stage 8: A report tool for your own computer**: a separate program that reads the
      logs you've downloaded, and is never uploaded to the server. Top usernames,
      passwords, paths and services, and what changed from day to day. A rules file you
      update by hand when a vulnerability is announced, matching paths, headers and
      bodies, showing when each rule was first and last seen and how many IPs it came
      from. It can only look back as far as the logs you've kept. `HashMap`, sorting,
      reading JSON back.
  - It treats logs as hostile: plain text output only, with everything escaped
  - It never connects to anything, so no looking up IPs and no opening links
  - Passwords and IPs are hidden by default
  - Downloaded logs follow safety rule 4 on your computer too: a private folder, out of
    git and cloud sync, and deleted on the same schedule
- [ ] **Stage 9: More fake services**: a `FakeService` trait, plus fixed banners and
      prompts for FTP and SSH (the version banner only), all sharing the same limits.
      Your own traits and enums
