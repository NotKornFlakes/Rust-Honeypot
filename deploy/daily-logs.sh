#!/usr/bin/env bash
# Copies the visit logs to this computer and prints a short summary. Run it once a day.
#
# Logs are private and hostile, so the summary never shows a password, a command or a download
# address, cuts each IP address down to its first two numbers, and strips anything that could
# affect the terminal.
set -euo pipefail
umask 077

LOG_DIR="$HOME/honeypot-logs"

# Keep this the same as KEEP_DAYS in src/log_files.rs.
KEEP_DAYS=30

# The fake shell costs at most 20 MB a day (MAX_SHELL_BYTES_PER_DAY in src/fake_shell.rs), and
# nothing else the server sends is large. Well over that means a limit isn't working.
MAX_SENT_MB_PER_DAY=40

# The tunnel prints a harmless warning each time, so only show this if something fails.
ERRORS=$(mktemp)
trap 'status=$?; [ "$status" -eq 0 ] || cat "$ERRORS" >&2; rm -f "$ERRORS"' EXIT

printable() {
  LC_ALL=C tr -cd '\11\12\40-\176'
}

# Only copy what's changed since the newest copy here, with a day's overlap, because this counts
# as outbound traffic too. With no copies yet, that's everything. Tar exits with 1 if today's log
# grows while it's being read, which is harmless. A line cut off that way is skipped below, and
# the next copy replaces it.
mkdir -p "$LOG_DIR"
NEWEST=$(find "$LOG_DIR" -name 'visits-*.jsonl' -printf '%T@\n' | sort -n | tail -n 1 | cut -d. -f1)
COPY_SINCE=$((${NEWEST:-86400} - 86400))
ssh honeypot "sudo tar -C /var/lib/honeypot/logs --newer-mtime=@$COPY_SINCE -cf - . || [ \$? -eq 1 ]" 2>>"$ERRORS" |
  tar -C "$LOG_DIR" --no-same-owner -xf -
find "$LOG_DIR" -name 'visits-*.jsonl' -mtime "+$KEEP_DAYS" -delete

echo "Honeypot summary, $(date -u '+%Y-%m-%d %H:%M') UTC"
echo "Logs in $LOG_DIR: $(find "$LOG_DIR" -name 'visits-*.jsonl' | wc -l) file(s), $(du -sh "$LOG_DIR" | cut -f1)"
echo

# Visits from 127.x are tests run on the server itself. A username only shows if several IPs
# tried it, because a one-off could be a real password typed into the wrong box.
{
  cat "$LOG_DIR/visits-$(date -u -d yesterday +%F).jsonl" \
    "$LOG_DIR/visits-$(date -u +%F).jsonl" 2>/dev/null || true
} | jq -n -R -r --argjson since "$(($(date +%s) - 86400))" '
  def mask: split(".")[:2] | join(".") | . + ".x.x";
  def top($n): to_entries | sort_by(-.value) | .[:$n]
    | map("\(.key[:32]) (\(.value))") | join(", ")
    | if . == "" then "none" else . end;
  reduce (inputs | fromjson? | select(.time >= $since and (.source_ip | startswith("127.") | not))) as $v
    ({visits: 0, outcomes: {}, ips: {}, nets: {}, users: {}, passwords: {}, commands: 0, urls: 0, sent: 0, silent: 0, offered: 0, answered: 0};
     .visits += 1
     | if $v.username == null then .silent += 1 else . end
     | if $v.telnet != null then .offered += 1 else . end
     | if ($v.telnet // "") != "" then .answered += 1 else . end
     | .commands += ($v.shell.commands // [] | length)
     | .urls += ($v.shell.urls // [] | length)
     | .sent += ($v.shell.reply_bytes // 0)
     | .outcomes[$v.outcome] += 1
     | .ips[$v.source_ip] = 1
     | .nets[$v.source_ip | mask] += 1
     | if ($v.username // "") != "" then .users[$v.username][$v.source_ip] = 1 else . end
     | if ($v.password // "") != "" then .passwords[$v.password] = 1 else . end)
  | "Last 24 hours: \(.visits) visit(s) from \(.ips | length) IP address(es)",
    "  Tried a login: \(.outcomes.attempted // 0)",
    "  Got into the fake shell: \(.outcomes.logged_in // 0), with \(.commands) command(s) and \(.urls) download address(es) (hidden), \(.sent / 1024 | floor) KB sent back",
    "  Left early: \(.outcomes.left // 0)",
    "  Went quiet: \(.outcomes.timed_out // 0)",
    "  Sent nothing at all: \(.silent)",
    "  Offered the telnet opening: \(.offered), and answered it: \(.answered)",
    "  Different passwords: \(.passwords | length) (hidden)",
    "  Usernames tried by several IPs: \(.users | map_values(length) | with_entries(select(.value >= 2)) | top(5))",
    "  Busiest networks: \(.nets | top(5))"
' | printable
echo

# Lines from before the port opened are setup noise, so the checks below only look back as far
# as that, or a day if that's more recent.
SINCE=$(($(date +%s) - 86400))
WINDOW="last day"
OPENED=$(gcloud compute firewall-rules list --filter='name=honeypot-fake-login' \
  --format='value(creationTimestamp)' 2>>"$ERRORS")
if [ -n "$OPENED" ]; then
  PORT_STATE="open since $(date -u -d "$OPENED" '+%Y-%m-%d %H:%M') UTC"
  if [ "$(date -d "$OPENED" +%s)" -gt "$SINCE" ]; then
    SINCE=$(date -d "$OPENED" +%s)
    WINDOW="since the port opened"
  fi
else
  PORT_STATE="closed"
fi

# "Refused" is what's left of the server's new connections after taking away the logged visits,
# the visitors still connected and admin logins. The server doesn't keep the program's own
# count, because that output also holds usernames, which could be passwords and would outlive
# KEEP_DAYS in the journal.
SERVER=$(ssh honeypot bash -s -- "$SINCE" 2>>"$ERRORS" <<'ON_SERVER'
since=$1
get() { systemctl show "$1" -p "$2" --value; }
mb() { awk -v bytes="$1" 'BEGIN { printf "%.1f", bytes / 1048576 }'; }

echo "Program: $(systemctl is-active honeypot), $(get honeypot NRestarts) restart(s), memory $(mb "$(get honeypot MemoryCurrent)") MB (peak $(mb "$(get honeypot MemoryPeak)") of 256 MB)"
echo "Firewall: $(systemctl is-active nftables)"
echo "Fake shell: $(systemctl show honeypot -p ExecStart --value | grep -q -- --credentials && echo on || echo off)"
echo "Disk: $(df -h --output=pcent,avail / | tail -1 | awk '{print $1 " used, " $2 " free"}')"

boot=$(date -d "$(uptime -s)" +%s)
opens=$(awk '/^Tcp:/ { if (!seen) { split($0, names); seen = 1 } else { split($0, values); for (i in names) if (names[i] == "PassiveOpens") print values[i] } }' /proc/net/snmp)
logins=$(sudo journalctl -b -u ssh --no-pager --grep Accepted | grep -c Accepted)
visits=$(sudo sh -c 'cat /var/lib/honeypot/logs/visits-*.jsonl' | grep -oE '^\{"time":[0-9]+' | cut -d: -f2 | awk -v boot="$boot" '$1 >= boot { n++ } END { print n + 0 }')
connected=$(ss -Htn '( sport = :2323 )' | wc -l)
refused=$((opens - logins - visits - connected))
echo "Refused by the limits since boot: about $((refused > 0 ? refused : 0))"

errors=$(sudo journalctl -u honeypot _TRANSPORT=stdout --since "@$since" --no-pager -o cat | wc -l)
echo "Program errors: $errors"
[ "$errors" -eq 0 ] || sudo journalctl -u honeypot _TRANSPORT=stdout --since "@$since" --no-pager -o cat | tail -n 3 | cut -c1-100 | sed 's/^/  /'
echo "Crashes during a visit: $(sudo journalctl -u honeypot _TRANSPORT=stdout --since "@$since" --no-pager -o cat | grep -c panicked)"

# Nothing the program does should ever show up here. "Nothing is ever run" is the rule these check
# from the outside, whatever the code says.
echo "Other programs run by the honeypot user: $(ps -u honeypot -o comm= | grep -cvx honeypot)"
echo "Its files outside the logs folder: $(sudo find / -xdev -user honeypot -not -path /var/lib/honeypot -not -path '/var/lib/honeypot/*' 2>/dev/null | wc -l)"

sent=$(awk -F'[: ]+' 'NR > 2 && $2 != "lo" { total += $11 } END { printf "%.0f", total }' /proc/net/dev)
per_day=$(awk -v sent="$sent" -v up="$(cut -d' ' -f1 /proc/uptime)" 'BEGIN { days = up / 86400; if (days < 1) days = 1; printf "%.0f", sent / days / 1048576 }')
echo "Sent since boot: $(mb "$sent") MB, about $per_day MB a day"

sudo journalctl -k --since "@$since" --no-pager -o cat --grep egress-blocked |
  awk '{
    who = /egress-blocked-honeypot:/ ? "honeypot" : "other"
    kind = / SYN / ? "connect" : (/PROTO=UDP/ ? "udp" : "other")
    match($0, /DST=[0-9.]+/); ip = substr($0, RSTART + 4, RLENGTH - 4)
    match($0, /DPT=[0-9]+/); port = substr($0, RSTART + 4, RLENGTH - 4)
    if (ip != "1.1.1.1") { split(ip, part, "."); ip = part[1] "." part[2] ".x.x" }
    count[who " " ip ":" port " " kind]++
  } END { for (key in count) print "BLOCKED " key " " count[key] }'
ON_SERVER
)

REASONS=()
stop_because() { REASONS+=("$1"); }

REPORT=$(printable <<<"$SERVER")
BLOCKED=$(grep '^BLOCKED ' <<<"$REPORT" || true)
echo "Server"
echo "  Port 23: $PORT_STATE"
grep -v '^BLOCKED ' <<<"$REPORT" | sed 's/^/  /'
grep -q '^Program: active' <<<"$REPORT" || stop_because "the program isn't running"
grep -q '^Firewall: active' <<<"$REPORT" || stop_because "the server's firewall isn't running"
grep -q '^Crashes during a visit: 0$' <<<"$REPORT" || stop_because "the program crashed during a visit"
grep -q '^Other programs run by the honeypot user: 0$' <<<"$REPORT" || stop_because "the honeypot user ran another program"
grep -q '^Its files outside the logs folder: 0$' <<<"$REPORT" || stop_because "the honeypot user wrote a file outside its logs"
PER_DAY=$(sed -n 's/^Sent since boot: .*about \([0-9]*\) MB a day$/\1/p' <<<"$REPORT")
if [ -z "$PER_DAY" ] || [ "$PER_DAY" -gt "$MAX_SENT_MB_PER_DAY" ]; then
  stop_because "the server is sending more than the limits allow (over $MAX_SENT_MB_PER_DAY MB a day)"
fi

if [ -z "$BLOCKED" ]; then
  echo "  Blocked outbound, $WINDOW: none"
else
  echo "  Blocked outbound, $WINDOW:"
  cut -d' ' -f2- <<<"$BLOCKED" | sed 's/^/    /'
  # 1.1.1.1:443 is the self-test from deploy/README.md, so it doesn't count.
  if grep -qv ' 1\.1\.1\.1:443 ' <<<"$BLOCKED"; then stop_because "something tried to connect out"; fi
fi

# The same test also shows up here if it's run with nftables off.
HITS=$(gcloud logging read "logName=\"projects/$(gcloud config get project 2>/dev/null)/logs/compute.googleapis.com%2Ffirewall\" AND timestamp>=\"$(date -u -d "@$SINCE" +%FT%TZ)\"" \
  --limit=100 \
  --format='value(jsonPayload.connection.dest_ip,jsonPayload.connection.dest_port)' 2>>"$ERRORS")
echo "  Google firewall hits, $WINDOW: $(grep -c . <<<"$HITS" || true)"
if [ -n "$HITS" ] && grep -qvP '^1\.1\.1\.1\t443$' <<<"$HITS"; then stop_because "Google's firewall blocked something"; fi

echo
if [ "${#REASONS[@]}" -gt 0 ]; then
  echo "STOP: stop the server first and investigate afterwards. See deploy/README.md, step 9."
  printf '  Why: %s\n' "${REASONS[@]}"
  echo "  gcloud compute instances stop honeypot"
else
  echo "Nothing that needs stopping."
fi
