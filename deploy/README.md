# Deploying to Google Cloud

These are the commands for the Stage 6 checklist in the [main README](../README.md), in
order. The fake login stays closed to the internet until step 8, so you can stop at any
point before that and nothing is exposed.

| File                     | What it is                                           |
| ------------------------ | ---------------------------------------------------- |
| `gcp/main.tf`            | The network, firewall rules and server, as Terraform |
| `host/nftables.conf`     | The firewall on the server itself                    |
| `host/honeypot.service`  | How systemd runs the program, with its limits        |

Commands run on your own computer, unless they're under "On the server".

## 1. Create the account and project

Create a Google account just for this and turn on 2-Step Verification. Then sign in at
[console.cloud.google.com](https://console.cloud.google.com) and set up billing, which asks
for a payment method even though most of this is free.

```sh
gcloud auth login
gcloud auth application-default login

PROJECT_ID=rust-honeypot-$(openssl rand -hex 3)
gcloud projects create "$PROJECT_ID"
gcloud config set project "$PROJECT_ID"
gcloud config set compute/zone us-central1-a

gcloud billing accounts list
BILLING_ACCOUNT=paste-the-account-id-here
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
gcloud services enable compute.googleapis.com iap.googleapis.com \
  logging.googleapis.com billingbudgets.googleapis.com

gcloud billing budgets create --billing-account="$BILLING_ACCOUNT" \
  --display-name=honeypot --budget-amount=10 \
  --filter-projects="projects/$PROJECT_ID" \
  --threshold-rule=percent=0.5 --threshold-rule=percent=1.0 \
  --billing-project="$PROJECT_ID"
```

New projects come with a `default` network that has permissive rules. Nothing here uses it,
so delete it:

```sh
gcloud compute firewall-rules delete default-allow-icmp default-allow-internal \
  default-allow-rdp default-allow-ssh --quiet
gcloud compute networks delete default --quiet
```

## 2. Make the admin SSH key

Use a passphrase, and don't use this key for anything else.

```sh
ssh-keygen -t ed25519 -f ~/.ssh/honeypot_admin -C honeypot-admin
```

## 3. Create the server and firewall rules

From `deploy/gcp`:

```sh
cp terraform.tfvars.example terraform.tfvars   # then set project_id in it
terraform init
terraform plan                                 # read what it's going to create
terraform apply
terraform output -raw ssh_config >> ~/.ssh/config
```

The server can connect out for now, so it can install packages, and the only way in is the
IAP tunnel. Check both of these. The first should print nothing, because the server has no
service account.

```sh
gcloud compute instances describe honeypot --format='value(serviceAccounts)'
ssh honeypot true
```

## 4. Set up the server

From the top of the repo:

```sh
scp target/x86_64-unknown-linux-musl/release/honeypot \
  deploy/host/honeypot.service deploy/host/nftables.conf honeypot:
ssh honeypot
```

On the server. These background services would keep trying to connect out, so they're turned
off. If one of them doesn't exist on this image, that's fine.

```sh
sudo apt-get update && sudo apt-get -y full-upgrade && sudo apt-get -y install nftables
for unit in google-osconfig-agent unattended-upgrades apt-daily.timer apt-daily-upgrade.timer; do
  sudo systemctl disable --now "$unit"
done

sudo useradd --system --no-create-home --shell /usr/sbin/nologin honeypot
sudo install -D -m 755 honeypot /opt/honeypot/honeypot
sudo install -m 644 honeypot.service /etc/systemd/system/honeypot.service
sudo install -m 644 nftables.conf /etc/nftables.conf
sudo systemctl daemon-reload

sudo nft -c -f /etc/nftables.conf
sudo systemctl enable nftables
sudo reboot
```

If `ssh honeypot` works after the reboot, the firewall allows admin access. If it doesn't,
nothing is lost yet: rebuild the server with
`terraform apply -replace=google_compute_instance.honeypot` and start this step again.

On the server, test `nftables` while the cloud firewall still allows outbound traffic. Then
check that password logins are off. It should say `blocked` and `passwordauthentication no`.

```sh
timeout 5 bash -c '</dev/tcp/1.1.1.1/443' && echo 'CONNECTED: STOP' || echo blocked
sudo sshd -T | grep -i '^passwordauthentication'
```

## 5. Close outbound traffic in the cloud firewall

In `terraform.tfvars`, set `allow_setup_egress = false`, then run `terraform apply`.

On the server, test the cloud firewall alone, by turning `nftables` off for a moment. Nobody
else can reach the server yet, so this is safe. Then check that the clock still syncs, which
uses one of the exceptions in `nftables.conf`.

```sh
sudo nft flush ruleset
timeout 5 bash -c '</dev/tcp/1.1.1.1/443' && echo 'CONNECTED: STOP' || echo blocked
sudo systemctl restart nftables
timedatectl show -p NTPSynchronized
```

## 6. Start the program

On the server. Only do this once you're happy with the checklist so far, since this is the
one place `--checklist-done` is used. The cloud firewall still keeps visitors out.

```sh
sudo systemctl enable --now honeypot
systemctl status honeypot --no-pager
df -h /
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2323; printf "test\nnot-a-real-password\n" >&3; cat <&3'
sudo sh -c 'tail -n 1 /var/lib/honeypot/logs/visits-*.jsonl'
```

Now see what the server's own services have tried to send. Any line here happened before a
single visitor arrived, so work out what each one is, and turn that service off if you can.
This list is what normal looks like, which you'll compare against later.

```sh
sudo journalctl -k --grep egress-blocked --no-pager
```

## 7. Practise stopping it

```sh
gcloud compute instances stop honeypot
gcloud compute instances start honeypot
ssh honeypot systemctl is-active nftables honeypot
```

The public IP changes each time the server stops, which doesn't matter yet. `terraform apply`
updates it in the output. The server may also need a moment to accept `ssh` after starting.

## 8. Open the fake login

This is the step that faces the internet. Only do it once **every other item in the
checklist is ticked**, including the permission items.

In `terraform.tfvars`, set `expose_fake_login = true`, then run `terraform apply`. Then test
it from your own computer, typing a made-up username and password. Some home internet providers
block port 23, so if the first command fails, try it from another network.

```sh
IP=$(terraform output -raw public_ip)
nc -w 10 "$IP" 23
nc -z -w 5 "$IP" 22 && echo 'OPEN: STOP' || echo closed
nc -z -w 5 "$IP" 2323 && echo 'OPEN: STOP' || echo closed
```

## 9. Check it after a day

Any `egress-blocked-honeypot` line, or any hit in the cloud firewall's log, means stop the
server first and investigate afterwards. So does an `egress-blocked` line that isn't on your
list from step 6.

```sh
ssh honeypot "sudo journalctl -k --since '1 day ago' --grep egress-blocked --no-pager"
gcloud logging read "logName=\"projects/$(gcloud config get project)/logs/compute.googleapis.com%2Ffirewall\"" \
  --freshness=1d --limit=20
```

## Copying logs off

The server never sends anything out, so you pull the logs from your own computer. Keep this
folder out of git and cloud sync. The last line deletes copies on the same schedule as
`KEEP_DAYS`, so change the number if you change `KEEP_DAYS`.

```sh
(umask 077; mkdir -p ~/honeypot-logs)
ssh honeypot 'sudo tar -C /var/lib/honeypot/logs -cf - .' | tar -C ~/honeypot-logs --no-same-owner -xf -
find ~/honeypot-logs -name 'visits-*.jsonl' -mtime +30 -delete
```

## Updating the server

Reinstall it from a fresh image, which also deletes the logs on it, so copy them off first. In
`terraform.tfvars`, set `allow_setup_egress = true` and `expose_fake_login = false`, then:

```sh
terraform apply -replace=google_compute_instance.honeypot
ssh-keygen -R honeypot
```

Then go back to step 4, and carry on through to step 8.

## Stopping it

| What you want                      | Command                                                 |
| ---------------------------------- | ------------------------------------------------------- |
| Stop now and keep the evidence     | `gcloud compute instances stop honeypot`                |
| Keep it running but close the port | Set `expose_fake_login = false`, then `terraform apply` |
| Remove the server and its logs     | `terraform destroy`                                     |
| End everything for good            | `gcloud projects delete "$(gcloud config get project)"` |

Stopping works from a phone too: open the Cloud Console, go to Compute Engine, then VM
instances.
