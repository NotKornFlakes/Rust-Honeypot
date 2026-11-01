# The honeypot's cloud resources: one network, its firewall rules and one e2-micro server.
# deploy/README.md shows how to use this, step by step.

terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

variable "project_id" {
  description = "The Google Cloud project that holds the honeypot and nothing else."
  type        = string
}

# Free Tier only covers an e2-micro in us-west1, us-central1 or us-east1.
variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "ssh_public_key_path" {
  description = "The public half of the SSH key used only for this server."
  type        = string
  default     = "~/.ssh/honeypot_admin.pub"
}

variable "allow_setup_egress" {
  description = "Let the server connect out so it can install packages. Only true during setup."
  type        = bool
  default     = false
}

variable "expose_fake_login" {
  description = "Open the fake login to the internet. Only true once the Stage 6 checklist is done."
  type        = bool
  default     = false
}

locals {
  admin_user = "hpadmin"

  # Where Identity-Aware Proxy tunnels come from. Google publishes this range.
  iap_range = "35.235.240.0/20"
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

resource "google_compute_network" "honeypot" {
  name                    = "honeypot"
  auto_create_subnetworks = false
}

# Flow logs and Private Google Access stay off. Flow logs would copy visitors' IP addresses
# somewhere KEEP_DAYS can't reach, and the server has no reason to talk to Google's APIs.
resource "google_compute_subnetwork" "honeypot" {
  #checkov:skip=CKV_GCP_26:Flow logs would keep visitors' IPs outside the retention plan
  #checkov:skip=CKV_GCP_74:The server must not reach Google APIs
  #checkov:skip=CKV_GCP_76:The server is IPv4 only
  name          = "honeypot"
  network       = google_compute_network.honeypot.id
  region        = var.region
  ip_cidr_range = "10.10.0.0/24"
  stack_type    = "IPV4_ONLY"
}

# Admin access only works through an IAP tunnel, so the public IP never shows port 22.
resource "google_compute_firewall" "admin_from_iap" {
  name          = "honeypot-admin-from-iap"
  network       = google_compute_network.honeypot.id
  direction     = "INGRESS"
  source_ranges = [local.iap_range]
  target_tags   = ["honeypot"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "fake_login" {
  #checkov:skip=CKV_GCP_106:This is the honeypot's only public service, on purpose
  count = var.expose_fake_login ? 1 : 0

  name          = "honeypot-fake-login"
  network       = google_compute_network.honeypot.id
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["honeypot"]

  allow {
    protocol = "tcp"
    ports    = ["23"]
  }
}

# Firewall rules track connections, so replies to incoming visitors still get out. Traffic to
# the metadata server skips these rules, which is why the server has nftables as well.
#
# Anything this logs is a reason to stop the server. See "Stopping it" in the README.
resource "google_compute_firewall" "deny_egress" {
  count = var.allow_setup_egress ? 0 : 1

  name               = "honeypot-deny-egress"
  network            = google_compute_network.honeypot.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "EXCLUDE_ALL_METADATA"
  }
}

# There's no service_account block, so the server has no Google Cloud permissions at all.
resource "google_compute_instance" "honeypot" {
  #checkov:skip=CKV_GCP_38:Google-managed encryption is enough, and the server holds no secrets
  #checkov:skip=CKV_GCP_40:A honeypot needs a public IP address
  name         = "honeypot"
  machine_type = "e2-micro"
  zone         = var.zone
  tags         = ["honeypot"]

  boot_disk {
    auto_delete = true

    # Free Tier covers 30 GB of standard disk, which is not the default type.
    initialize_params {
      image = "debian-cloud/debian-13"
      size  = 30
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.honeypot.id
    stack_type = "IPV4_ONLY"

    access_config {}
  }

  metadata = {
    block-project-ssh-keys = "TRUE"
    enable-oslogin         = "FALSE"
    serial-port-enable     = "FALSE"
    ssh-keys               = "${local.admin_user}:${trimspace(file(pathexpand(var.ssh_public_key_path)))}"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

output "public_ip" {
  value = google_compute_instance.honeypot.network_interface[0].access_config[0].nat_ip
}

output "ssh_config" {
  description = "Add this to ~/.ssh/config, then `ssh honeypot` connects through the IAP tunnel."
  value       = <<-EOT
    Host honeypot
      User ${local.admin_user}
      IdentityFile ${trimsuffix(pathexpand(var.ssh_public_key_path), ".pub")}
      IdentitiesOnly yes
      ProxyCommand gcloud compute start-iap-tunnel honeypot %p --listen-on-stdin --project=${var.project_id} --zone=${var.zone} --verbosity=warning
  EOT
}
