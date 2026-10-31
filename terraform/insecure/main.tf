terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

variable "project_id" { type = string }
variable "region" { default = "us-central1" }

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "random_id" "suffix" { byte_length = 4 }

# BAD: public bucket, no uniform access, no public access prevention
resource "google_storage_bucket" "public_bucket" {
  name          = "audit-demo-public-${random_id.suffix.hex}"
  location      = "US-CENTRAL1"
  force_destroy = true
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_network" "vpc" {
  name                    = "audit-demo-vpc"
  auto_create_subnetworks = true
}


# BAD: SSH and RDP open to the world
resource "google_compute_firewall" "open_ssh" {
  name    = "allow-ssh-anywhere"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
  source_ranges = ["0.0.0.0/0"]
}

# BAD: primitive role (Editor) for a service account
resource "google_service_account" "demo" {
  account_id   = "audit-demo-sa"
  display_name = "Over-privileged demo SA"
}

resource "google_project_iam_member" "demo_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.demo.email}"
}

