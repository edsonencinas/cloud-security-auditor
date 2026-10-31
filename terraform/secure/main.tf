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
variable "region" { default = "asia-southeast1" }
variable "allowed_ssh_cidr" {
  type    = string
  default = "138.84.149.117/32" # replace with your own public IP, e.g. 1.2.3.4/32
}


provider "google" {
  project = var.project_id
  region  = var.region
}

resource "random_id" "suffix" { byte_length = 4 }

resource "google_compute_network" "vpc" {
  name                    = "audit-demo-vpc"
  auto_create_subnetworks = true
}

resource "google_service_account" "demo" {
  account_id   = "audit-demo-sa"
  display_name = "Least-privilege demo SA"
}

resource "google_storage_bucket" "private_bucket" {
  name                        = "audit-demo-private-${random_id.suffix.hex}"
  location                    = "US-CENTRAL1"
  force_destroy		      = true 
  uniform_bucket_level_access = true 
  public_access_prevention    = "enforced" 
  
  versioning {
    enabled = true
  }
  
  logging {
    log_bucket = google_storage_bucket.log_bucket.name
  }
}

resource "google_storage_bucket" "log_bucket" {
  name                        = "audit-demo-logs-${random_id.suffix.hex}"
  location                    = "US-CENTRAL1" 
  force_destroy	              = true
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_compute_firewall" "ssh_from_office" {
  name = "allow-ssh-office-only"
  network = google_compute_network.vpc.name 

  allow { 
    protocol = "tcp" 
    ports = ["22"] 
  }
  source_ranges = [var.allowed_ssh_cidr] # replace with your own IP
}

resource "google_project_iam_member" "demo_viewer" {
  project = var.project_id
  role    = "roles/viewer" 
  member  = "serviceAccount:${google_service_account.demo.email}"
}


